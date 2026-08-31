package bfd

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
)

func TestDialUDPErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		local, peer netip.Addr
	}{
		{
			name: "no addresses",
		},
		{
			name:  "no local",
			peer:  netip.MustParseAddr("127.0.0.1"),
			local: netip.Addr{},
		},
		{
			name:  "no peer",
			local: netip.MustParseAddr("127.0.0.1"),
		},
		{
			name:  "family mismatch",
			local: netip.MustParseAddr("127.0.0.1"),
			peer:  netip.MustParseAddr("::1"),
		},
		{
			name:  "multicast peer",
			local: netip.MustParseAddr("127.0.0.1"),
			peer:  netip.MustParseAddr("224.0.0.1"),
		},
		{
			name:  "unspecified peer",
			local: netip.MustParseAddr("127.0.0.1"),
			peer:  netip.MustParseAddr("0.0.0.0"),
		},
		{
			name:  "multicast local",
			local: netip.MustParseAddr("224.0.0.1"),
			peer:  netip.MustParseAddr("127.0.0.1"),
		},
		{
			name:  "unspecified local",
			local: netip.MustParseAddr("0.0.0.0"),
			peer:  netip.MustParseAddr("127.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr, err := DialUDP(tt.local, tt.peer)
			if err == nil {
				_ = tr.Close()
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

// TestUDPTransportIPv4 exercises the real sockets between two loopback
// transports: delivery in both directions, the RFC 5881, section 5 receive
// filters, 4-in-6 mapped address handling, and Close unblocking a read.
func TestUDPTransportIPv4(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("skipping, test binds several 127.0.0.0/8 addresses, which only Linux provides by default")
	}

	local, peer := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")

	a, err := DialUDP(local, peer)
	if err != nil {
		t.Fatalf("failed to dial transport A: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	// The reverse direction names its peer 4-in-6 mapped, which DialUDP
	// must treat as 127.0.0.1 everywhere, the receive filter included.
	b, err := DialUDP(peer, netip.MustParseAddr("::ffff:127.0.0.1"))
	if err != nil {
		t.Fatalf("failed to dial transport B: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	// One transport exists per local address: A already owns 127.0.0.1's
	// Port entirely.
	if tr, err := DialUDP(local, peer); err == nil {
		_ = tr.Close()
		t.Fatal("expected an error dialing a second transport for the same local address")
	}

	// Datagrams which fail the section 5 checks must surface only as drop
	// reports: one from an address other than the peer's, and one from
	// the peer's address without the maximum TTL.
	spoofed, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.9")},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: Port},
	)
	if err != nil {
		t.Fatalf("failed to dial spoofed source: %v", err)
	}
	t.Cleanup(func() { _ = spoofed.Close() })

	if _, err := spoofed.Write([]byte("wrong source address")); err != nil {
		t.Fatalf("failed to write from spoofed source: %v", err)
	}

	// The kernel's default TTL is well below the 255 GTSM demands.
	lowTTL, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: Port},
	)
	if err != nil {
		t.Fatalf("failed to dial low TTL source: %v", err)
	}
	t.Cleanup(func() { _ = lowTTL.Close() })

	if _, err := lowTTL.Write([]byte("low TTL")); err != nil {
		t.Fatalf("failed to write with low TTL: %v", err)
	}

	// Only the genuine transport's datagram survives the filters; the two
	// hostile ones surface as ErrDropped reads first.
	payload := []byte("a to b")
	if err := a.WritePacket(payload); err != nil {
		t.Fatalf("failed to write A to B: %v", err)
	}

	got, drops := readDatagram(t, b)
	if !bytes.Equal(payload, got) {
		t.Fatalf("unexpected B payload: got %q, want %q", got, payload)
	}

	if drops != 2 {
		t.Fatalf("unexpected B drop count: got %d, want 2", drops)
	}

	payload = []byte("b to a")
	if err := b.WritePacket(payload); err != nil {
		t.Fatalf("failed to write B to A: %v", err)
	}

	if got, drops := readDatagram(t, a); !bytes.Equal(payload, got) || drops != 0 {
		t.Fatalf("unexpected A payload: got %q (%d drops), want %q", got, drops, payload)
	}

	// Close must unblock a pending read, so a session can always tear down.
	errC := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := a.ReadPacket(buf)
		errC <- err
	}()

	_ = a.Close()
	if err := recv(t, errC, "the read to unblock"); err == nil {
		t.Fatal("expected an error from the unblocked read, but none occurred")
	}
}

// TestUDPTransportIPv6 exercises the IPv6 socket paths with a transport
// peered with itself: ::1 is the only IPv6 loopback address, so a write
// loops back to the transport's own receive socket, crossing the hop limit
// checks in both directions.
func TestUDPTransportIPv6(t *testing.T) {
	t.Parallel()

	lo := netip.MustParseAddr("::1")
	tr, err := DialUDP(lo, lo)
	if err != nil {
		t.Fatalf("failed to dial transport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	payload := []byte("hello, self")
	if err := tr.WritePacket(payload); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if got, drops := readDatagram(t, tr); !bytes.Equal(payload, got) || drops != 0 {
		t.Fatalf("unexpected payload: got %q (%d drops), want %q", got, drops, payload)
	}
}

// readDatagram reads from tr on a goroutine until a datagram survives the
// receive filters, so a filtering bug which blocks forever fails the test
// instead of hanging it. It returns the surviving payload and the count of
// ErrDropped reads before it, failing the test on any other error.
func readDatagram(tb testing.TB, tr Transport) ([]byte, int) {
	tb.Helper()

	type result struct {
		b     []byte
		drops int
		err   error
	}

	resC := make(chan result, 1)
	go func() {
		var drops int
		for {
			b := make([]byte, 64)
			n, err := tr.ReadPacket(b)
			if errors.Is(err, ErrDropped) {
				drops++
				continue
			}

			resC <- result{b: b[:n], drops: drops, err: err}
			return
		}
	}()

	res := recv(tb, resC, "a datagram")
	if res.err != nil {
		tb.Fatalf("failed to read: %v", res.err)
	}

	return res.b, res.drops
}
