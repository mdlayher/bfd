package bfd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestDialUDPErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		local, peer netip.Addr

		// contains, when set, is a substring the error must carry, so a
		// case which would fail for some other reason cannot pass.
		contains string
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
		{
			// A zoned local address is bound to one link, and the kernel
			// reports every link-local source with the receiving
			// interface's zone, so a peer on another link or on none can
			// never be attributed to the session.
			name:     "zone mismatch",
			local:    netip.MustParseAddr("fe80::1%eth0"),
			peer:     netip.MustParseAddr("fe80::2%eth1"),
			contains: "must share a zone",
		},
		{
			name:     "unzoned peer",
			local:    netip.MustParseAddr("fe80::1%eth0"),
			peer:     netip.MustParseAddr("fe80::2"),
			contains: "must share a zone",
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

			if tt.contains != "" && !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("unexpected error: got %q, want it to contain %q", err, tt.contains)
			}
		})
	}
}

// TestUDPTransportIPv4 exercises the real sockets between two loopback
// transports: delivery in both directions, the RFC 5881, section 5 receive
// filters, 4-in-6 mapped address handling, and Close unblocking a read.
func TestUDPTransportIPv4(t *testing.T) {
	t.Parallel()

	requireLoopbackAddrs(t)

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

// TestDialUDPUnroutableDatagram pins the difference between a DialUDP
// transport and one from a shared listener. DialUDP's listener exists for
// a single session, so a datagram which names no session is still that
// session's to judge: it reaches the transport and its RFC 5881, section 5
// checks report it. A peer configured with the wrong local address is the
// common mistake behind such a datagram, and the session's own log is
// where an operator finds it. A shared listener has no single session to
// blame, so it drops instead, which TestListenerRouting covers.
func TestDialUDPUnroutableDatagram(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local, peer := netip.MustParseAddr("127.0.7.1"), netip.MustParseAddr("127.0.7.2")
	tr := dialUDP(t, local, peer)

	// Neither a first contact nor a steady-state packet from a source
	// which is not the peer can be routed, and both must be reported.
	spoofed := newRawPeer(t, netip.MustParseAddr("127.0.7.9"), local, 255)
	spoofed.write(peerPacket(scriptDiscr, 0))
	spoofed.write(peerPacket(scriptDiscr, 0xdeadbeef))

	// A discriminator naming no session, but from the peer itself, passes
	// the section 5 checks and is the Session's to discard, exactly as it
	// was before a listener sat underneath.
	newRawPeer(t, peer, local, 255).write(peerPacket(scriptDiscr, 0xdeadbeef))

	got, drops := readDatagram(t, tr)
	if want := must(peerPacket(scriptDiscr, 0xdeadbeef).AppendBinary(nil)); !bytes.Equal(got, want) {
		t.Fatalf("unexpected payload: got %x, want %x", got, want)
	}

	if drops != 2 {
		t.Fatalf("unexpected drop count: got %d, want 2", drops)
	}
}

func TestListenUDPErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		local netip.Addr
	}{
		{
			name: "no local",
		},
		{
			name:  "multicast local",
			local: netip.MustParseAddr("224.0.0.1"),
		},
		{
			name:  "unspecified local",
			local: netip.MustParseAddr("::"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, err := ListenUDP(tt.local, ListenConfig{})
			if err == nil {
				_ = l.Close()
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

// TestListenerDialErrors exercises the rejections of one listener's Dial,
// which share its fixture: the peers a session cannot be built on, and the
// peer it already has a session with.
func TestListenerDialErrors(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.1.1")
	taken := netip.MustParseAddr("127.0.1.2")

	l := listen(t, local)
	dial(t, l, taken)

	tests := []struct {
		name string
		peer netip.Addr
	}{
		{
			name: "no peer",
		},
		{
			name: "family mismatch",
			peer: netip.MustParseAddr("::1"),
		},
		{
			name: "multicast peer",
			peer: netip.MustParseAddr("224.0.0.1"),
		},
		{
			name: "unspecified peer",
			peer: netip.MustParseAddr("0.0.0.0"),
		},
		{
			name: "duplicate peer",
			peer: taken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := l.Dial(tt.peer)
			if err == nil {
				_ = tr.Close()
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

// TestListenerDialZoneMismatch checks the rejection which keeps a
// link-local listener's routing honest: the kernel reports every
// link-local source with the receiving interface's zone, so a peer naming
// another link, or none, could never be matched to its session. No socket
// is involved, since binding a link-local address needs an interface this
// test cannot assume.
func TestListenerDialZoneMismatch(t *testing.T) {
	t.Parallel()

	// A Listener built by hand, since binding a link-local address needs an
	// interface this test cannot assume. Dial validates the pair before it
	// touches anything but local; the routing tables are built anyway, so a
	// change to that order fails an assertion rather than panicking.
	l := &Listener{
		local:  netip.MustParseAddr("fe80::1%eth0"),
		peers:  make(map[netip.Addr]*listenerTransport),
		discrs: make(map[uint32]*listenerTransport),
	}

	for _, peer := range []netip.Addr{
		netip.MustParseAddr("fe80::2%eth1"),
		netip.MustParseAddr("fe80::2"),
	} {
		tr, err := l.Dial(peer)
		if err == nil {
			_ = tr.Close()
			t.Fatalf("expected an error dialing peer %s, but none occurred", peer)
		}

		if !strings.Contains(err.Error(), "must share a zone") {
			t.Fatalf("unexpected error for peer %s: %v", peer, err)
		}
	}
}

// TestListenerTwoSessionsOneLocalAddress is the listener's reason to
// exist: two single-hop sessions from one local address, one per neighbor,
// all four halves reaching Up over real sockets. The far ends take a local
// address each, which is all DialUDP can do.
func TestListenerTwoSessionsOneLocalAddress(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.2.1")
	peerA, peerB := netip.MustParseAddr("127.0.2.2"), netip.MustParseAddr("127.0.2.3")

	l := listen(t, local)

	ups := []struct {
		name string
		upC  <-chan struct{}
	}{
		{name: "near A", upC: runUDPSession(t, dial(t, l, peerA))},
		{name: "near B", upC: runUDPSession(t, dial(t, l, peerB))},
		{name: "far A", upC: runUDPSession(t, dialUDP(t, peerA, local))},
		{name: "far B", upC: runUDPSession(t, dialUDP(t, peerB, local))},
	}

	for _, up := range ups {
		recv(t, up.upC, up.name+" to reach Up")
	}
}

// TestListenerRouting drives raw datagrams at one listener to exercise
// every routing decision it makes. The cases share the listener and take a
// peer address each, so one case's stragglers cannot reach another's
// session.
func TestListenerRouting(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.3.1")
	l := listen(t, local)

	t.Run("a nonzero your discriminator selects its session", func(t *testing.T) {
		peerA, peerB := netip.MustParseAddr("127.0.3.2"), netip.MustParseAddr("127.0.3.3")
		ta, tb := dial(t, l, peerA), dial(t, l, peerB)

		rawA := newRawPeer(t, peerA, local, 255)
		newRawPeer(t, peerB, local, 255)

		// Each session's first transmission is what teaches the listener
		// its discriminator; no caller registers anything.
		const discrA, discrB uint32 = 0x0a0a0a0a, 0x0b0b0b0b
		writePacket(t, ta, peerPacket(discrA, 0))
		writePacket(t, tb, peerPacket(discrB, 0))

		// B's discriminator from A's address belongs to B, where the
		// source check fails it. It must never be re-routed to A, so the
		// properly addressed packet behind it is the first thing A sees.
		rawA.write(peerPacket(scriptDiscr, discrB))
		rawA.write(peerPacket(scriptDiscr, discrA))

		if _, err := readOnce(t, tb); !errors.Is(err, ErrDropped) {
			t.Fatalf("expected a drop report on B, but got: %v", err)
		}

		got, drops := readDatagram(t, ta)
		if want := must(peerPacket(scriptDiscr, discrA).AppendBinary(nil)); !bytes.Equal(got, want) {
			t.Fatalf("unexpected A payload: got %x, want %x", got, want)
		}

		if drops != 0 {
			t.Fatalf("unexpected A drop count: got %d, want 0", drops)
		}
	})

	t.Run("a zero your discriminator selects by source address", func(t *testing.T) {
		peerC, peerD := netip.MustParseAddr("127.0.3.4"), netip.MustParseAddr("127.0.3.5")
		tc, td := dial(t, l, peerC), dial(t, l, peerD)

		rawC := newRawPeer(t, peerC, local, 255)
		rawD := newRawPeer(t, peerD, local, 255)

		// Neither session has transmitted, so neither discriminator is
		// known: first contact is the address pair's to route, and each
		// packet's My Discriminator says which peer sent it.
		const discrC, discrD uint32 = 0x0c0c0c0c, 0x0d0d0d0d
		rawC.write(peerPacket(discrC, 0))
		rawD.write(peerPacket(discrD, 0))

		for _, tt := range []struct {
			name  string
			tr    Transport
			discr uint32
		}{
			{name: "C", tr: tc, discr: discrC},
			{name: "D", tr: td, discr: discrD},
		} {
			got, drops := readDatagram(t, tt.tr)
			if want := must(peerPacket(tt.discr, 0).AppendBinary(nil)); !bytes.Equal(got, want) {
				t.Fatalf("unexpected %s payload: got %x, want %x", tt.name, got, want)
			}

			if drops != 0 {
				t.Fatalf("unexpected %s drop count: got %d, want 0", tt.name, drops)
			}
		}
	})

	t.Run("an unknown discriminator never reaches a session", func(t *testing.T) {
		peerE := netip.MustParseAddr("127.0.3.6")
		te := dial(t, l, peerE)
		rawE := newRawPeer(t, peerE, local, 255)

		// No session owns this discriminator, so the listener drops the
		// datagram itself. The first contact behind it arrives with no
		// drop report before it, which is the proof nothing surfaced.
		rawE.write(peerPacket(scriptDiscr, 0xdeadbeef))
		rawE.write(peerPacket(scriptDiscr, 0))

		got, drops := readDatagram(t, te)
		if want := must(peerPacket(scriptDiscr, 0).AppendBinary(nil)); !bytes.Equal(got, want) {
			t.Fatalf("unexpected E payload: got %x, want %x", got, want)
		}

		if drops != 0 {
			t.Fatalf("unexpected E drop count: got %d, want 0", drops)
		}
	})

	t.Run("a TTL below 255 is dropped by the routed session", func(t *testing.T) {
		peerF := netip.MustParseAddr("127.0.3.7")
		tf := dial(t, l, peerF)

		// The RFC 5881, section 5 checks stay below the Transport seam and
		// surface on the session the datagram routed to.
		newRawPeer(t, peerF, local, 1).write(peerPacket(scriptDiscr, 0))

		if _, err := readOnce(t, tf); !errors.Is(err, ErrDropped) {
			t.Fatalf("expected a drop report on F, but got: %v", err)
		}
	})
}

// TestListenerTransportClose checks that one session's teardown is its
// own: its pending read fails, its peer address is free again, and its
// sibling on the same listener carries on.
func TestListenerTransportClose(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.4.1")
	peerA, peerB := netip.MustParseAddr("127.0.4.2"), netip.MustParseAddr("127.0.4.3")

	l := listen(t, local)
	ta, tb := dial(t, l, peerA), dial(t, l, peerB)
	rawB := newRawPeer(t, peerB, local, 255)

	// Close is called concurrently with a pending read and must unblock it
	// terminally, so Session.Run returns instead of reading again.
	errC := readAsync(ta)
	if err := ta.Close(); err != nil {
		t.Fatalf("failed to close transport A: %v", err)
	}

	if err := recv(t, errC, "A's read to unblock"); err == nil || errors.Is(err, ErrDropped) {
		t.Fatalf("expected a terminal error from A's read, but got: %v", err)
	}

	// The listener's receive socket is untouched, so B is still routed.
	rawB.write(peerPacket(scriptDiscr, 0))
	if _, drops := readDatagram(t, tb); drops != 0 {
		t.Fatalf("unexpected B drop count: got %d, want 0", drops)
	}

	// A closed session leaves its registrations behind it: Close again is
	// harmless, and the peer address may be dialed afresh.
	if err := ta.Close(); err != nil {
		t.Fatalf("failed to close transport A again: %v", err)
	}

	tr, err := l.Dial(peerA)
	if err != nil {
		t.Fatalf("failed to redial peer A: %v", err)
	}
	_ = tr.Close()
}

// TestListenerClose checks the listener's own teardown: every session over
// it ends terminally, no new one may start, and closing twice is harmless.
func TestListenerClose(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.5.1")
	peerA, peerB := netip.MustParseAddr("127.0.5.2"), netip.MustParseAddr("127.0.5.3")

	l := listen(t, local)
	ta, tb := dial(t, l, peerA), dial(t, l, peerB)

	errA, errB := readAsync(ta), readAsync(tb)
	if err := l.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	// A read error wrapping ErrDropped is not terminal, so the read
	// goroutine's exit must report something else or a session would read
	// forever against a dead listener.
	for _, tt := range []struct {
		name string
		errC <-chan error
	}{
		{name: "A", errC: errA},
		{name: "B", errC: errB},
	} {
		err := recv(t, tt.errC, tt.name+"'s read to unblock")
		if err == nil || errors.Is(err, ErrDropped) {
			t.Fatalf("expected a terminal error from %s's read, but got: %v", tt.name, err)
		}
	}

	if tr, err := l.Dial(netip.MustParseAddr("127.0.5.4")); err == nil {
		_ = tr.Close()
		t.Fatal("expected an error dialing a closed listener, but none occurred")
	}

	// Session.Run closes its own transport as it returns, after the
	// listener already closed it. That must be quiet.
	if err := ta.Close(); err != nil {
		t.Fatalf("failed to close transport A: %v", err)
	}

	// Closing again is harmless, concurrently included: the teardown runs
	// once, and every caller joins the read goroutine before returning
	// rather than racing past it.
	errC := make(chan error, 2)
	for range 2 {
		go func() { errC <- l.Close() }()
	}

	for range 2 {
		if err := recv(t, errC, "a repeated Close to return"); err != nil {
			t.Fatalf("failed to close listener again: %v", err)
		}
	}
}

// TestListenerReadFailure checks the listener's other terminal exit: the
// receive socket dying under it, with no Close to close the sessions too.
// A read error wrapping ErrDropped is not terminal, so the read
// goroutine's own exit must report something else or every session over
// the listener would read forever against a socket which is gone.
func TestListenerReadFailure(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.6.1")
	l := listen(t, local)
	dial(t, l, netip.MustParseAddr("127.0.6.2"))
	tb := dial(t, l, netip.MustParseAddr("127.0.6.3"))

	errC := readAsync(tb)

	// Only a Listener can reach its own receive socket, so only this
	// package can stage its failure.
	_ = l.rx.Close()

	if err := recv(t, errC, "the read to unblock"); err == nil || errors.Is(err, ErrDropped) {
		t.Fatalf("expected a terminal error from the read, but got: %v", err)
	}
}

// TestListenerCloseWhileRouting pins why a session's queue is never
// closed. Routing releases the listener's mutex before it queues a
// datagram, so a session closing at that instant is racing the send, and a
// closed queue would panic the listener's read goroutine and take every
// other session with it. A session ending while its peer still transmits
// is ordinary, so this drives both routing tables through close and redial
// under a steady stream of datagrams. The race detector is the assertion;
// the exchange at the end proves the listener still routes afterwards.
func TestListenerCloseWhileRouting(t *testing.T) {
	t.Parallel()
	requireLoopbackAddrs(t)

	local := netip.MustParseAddr("127.0.8.1")
	l := listen(t, local)

	peers := []netip.Addr{
		netip.MustParseAddr("127.0.8.2"),
		netip.MustParseAddr("127.0.8.3"),
		netip.MustParseAddr("127.0.8.4"),
	}

	// Bounded on both sides, so the volume is enough to overlap but small
	// enough that the listener's own Debug log of each unroutable datagram
	// stays readable.
	const rounds = 500

	var wg sync.WaitGroup
	for _, peer := range peers {
		raw := newRawPeer(t, peer, local, 255)
		wg.Go(func() {
			for range rounds {
				_ = raw.send(peerPacket(scriptDiscr, 0))
			}
		})
	}

	for i, peer := range peers {
		// A transmission registers a discriminator, so closing and
		// redialling churns the discriminator table too, not only the
		// addresses.
		opening := must(peerPacket(0xabc0000+uint32(i), 0).AppendBinary(nil))
		wg.Go(func() {
			for range rounds {
				tr, err := l.Dial(peer)
				if err != nil {
					continue
				}

				_ = tr.WritePacket(opening)
				_ = tr.Close()
			}
		})
	}

	wg.Wait()

	// A session dialed after the churn still receives, so the listener and
	// its read goroutine came through intact.
	peer := netip.MustParseAddr("127.0.8.5")
	tr := dial(t, l, peer)
	newRawPeer(t, peer, local, 255).write(peerPacket(scriptDiscr, 0))

	if _, drops := readDatagram(t, tr); drops != 0 {
		t.Fatalf("unexpected drop count: got %d, want 0", drops)
	}
}

// TestSourceKey covers the normalization of a datagram's source into the
// listener's routing key, the zone above all: two peers on different links
// may hold the same link-local address, so a key which dropped the zone
// would route one's packets to the other.
func TestSourceKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  net.Addr
		want netip.Addr
		ok   bool
	}{
		{
			name: "not a UDP address",
			src:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: Port},
		},
		{
			name: "IPv4",
			src:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: Port},
			want: netip.MustParseAddr("127.0.0.1"),
			ok:   true,
		},
		{
			name: "4-in-6 mapped",
			src:  &net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: Port},
			want: netip.MustParseAddr("127.0.0.1"),
			ok:   true,
		},
		{
			name: "IPv6",
			src:  &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: Port},
			want: netip.MustParseAddr("fd00::1"),
			ok:   true,
		},
		{
			name: "link-local IPv6 with a zone",
			src:  &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: Port, Zone: "eth0"},
			want: netip.MustParseAddr("fe80::1%eth0"),
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := sourceKey(tt.src)
			if ok != tt.ok {
				t.Fatalf("unexpected ok: got %v, want %v", ok, tt.ok)
			}

			if got != tt.want {
				t.Fatalf("unexpected key: got %s, want %s", got, tt.want)
			}
		})
	}

	// The zone is part of the key, not decoration on it.
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if zoned == zoned.WithZone("") {
		t.Fatal("a zoned key must not equal its unzoned address")
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

// requireLoopbackAddrs skips a test which binds several 127.0.0.0/8
// addresses, which only Linux provides by default.
func requireLoopbackAddrs(tb testing.TB) {
	tb.Helper()

	if runtime.GOOS != "linux" {
		tb.Skip("skipping, test binds several 127.0.0.0/8 addresses, which only Linux provides by default")
	}
}

// listen builds a Listener on local, closed when the test ends.
func listen(tb testing.TB, local netip.Addr) *Listener {
	tb.Helper()

	l, err := ListenUDP(local, ListenConfig{Logger: testLogger(tb)})
	if err != nil {
		tb.Fatalf("failed to listen on %s: %v", local, err)
	}
	tb.Cleanup(func() { _ = l.Close() })

	return l
}

// dial builds one peer's Transport on l, closed when the test ends.
func dial(tb testing.TB, l *Listener, peer netip.Addr) Transport {
	tb.Helper()

	tr, err := l.Dial(peer)
	if err != nil {
		tb.Fatalf("failed to dial peer %s: %v", peer, err)
	}
	tb.Cleanup(func() { _ = tr.Close() })

	return tr
}

// dialUDP builds an exclusive-port Transport between local and peer,
// closed when the test ends.
func dialUDP(tb testing.TB, local, peer netip.Addr) Transport {
	tb.Helper()

	tr, err := DialUDP(local, peer)
	if err != nil {
		tb.Fatalf("failed to dial %s to %s: %v", local, peer, err)
	}
	tb.Cleanup(func() { _ = tr.Close() })

	return tr
}

// runUDPSession runs a Session over tr for the rest of the test,
// delivering each OnUp on the returned channel. Cleanup cancels Run and
// verifies its exit, before the transport's own cleanup closes it.
func runUDPSession(tb testing.TB, tr Transport) <-chan struct{} {
	tb.Helper()

	upC := make(chan struct{}, 4)
	s, err := NewSession(tr, Config{
		OnUp:   func(*Session) { upC <- struct{}{} },
		Logger: testLogger(tb),
	})
	if err != nil {
		tb.Fatalf("failed to build session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx) }()

	tb.Cleanup(func() {
		cancel()
		if err := recv(tb, runC, "Run to return"); !errors.Is(err, context.Canceled) {
			tb.Errorf("unexpected Run error: %v", err)
		}
	})

	return upC
}

// peerPacket is one well-formed control packet from a scripted far end: a
// first contact when your is zero, and the steady state otherwise.
func peerPacket(my, your uint32) *ControlPacket {
	return &ControlPacket{
		State:             StateDown,
		DetectMultiplier:  3,
		MyDiscriminator:   my,
		YourDiscriminator: your,
		DesiredMinTX:      300 * time.Millisecond,
		RequiredMinRX:     300 * time.Millisecond,
	}
}

// writePacket transmits one control packet through a transport, as a
// session's own transmission does, which is also what teaches a Listener
// the session's discriminator.
func writePacket(tb testing.TB, tr Transport, p *ControlPacket) {
	tb.Helper()

	if err := tr.WritePacket(must(p.AppendBinary(nil))); err != nil {
		tb.Fatalf("failed to write packet: %v", err)
	}
}

// A rawPeer stands in for the far end of a session without running one: it
// holds its address's Port, so the datagrams a listener sends there are
// absorbed rather than answered with ICMP, and it writes packets to the
// listener with whatever TTL the scenario calls for.
type rawPeer struct {
	tb testing.TB
	c  *net.UDPConn
	to *net.UDPAddr
}

// newRawPeer binds addr's Port and aims at local's, torn down when the
// test ends.
func newRawPeer(tb testing.TB, addr, local netip.Addr, ttl int) *rawPeer {
	tb.Helper()

	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, Port)))
	if err != nil {
		tb.Fatalf("failed to bind raw peer %s: %v", addr, err)
	}
	tb.Cleanup(func() { _ = c.Close() })

	if err := ipv4.NewConn(c).SetTTL(ttl); err != nil {
		tb.Fatalf("failed to set raw peer TTL: %v", err)
	}

	return &rawPeer{
		tb: tb,
		c:  c,
		to: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, Port)),
	}
}

// write sends one control packet to the listener. Datagrams written in
// sequence from one socket arrive in that sequence, which is what lets a
// scenario put a well-formed packet behind a hostile one and assert the
// hostile one never surfaced.
func (p *rawPeer) write(cp *ControlPacket) {
	p.tb.Helper()

	if err := p.send(cp); err != nil {
		p.tb.Fatalf("failed to write from raw peer: %v", err)
	}
}

// send is write for a goroutine other than the test's, which must not call
// Fatalf. A write losing a race with the test's own teardown is harmless.
func (p *rawPeer) send(cp *ControlPacket) error {
	_, err := p.c.WriteToUDP(must(cp.AppendBinary(nil)), p.to)
	return err
}

// readAsync starts one ReadPacket on a goroutine and returns the channel
// its error lands on, so a test can hold a read open across a Close.
func readAsync(tr Transport) <-chan error {
	errC := make(chan error, 1)
	go func() {
		b := make([]byte, 64)
		_, err := tr.ReadPacket(b)
		errC <- err
	}()

	return errC
}

// readOnce performs one ReadPacket on a goroutine, so a routing bug which
// delivers nothing fails the test instead of hanging it.
func readOnce(tb testing.TB, tr Transport) ([]byte, error) {
	tb.Helper()

	type result struct {
		b   []byte
		err error
	}

	resC := make(chan result, 1)
	go func() {
		b := make([]byte, 64)
		n, err := tr.ReadPacket(b)
		resC <- result{b: b[:n], err: err}
	}()

	res := recv(tb, resC, "a read to return")

	return res.b, res.err
}
