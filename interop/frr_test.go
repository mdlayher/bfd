//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mdlayher/bfd"
)

// The harness timing fixture: the library's own defaults (300ms
// intervals, a multiplier of 3) mirrored explicitly into FRR, so a
// severed path is detected in roughly a second on either side.
const (
	intervalMS = 300
	multiplier = 3
)

var (
	hostAddr4    = netip.MustParseAddr(hostV4)
	hostAddr4Alt = netip.MustParseAddr(hostV4Alt)
	hostAddr6    = netip.MustParseAddr(hostV6)
)

// Scenario 1: session establishment, per address family. Both sides
// reach Up, and FRR's JSON view is the oracle's record of what this
// library put on the wire: our discriminator, our multiplier, and our
// negotiated intervals.

func TestFRRUpIPv4(t *testing.T) {
	t.Parallel()

	testFRRUp(t, false)
}

func TestFRRUpIPv6(t *testing.T) {
	t.Parallel()

	testFRRUp(t, true)
}

func testFRRUp(t *testing.T, v6 bool) {
	f, host := startFRRPeer(t, v6)

	peer := f.Addr
	if v6 {
		peer = f.Addr6
	}

	ls := runSession(t, host, peer)
	await(t, ls.upC, "OnUp")

	// FRR's view of us: the remote-* fields echo our wire values. FRR
	// reaches up on our last pre-Up packet, whose transmit desire still
	// carries the RFC 5880, section 6.8.3 slow-start clamp; the 300ms
	// steady state arrives with our first Up transmission, so poll to
	// convergence rather than racing it.
	var p frrPeerJSON
	f.poll(t, "peer never converged to the steady state", func() bool {
		var err error
		p, err = f.peer(t, host)
		return err == nil && p.Status == "up" && p.RemoteTransmitInterval == intervalMS
	})

	if got, want := p.RemoteID, ls.s.LocalDiscriminator(); got != want {
		t.Errorf("FRR reports unexpected remote discriminator: got %d, want %d", got, want)
	}

	if got, want := p.RemoteDetectMultiplier, multiplier; got != want {
		t.Errorf("FRR reports unexpected remote multiplier: got %d, want %d", got, want)
	}

	if got, want := p.RemoteReceiveInterval, intervalMS; got != want {
		t.Errorf("FRR reports unexpected remote receive interval: got %dms, want %dms", got, want)
	}

	if p.ID == 0 {
		t.Error("FRR reports a zero local discriminator")
	}
}

// Scenario 2: the cancellation farewell. Run's teardown transmits
// AdminDown, so the oracle records a deliberate goodbye rather than
// waiting out its detection time.
func TestFRRCancelFarewell(t *testing.T) {
	t.Parallel()

	f, host := startFRRPeer(t, false)

	ls := runSession(t, host, f.Addr)
	await(t, ls.upC, "OnUp")
	f.awaitStatus(t, host, "up")

	ls.cancel()

	// The fall is local: the peer's last report was its own Up.
	want := sessionDown{
		Diag:   bfd.DiagAdministrativelyDown,
		Remote: bfd.StateUp,
	}

	if d := diff(t, want, await(t, ls.downC, "OnDown")); d != "" {
		t.Fatalf("unexpected OnDown (-want +got):\n%s", d)
	}

	// The farewell reaches FRR as our AdminDown: its session falls
	// immediately, recording our administrative diagnostic.
	p := f.awaitStatus(t, host, "down")
	if got, want := p.RemoteDiagnostic, "administratively down"; got != want {
		t.Errorf("FRR reports unexpected remote diagnostic: got %q, want %q", got, want)
	}
}

// Scenario 3: the oracle signals down and comes back. FRR's shutdown
// transmits AdminDown toward us, felling the session with the neighbor
// diagnostic and the peer's AdminDown, which RFC 5882, section 3.2 says a
// client must not treat as a forwarding failure; no shutdown brings a
// second handshake and a second OnUp, the perpetual session against a real
// implementation.
func TestFRRNeighborAdminDown(t *testing.T) {
	t.Parallel()

	f, host := startFRRPeer(t, false)

	ls := runSession(t, host, f.Addr)
	await(t, ls.upC, "OnUp")

	peerCmd := "peer " + host.String() + " local-address " + f.Addr.String()
	f.configure(t, "bfd", peerCmd, "shutdown")

	want := sessionDown{
		Diag:   bfd.DiagNeighborSignaledSessionDown,
		Remote: bfd.StateAdminDown,
	}

	if d := diff(t, want, await(t, ls.downC, "OnDown")); d != "" {
		t.Fatalf("unexpected OnDown (-want +got):\n%s", d)
	}

	f.configure(t, "bfd", peerCmd, "no shutdown")
	await(t, ls.upC, "a second OnUp")
	f.awaitStatus(t, host, "up")
}

// Scenario 4: real detection. Severing the veth link silences both
// directions without any farewell, so each side must time the other
// out; restoring it brings both back Up.
func TestFRRDetectionExpired(t *testing.T) {
	t.Parallel()

	f, host := startFRRPeer(t, false)

	ls := runSession(t, host, f.Addr)
	await(t, ls.upC, "OnUp")
	f.awaitStatus(t, host, "up")

	linkSet(t, "down")

	// The peer said nothing new: its last report was its own Up.
	want := sessionDown{
		Diag:   bfd.DiagControlDetectionTimeExpired,
		Remote: bfd.StateUp,
	}

	if d := diff(t, want, await(t, ls.downC, "OnDown")); d != "" {
		t.Fatalf("unexpected OnDown (-want +got):\n%s", d)
	}

	// The oracle timed us out too. Its diagnostic must be checked
	// mid-outage: FRR clears it back to "ok" on recovery.
	p := f.awaitStatus(t, host, "down")
	if got, want := p.Diagnostic, "control detection time expired"; got != want {
		t.Errorf("FRR reports unexpected local diagnostic: got %q, want %q", got, want)
	}

	linkSet(t, "up")
	await(t, ls.upC, "a second OnUp")
	f.awaitStatus(t, host, "up")
}

// Scenario 5: holding Up. The packets just after reaching Up are the
// easiest to mistime: reaching Up lifts the slow-start clamp, and a
// transmit timer still armed with the old one second spacing leaves a
// gap that overshoots FRR's 900ms detection time, flapping the session
// exactly once before it self-heals. Hold for several detection times
// and require silence from OnDown, with FRR still up at the end.
func TestFRRHoldAfterUp(t *testing.T) {
	t.Parallel()

	f, host := startFRRPeer(t, false)

	ls := runSession(t, host, f.Addr)
	await(t, ls.upC, "OnUp")
	f.awaitStatus(t, host, "up")

	// An absence has no signal to await, so the hold is wall-clock time
	// against the oracle's real timers, sized at several detection
	// times: the same documented exception as poll.
	select {
	case d := <-ls.downC:
		t.Fatalf("session flapped after reaching Up: %+v", d)
	case <-time.After(4 * time.Second):
	}

	f.awaitStatus(t, host, "up")
}

// Scenario 6: the shared listener. One local address carries two
// sessions at once, the oracle's and a second one to another host
// address, so FRR's datagrams must be demultiplexed to their own
// session against live traffic on the same socket. FRR is only ever
// one of the two peers: see hostV4Alt for why a second FRR-side peer
// would take a second instance.
func TestFRRSharedListener(t *testing.T) {
	t.Parallel()

	f, host := startFRRPeer(t, false)

	l, err := bfd.ListenUDP(host, bfd.ListenConfig{})
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", host, err)
	}

	t.Cleanup(func() { _ = l.Close() })

	oracle := runTransport(t, dialListener(t, l, f.Addr), nil)
	sibling := runTransport(t, dialListener(t, l, hostAddr4Alt), nil)
	far := runSession(t, hostAddr4Alt, host)

	await(t, oracle.upC, "OnUp against the oracle")
	await(t, sibling.upC, "OnUp on the sibling session")
	await(t, far.upC, "OnUp on the sibling's far end")

	// The oracle's own view is the proof its packets landed on its own
	// session: the discriminator FRR learned is that session's, not the
	// sibling's, and FRR would never have reached up without them.
	p := f.awaitStatus(t, host, "up")
	if got, want := p.RemoteID, oracle.s.LocalDiscriminator(); got != want {
		t.Errorf("FRR reports unexpected remote discriminator: got %d, want %d", got, want)
	}
}

// startFRRPeer starts an FRR instance configured with the harness
// timing fixture for one single-hop peer, returning it and the host
// address the library session uses for the chosen family.
func startFRRPeer(t *testing.T, v6 bool) (*frr, netip.Addr) {
	t.Helper()

	host, local := hostAddr4, netip.MustParseAddr(frrV4)
	if v6 {
		host, local = hostAddr6, netip.MustParseAddr(frrV6)
	}

	f := startFRR(t, frrConfig{
		Peers: []frrPeer{{
			Addr:       host,
			Local:      local,
			Multiplier: multiplier,
			RXMS:       intervalMS,
			TXMS:       intervalMS,
		}},
	})

	return f, host
}

// A sessionDown is one OnDown invocation, delivered by a libSession.
type sessionDown struct {
	Diag   bfd.Diagnostic
	Remote bfd.State
	Err    error
}

// A libSession is a library Session running under test on a
// test-scoped goroutine, with channels delivering each OnUp and OnDown
// and Run's cancel function. Test cleanup still cancels and joins Run,
// harmlessly, after a test's own cancellation.
type libSession struct {
	s      *bfd.Session
	upC    <-chan struct{}
	downC  <-chan sessionDown
	cancel context.CancelFunc
}

// runSession dials the RFC 5881 transport from local to peer and runs an
// unauthenticated Session over it.
func runSession(t *testing.T, local, peer netip.Addr) *libSession {
	t.Helper()

	return runTransport(t, dialUDP(t, local, peer), nil)
}

// dialUDP dials the RFC 5881 transport from local to peer.
func dialUDP(t *testing.T, local, peer netip.Addr) bfd.Transport {
	t.Helper()

	tr, err := bfd.DialUDP(local, peer)
	if err != nil {
		t.Fatalf("failed to dial transport: %v", err)
	}

	return tr
}

// dialListener builds one peer's Transport on a shared listener.
func dialListener(t *testing.T, l *bfd.Listener, peer netip.Addr) bfd.Transport {
	t.Helper()

	tr, err := l.Dial(peer)
	if err != nil {
		t.Fatalf("failed to dial peer %s: %v", peer, err)
	}

	return tr
}

// runTransport runs a Session over tr, authenticated with auth when it is
// non-nil. Teardown cancels Run and joins it when t ends.
func runTransport(t *testing.T, tr bfd.Transport, auth *bfd.AuthConfig) *libSession {
	t.Helper()

	upC := make(chan struct{}, 4)
	downC := make(chan sessionDown, 4)
	s, err := bfd.NewSession(tr, bfd.Config{
		OnUp: func(_ *bfd.Session) { upC <- struct{}{} },

		OnDown: func(_ *bfd.Session, d bfd.Diagnostic, remote bfd.State, err error) {
			downC <- sessionDown{
				Diag:   d,
				Remote: remote,
				Err:    err,
			}
		},

		Auth: auth,
	})
	if err != nil {
		_ = tr.Close()
		t.Fatalf("failed to build session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Run(ctx); ctx.Err() == nil {
			t.Logf("session run: %v", err)
		}
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &libSession{
		s:      s,
		upC:    upC,
		downC:  downC,
		cancel: cancel,
	}
}

// linkSet flips the host side of the veth pair, severing or restoring
// the path between the library and the oracle.
func linkSet(t *testing.T, state string) {
	t.Helper()

	if out, err := exec.Command("ip", "link", "set", vethHost, state).CombinedOutput(); err != nil {
		t.Fatalf("failed to set %s %s: %v: %s", vethHost, state, err, out)
	}
}

// await receives one value from ch, failing the test if none arrives
// within the oracle deadline. Interop waits are generous: the oracle's
// timers are real.
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(60 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal. An error matches its want by errors.Is.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()

	return cmp.Diff(want, got, cmpopts.EquateErrors())
}
