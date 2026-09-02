//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"
	"time"

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
	hostAddr4 = netip.MustParseAddr(hostV4)
	hostAddr6 = netip.MustParseAddr(hostV6)
)

// Scenario 1: session establishment, per address family. Both sides
// reach Up, and FRR's JSON view is the oracle's record of what this
// library put on the wire: our discriminator, our multiplier, and our
// negotiated intervals.

func TestFRRUpIPv4(t *testing.T) { testFRRUp(t, false) }
func TestFRRUpIPv6(t *testing.T) { testFRRUp(t, true) }

func testFRRUp(t *testing.T, v6 bool) {
	f, host := startFRRPeer(t, v6)

	peer := f.Addr
	if v6 {
		peer = f.Addr6
	}

	s, upC, _ := runSession(t, host, peer)
	await(t, upC, "OnUp")

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

	if got, want := p.RemoteID, s.LocalDiscriminator(); got != want {
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
	f, host := startFRRPeer(t, false)

	_, upC, downC, cancel := runSessionCancel(t, host, f.Addr)
	await(t, upC, "OnUp")
	f.awaitStatus(t, host, "up")

	cancel()
	d := await(t, downC, "OnDown")
	if d.Diag != bfd.DiagAdministrativelyDown || d.Err != nil {
		t.Fatalf("unexpected OnDown: %+v", d)
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
// diagnostic; no shutdown brings a second handshake and a second OnUp,
// the perpetual session against a real implementation.
func TestFRRNeighborAdminDown(t *testing.T) {
	f, host := startFRRPeer(t, false)

	_, upC, downC := runSession(t, host, f.Addr)
	await(t, upC, "OnUp")

	peerCmd := "peer " + host.String() + " local-address " + f.Addr.String()
	f.configure(t, "bfd", peerCmd, "shutdown")

	d := await(t, downC, "OnDown")
	if d.Diag != bfd.DiagNeighborSignaledSessionDown || d.Err != nil {
		t.Fatalf("unexpected OnDown: %+v", d)
	}

	f.configure(t, "bfd", peerCmd, "no shutdown")
	await(t, upC, "a second OnUp")
	f.awaitStatus(t, host, "up")
}

// Scenario 4: real detection. Severing the veth link silences both
// directions without any farewell, so each side must time the other
// out; restoring it brings both back Up.
func TestFRRDetectionExpired(t *testing.T) {
	f, host := startFRRPeer(t, false)

	_, upC, downC := runSession(t, host, f.Addr)
	await(t, upC, "OnUp")
	f.awaitStatus(t, host, "up")

	linkSet(t, "down")
	d := await(t, downC, "OnDown")
	if d.Diag != bfd.DiagControlDetectionTimeExpired || d.Err != nil {
		t.Fatalf("unexpected OnDown: %+v", d)
	}

	// The oracle timed us out too. Its diagnostic must be checked
	// mid-outage: FRR clears it back to "ok" on recovery.
	p := f.awaitStatus(t, host, "down")
	if got, want := p.Diagnostic, "control detection time expired"; got != want {
		t.Errorf("FRR reports unexpected local diagnostic: got %q, want %q", got, want)
	}

	linkSet(t, "up")
	await(t, upC, "a second OnUp")
	f.awaitStatus(t, host, "up")
}

// Scenario 5: holding Up. The packets just after reaching Up are the
// easiest to mistime: reaching Up lifts the slow-start clamp, and a
// transmit timer still armed with the old one second spacing leaves a
// gap that overshoots FRR's 900ms detection time, flapping the session
// exactly once before it self-heals. Hold for several detection times
// and require silence from OnDown, with FRR still up at the end.
func TestFRRHoldAfterUp(t *testing.T) {
	f, host := startFRRPeer(t, false)

	_, upC, downC := runSession(t, host, f.Addr)
	await(t, upC, "OnUp")
	f.awaitStatus(t, host, "up")

	// An absence has no signal to await, so the hold is wall-clock time
	// against the oracle's real timers, sized at several detection
	// times: the same documented exception as poll.
	select {
	case d := <-downC:
		t.Fatalf("session flapped after reaching Up: %+v", d)
	case <-time.After(4 * time.Second):
	}

	f.awaitStatus(t, host, "up")
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

// A sessionDown is one OnDown invocation, delivered by runSession.
type sessionDown struct {
	Diag bfd.Diagnostic
	Err  error
}

// runSession dials the RFC 5881 transport from local to peer and runs
// a Session over it on a test-scoped goroutine, returning the Session
// and channels delivering each OnUp and OnDown. Teardown cancels Run
// and joins it when t ends.
func runSession(t *testing.T, local, peer netip.Addr) (*bfd.Session, <-chan struct{}, <-chan sessionDown) {
	t.Helper()

	s, upC, downC, _ := runSessionCancel(t, local, peer)
	return s, upC, downC
}

// runSessionCancel is runSession, also returning the cancel function
// of Run's context so lifecycle tests can end the session themselves.
// Test cleanup still cancels and joins, harmlessly, after the test's
// own cancellation.
func runSessionCancel(t *testing.T, local, peer netip.Addr) (*bfd.Session, <-chan struct{}, <-chan sessionDown, context.CancelFunc) {
	t.Helper()

	tr, err := bfd.DialUDP(local, peer)
	if err != nil {
		t.Fatalf("failed to dial transport: %v", err)
	}

	upC := make(chan struct{}, 4)
	downC := make(chan sessionDown, 4)
	s, err := bfd.NewSession(tr, bfd.Config{
		OnUp:   func(_ *bfd.Session) { upC <- struct{}{} },
		OnDown: func(_ *bfd.Session, d bfd.Diagnostic, err error) { downC <- sessionDown{Diag: d, Err: err} },
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

	return s, upC, downC, cancel
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
