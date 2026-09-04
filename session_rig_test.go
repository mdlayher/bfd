package bfd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// timeout bounds every rig wait: fake time inside a synctest bubble, real
// time outside one.
const timeout = 30 * time.Second

// scriptDiscr is the discriminator of the scripted peer: arbitrary, nonzero,
// and impossible to mistake for the session's random one in a test failure.
const scriptDiscr uint32 = 0xbfdbfd

// memTransports returns the two ends of an in-memory packet pipe for
// synctest bubbles. Writes buffer generously and never block, as UDP
// effectively does at test sizes, so a session transmitting while the
// scripted side is mid-sleep never distorts the timing under test; a write
// beyond the buffer is dropped, as UDP would drop it. Reads block on a
// channel, so a bubble sees them as durably blocked and fake time advances
// across them.
func memTransports() (a, b *memTransport) {
	ab := make(chan []byte, 64)
	ba := make(chan []byte, 64)
	return &memTransport{in: ba, out: ab, errC: make(chan error, 1), done: make(chan struct{})},
		&memTransport{in: ab, out: ba, errC: make(chan error, 1), done: make(chan struct{})}
}

// A memTransport is one end of an in-memory packet pipe: each channel value
// is one whole packet. failRead injects a read failure, the terminal fault
// of a real socket.
type memTransport struct {
	in, out chan []byte
	errC    chan error
	done    chan struct{}
	once    sync.Once
}

func (t *memTransport) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-t.in:
		return copy(b, p), nil
	case err := <-t.errC:
		return 0, err
	case <-t.done:
		return 0, net.ErrClosed
	}
}

// failRead makes a pending or future ReadPacket return err.
func (t *memTransport) failRead(err error) { t.errC <- err }

func (t *memTransport) WritePacket(b []byte) error {
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}

	// The session reuses its marshal buffer across transmissions, so the
	// packet must be copied before it crosses goroutines.
	p := slices.Clone(b)
	select {
	case t.out <- p:
	default:
		// The buffer is full: the packet is lost, as a UDP datagram would be.
	}

	return nil
}

// Close unblocks this end's pending reads; the other end is unaffected, as
// closing one socket leaves its peer's open.
func (t *memTransport) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}

// A stateChange is one OnStateChange invocation, recorded by the rig.
type stateChange struct {
	From, To State
}

// A down is one OnDown invocation, recorded by the rig.
type down struct {
	Diag Diagnostic
	Err  error
}

// A sessionRig runs one Session under test over an in-memory transport: its
// hooks record every transition, and Run's lifecycle is managed for the
// test. Jitter is fixed at one, so each transmit interval is exactly the
// negotiated interval and a bubble's fake clock makes every test timing
// deterministic.
type sessionRig struct {
	tb     testing.TB
	s      *Session
	local  *memTransport
	script *script
	cancel context.CancelFunc

	upC    chan struct{}
	downC  chan down
	stateC chan stateChange
}

// newSessionRig builds a Session from cfg with recording hooks and runs it
// in the background. Run must exit via cancellation by the end of the test;
// the rig's cleanup cancels it and verifies the exit.
func newSessionRig(tb testing.TB, cfg Config) *sessionRig {
	tb.Helper()

	r := &sessionRig{
		tb:     tb,
		upC:    make(chan struct{}, 4),
		downC:  make(chan down, 4),
		stateC: make(chan stateChange, 32),
	}

	// The rig's recorders run first, then any hook the test configured.
	userUp, userDown, userState := cfg.OnUp, cfg.OnDown, cfg.OnStateChange
	cfg.OnUp = func(s *Session) {
		r.upC <- struct{}{}
		if userUp != nil {
			userUp(s)
		}
	}

	cfg.OnDown = func(s *Session, d Diagnostic, err error) {
		r.downC <- down{Diag: d, Err: err}
		if userDown != nil {
			userDown(s, d, err)
		}
	}

	cfg.OnStateChange = func(s *Session, from, to State) {
		r.stateC <- stateChange{From: from, To: to}
		if userState != nil {
			userState(s, from, to)
		}
	}

	if cfg.Logger == nil {
		cfg.Logger = testLogger(tb)
	}

	local, remote := memTransports()
	tb.Cleanup(func() { _ = remote.Close() })

	s := must(NewSession(local, cfg))
	s.jitter = func() float64 { return 1 }
	r.s = s
	r.local = local
	r.script = &script{tb: tb, t: remote, discr: s.LocalDiscriminator()}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx) }()

	tb.Cleanup(func() {
		cancel()
		if err := recv(tb, runC, "Run to return"); !errors.Is(err, context.Canceled) {
			tb.Errorf("unexpected Run error: %v", err)
		}
	})

	return r
}

// up drives the session to Up: the scripted peer opens the three-way
// handshake from Down, without waiting for the session's own cadence.
func (r *sessionRig) up() {
	r.tb.Helper()

	// First contact: the scripted peer has not learned our discriminator.
	p := r.script.packet(StateDown)
	p.YourDiscriminator = 0
	r.script.write(p)
	r.wantTransition(StateDown, StateInit)

	r.script.write(r.script.packet(StateInit))
	r.wantTransition(StateInit, StateUp)
	recv(r.tb, r.upC, "OnUp")
}

// wantTransition asserts the next recorded state transition.
func (r *sessionRig) wantTransition(from, to State) {
	r.tb.Helper()

	got := recv(r.tb, r.stateC, "a state transition")
	if d := diff(r.tb, stateChange{From: from, To: to}, got); d != "" {
		r.tb.Fatalf("unexpected state transition (-want +got):\n%s", d)
	}
}

// A script is the scripted peer of a session under test: the raw side of
// the in-memory transport, speaking both well-formed and hand-built packets
// to reach paths a correct implementation never produces.
type script struct {
	tb testing.TB
	t  *memTransport

	// discr is the session's discriminator, echoed as Your Discriminator.
	discr uint32
}

// packet returns a well-formed packet from the scripted peer in the given
// state: discriminators filled in, a 300ms cadence, and a detection
// multiplier of 10, so the session's detection time (3s) outlives a test's
// own pauses unless a test shortens it.
func (s *script) packet(state State) *ControlPacket {
	return &ControlPacket{
		State:             state,
		DetectMultiplier:  10,
		MyDiscriminator:   scriptDiscr,
		YourDiscriminator: s.discr,
		DesiredMinTX:      300 * time.Millisecond,
		RequiredMinRX:     300 * time.Millisecond,
	}
}

// write sends a well-formed packet to the session.
func (s *script) write(p *ControlPacket) {
	s.tb.Helper()

	if err := s.t.WritePacket(must(p.AppendBinary(nil))); err != nil {
		s.tb.Fatalf("failed to write packet: %v", err)
	}
}

// writeAuth sends a well-formed packet in the given state carrying auth. An
// opening packet zeroes Your Discriminator, as a peer which has not yet
// learned the session's discriminator does.
func (s *script) writeAuth(state State, auth *AuthSection, open bool) {
	s.tb.Helper()

	p := s.packet(state)
	if open {
		p.YourDiscriminator = 0
	}

	p.Auth = auth
	s.write(p)
}

// writeRaw sends hand-built wire bytes to the session.
func (s *script) writeRaw(b []byte) {
	s.tb.Helper()

	if err := s.t.WritePacket(b); err != nil {
		s.tb.Fatalf("failed to write raw packet: %v", err)
	}
}

// read returns the session's next packet.
func (s *script) read() *ControlPacket {
	s.tb.Helper()

	p, err := ParseControlPacket(recv(s.tb, s.t.in, "a packet from the session"))
	if err != nil {
		s.tb.Fatalf("failed to parse packet: %v", err)
	}

	return p
}

// nextState reads until a packet carrying the given state arrives, skipping
// the periodic transmissions queued before a transition.
func (s *script) nextState(state State) *ControlPacket {
	s.tb.Helper()

	for {
		if p := s.read(); p.State == state {
			return p
		}
	}
}

// testLogger returns the logger for a Session under test: it writes to the
// test log when the -test.v flag is set, and discards everything otherwise.
func testLogger(tb testing.TB) *slog.Logger {
	if !testing.Verbose() {
		return slog.New(slog.DiscardHandler)
	}

	return slog.New(slog.NewTextHandler(tb.Output(), &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// The test log carries its own ordering; slog's timestamps are noise.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}

			return a
		},
	}))
}

// recv receives one value, failing the test if what does not happen within
// the timeout.
func recv[T any](tb testing.TB, ch <-chan T, what string) T {
	tb.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(timeout):
		tb.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// must returns v, panicking on error: for test values which cannot fail to
// construct.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}
