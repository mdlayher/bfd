package bfd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewSessionDefaults(t *testing.T) {
	t.Parallel()

	tr, _ := memTransports()
	s := must(NewSession(tr, Config{}))

	if s.cfg.DesiredMinTX != defaultInterval {
		t.Fatalf("unexpected DesiredMinTX: got %s, want %s", s.cfg.DesiredMinTX, defaultInterval)
	}

	if s.cfg.RequiredMinRX != defaultInterval {
		t.Fatalf("unexpected RequiredMinRX: got %s, want %s", s.cfg.RequiredMinRX, defaultInterval)
	}

	if s.cfg.DetectMultiplier != defaultDetectMultiplier {
		t.Fatalf("unexpected DetectMultiplier: got %d, want %d", s.cfg.DetectMultiplier, defaultDetectMultiplier)
	}

	if s.LocalDiscriminator() == 0 {
		t.Fatal("local discriminator must be nonzero")
	}

	if s.state != StateDown {
		t.Fatalf("unexpected initial state: %s", s.state)
	}

	// The RFC 5880, section 6.8.1 initial value for the peer's requirement.
	if s.remoteMinRX != time.Microsecond {
		t.Fatalf("unexpected initial remote RequiredMinRX: %s", s.remoteMinRX)
	}

	// Sub-microsecond precision cannot reach the wire and is truncated.
	s = must(NewSession(tr, Config{
		DesiredMinTX:  300*time.Millisecond + 500*time.Nanosecond,
		RequiredMinRX: 100*time.Millisecond + 999*time.Nanosecond,
	}))

	if s.cfg.DesiredMinTX != 300*time.Millisecond {
		t.Fatalf("DesiredMinTX was not truncated: %s", s.cfg.DesiredMinTX)
	}

	if s.cfg.RequiredMinRX != 100*time.Millisecond {
		t.Fatalf("RequiredMinRX was not truncated: %s", s.cfg.RequiredMinRX)
	}
}

func TestNewSessionErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "sub-microsecond desired",
			cfg:  Config{DesiredMinTX: 500 * time.Nanosecond},
		},
		{
			name: "sub-microsecond required",
			cfg:  Config{RequiredMinRX: 500 * time.Nanosecond},
		},
		{
			name: "negative desired",
			cfg:  Config{DesiredMinTX: -time.Second},
		},
		{
			name: "oversized desired",
			cfg:  Config{DesiredMinTX: (math.MaxUint32 + 1) * time.Microsecond},
		},
		{
			name: "oversized required",
			cfg:  Config{RequiredMinRX: (math.MaxUint32 + 1) * time.Microsecond},
		},
		{
			name: "auth unsupported type",
			cfg:  Config{Auth: &AuthConfig{Type: AuthTypeKeyedSHA1, Key: []byte("secret")}},
		},
		{
			name: "auth empty key",
			cfg:  Config{Auth: &AuthConfig{Type: AuthTypeSimplePassword}},
		},
		{
			name: "auth oversize key",
			cfg:  Config{Auth: &AuthConfig{Type: AuthTypeSimplePassword, Key: bytes.Repeat([]byte{'a'}, 17)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr, _ := memTransports()
			s, err := NewSession(tr, tt.cfg)
			if err == nil {
				t.Fatalf("expected an error, but got a session: %+v", s)
			}
		})
	}
}

func TestSessionRunTwice(t *testing.T) {
	t.Parallel()

	tr, _ := memTransports()
	s := must(NewSession(tr, Config{Logger: testLogger(t)}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected first Run error: %v", err)
	}

	if err := s.Run(ctx); err == nil {
		t.Fatal("expected an error from the second Run, but none occurred")
	}
}

// TestSessionUp drives the RFC 5880 three-way handshake and verifies every
// field of the packets the session transmits on the way: the slow-start
// cadence and unknown peer before Up, and the negotiated values after.
func TestSessionUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		// The session's first packet, one slow-start interval in: nothing is
		// known about the peer yet. With jitter pinned at one, the interval
		// is exactly the RFC 5880, section 6.8.3 clamp.
		start := time.Now()
		want := &ControlPacket{
			State:            StateDown,
			DetectMultiplier: defaultDetectMultiplier,
			MyDiscriminator:  r.script.discr,
			DesiredMinTX:     slowStartTX,
			RequiredMinRX:    defaultInterval,
		}

		if d := diff(t, want, r.script.read()); d != "" {
			t.Fatalf("unexpected first packet (-want +got):\n%s", d)
		}

		if elapsed := time.Since(start); elapsed != slowStartTX {
			t.Fatalf("first packet after %s, want %s", elapsed, slowStartTX)
		}

		r.up()

		// After Up: the peer's discriminator is echoed, and the configured
		// transmit desire replaces the slow-start clamp.
		want = &ControlPacket{
			State:             StateUp,
			DetectMultiplier:  defaultDetectMultiplier,
			MyDiscriminator:   r.script.discr,
			YourDiscriminator: scriptDiscr,
			DesiredMinTX:      defaultInterval,
			RequiredMinRX:     defaultInterval,
		}

		if d := diff(t, want, r.script.nextState(StateUp)); d != "" {
			t.Fatalf("unexpected Up packet (-want +got):\n%s", d)
		}
	})
}

// TestSessionUpFromInit verifies the short handshake: a peer which already
// saw our packets opens with Init, and Down moves straight to Up.
func TestSessionUpFromInit(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		r.script.write(r.script.packet(StateInit))
		r.wantTransition(StateDown, StateUp)
		recv(t, r.upC, "OnUp")
	})
}

// TestSessionAuthSimplePassword verifies an authenticated handshake: the
// session stamps every packet with the Simple Password section, and an
// authenticated peer reaches Up.
func TestSessionAuthSimplePassword(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		key := []byte("hunter2")
		r := newSessionRig(t, Config{
			Auth: &AuthConfig{Type: AuthTypeSimplePassword, KeyID: 3, Key: key},
		})

		// The session's own packets carry the configured password.
		first := r.script.read()
		want := &AuthSection{Type: AuthTypeSimplePassword, KeyID: 3, Data: key}
		if d := diff(t, want, first.Auth); d != "" {
			t.Fatalf("unexpected auth section (-want +got):\n%s", d)
		}

		// The scripted peer authenticates, and the handshake completes.
		r.script.writeAuth(StateDown, want, true)
		r.wantTransition(StateDown, StateInit)

		r.script.writeAuth(StateInit, want, false)
		r.wantTransition(StateInit, StateUp)
		recv(t, r.upC, "OnUp")
	})
}

// TestSessionAuthRejected verifies the RFC 5880, section 6.8.6 policy: a
// configured session discards a packet with the wrong password and one with
// no Authentication Section at all, without touching the state machine.
func TestSessionAuthRejected(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{
			Auth: &AuthConfig{Type: AuthTypeSimplePassword, KeyID: 1, Key: []byte("correct")},
		})

		// Wrong password: discarded.
		r.script.writeAuth(StateDown, &AuthSection{
			Type: AuthTypeSimplePassword, KeyID: 1, Data: []byte("wrong"),
		}, true)

		// No section on a session that requires one: discarded.
		open := r.script.packet(StateDown)
		open.YourDiscriminator = 0
		r.script.write(open)

		// Neither packet moved the machine off Down.
		synctest.Wait()
		select {
		case sc := <-r.stateC:
			t.Fatalf("unexpected transition on unauthenticated packets: %+v", sc)
		default:
		}
	})
}

// TestSessionDetectMultiplierOneInterval verifies the tightened jitter of
// RFC 5880, section 6.8.7: with a detection multiplier of one, a single
// packet is the whole detection budget, so the transmit interval is scaled
// to 75-90% rather than 75-100%. Jitter is pinned at one, so the first
// packet lands at exactly 90% of the slow-start interval.
func TestSessionDetectMultiplierOneInterval(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{DetectMultiplier: 1})

		start := time.Now()
		if p := r.script.read(); p.DetectMultiplier != 1 {
			t.Fatalf("unexpected DetectMultiplier: %d", p.DetectMultiplier)
		}

		if elapsed, want := time.Since(start), 900*time.Millisecond; elapsed != want {
			t.Fatalf("first packet after %s, want %s", elapsed, want)
		}
	})
}

// TestSessionPollFinal verifies that a Poll is answered immediately with
// Final, outside the periodic cadence, and that the answer is the last step
// of reception (RFC 5880, section 6.8.6): the Final reflects the state
// change the same packet caused.
func TestSessionPollFinal(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		p := r.script.packet(StateDown)
		p.YourDiscriminator = 0
		p.Poll = true
		r.script.write(p)
		r.wantTransition(StateDown, StateInit)

		want := &ControlPacket{
			// The answer reflects the transition the same packet caused,
			// and already echoes the just-learned peer.
			State:             StateInit,
			Final:             true,
			DetectMultiplier:  defaultDetectMultiplier,
			MyDiscriminator:   r.script.discr,
			YourDiscriminator: scriptDiscr,
			DesiredMinTX:      slowStartTX,
			RequiredMinRX:     defaultInterval,
		}

		if d := diff(t, want, r.script.read()); d != "" {
			t.Fatalf("unexpected Final packet (-want +got):\n%s", d)
		}
	})
}

// TestSessionDetectionTimeExpired verifies detection: a silent peer is
// declared down after exactly the peer's detection multiplier times the
// agreed interval, and the session is perpetual: the peer returning brings
// it Up again.
func TestSessionDetectionTimeExpired(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})
		r.up()

		// The scripted peer goes silent: its packets advertised a
		// multiplier of 10 and a 300ms cadence, so detection fires after
		// exactly 3s.
		start := time.Now()
		if d := recv(t, r.downC, "OnDown"); d.Diag != DiagControlDetectionTimeExpired || d.Err != nil {
			t.Fatalf("unexpected OnDown: %+v", d)
		}

		if elapsed := time.Since(start); elapsed != 3*time.Second {
			t.Fatalf("detection fired after %s, want 3s", elapsed)
		}

		r.wantTransition(StateUp, StateDown)

		// Subsequent transmissions tell the peer why the session fell.
		if p := r.script.nextState(StateDown); p.Diagnostic != DiagControlDetectionTimeExpired {
			t.Fatalf("unexpected diagnostic on the wire: %s", p.Diagnostic)
		}

		// The peer returns: a second complete handshake, a second OnUp.
		r.script.write(r.script.packet(StateDown))
		r.wantTransition(StateDown, StateInit)
		r.script.write(r.script.packet(StateInit))
		r.wantTransition(StateInit, StateUp)
		recv(t, r.upC, "a second OnUp")
	})
}

// TestSessionNeighborSignaledDown verifies the transitions out of Up on the
// peer's word: both Down and AdminDown fell the session with the neighbor
// diagnostic.
func TestSessionNeighborSignaledDown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
	}{
		{name: "down", state: StateDown},
		{name: "admin down", state: StateAdminDown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newSessionRig(t, Config{})
				r.up()

				r.script.write(r.script.packet(tt.state))
				r.wantTransition(StateUp, StateDown)
				if d := recv(t, r.downC, "OnDown"); d.Diag != DiagNeighborSignaledSessionDown || d.Err != nil {
					t.Fatalf("unexpected OnDown: %+v", d)
				}
			})
		})
	}
}

// TestSessionIgnoresUnknownDiscriminator verifies demultiplexing: a packet
// naming a discriminator other than the session's is dropped without a
// state change.
func TestSessionIgnoresUnknownDiscriminator(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		p := r.script.packet(StateDown)
		p.YourDiscriminator = 0
		r.script.write(p)
		r.wantTransition(StateDown, StateInit)

		// A packet for some other session: were it accepted, Init and Init
		// would produce Up.
		bad := r.script.packet(StateInit)
		bad.YourDiscriminator = r.script.discr + 1
		if bad.YourDiscriminator == 0 {
			bad.YourDiscriminator = 1
		}

		r.script.write(bad)

		synctest.Wait()
		select {
		case sc := <-r.stateC:
			t.Fatalf("unexpected state transition: %s -> %s", sc.From, sc.To)
		default:
		}

		// The genuine article still works.
		r.script.write(r.script.packet(StateInit))
		r.wantTransition(StateInit, StateUp)
	})
}

// TestSessionDropsMalformedPackets verifies that undecodable datagrams are
// discarded without harming the session.
func TestSessionDropsMalformedPackets(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		// Truncated garbage, then a full-length packet with a bad version.
		r.script.writeRaw([]byte{0xde, 0xad})
		b := must(validPacket().AppendBinary(nil))
		b[0] &^= 0xe0
		r.script.writeRaw(b)

		p := r.script.packet(StateDown)
		p.YourDiscriminator = 0
		r.script.write(p)
		r.wantTransition(StateDown, StateInit)
	})
}

// TestSessionTransportDrops verifies ErrDropped: a read error wrapping it
// records a datagram the transport discarded, and the session reads on,
// unharmed.
func TestSessionTransportDrops(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		// The transport reports a drop; a full handshake still succeeds
		// around it, and the rig's cleanup verifies a clean shutdown.
		r.local.failRead(fmt.Errorf("%w: TTL 254", ErrDropped))
		r.up()
	})
}

// TestSessionSuppressedTransmission verifies RFC 5880, section 6.8.7: a peer
// advertising a zero RequiredMinRX silences the periodic cadence, a Poll is
// still answered, and a nonzero advertisement lifts the suppression.
func TestSessionSuppressedTransmission(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})

		p := r.script.packet(StateDown)
		p.YourDiscriminator = 0
		p.RequiredMinRX = 0
		r.script.write(p)
		r.wantTransition(StateDown, StateInit)

		// Two slow-start intervals pass without a packet on the wire.
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()
		select {
		case <-r.script.t.in:
			t.Fatal("the session transmitted while suppressed")
		default:
		}

		// A Poll cuts through the suppression.
		p = r.script.packet(StateInit)
		p.Poll = true
		p.RequiredMinRX = 0
		r.script.write(p)
		if got := r.script.read(); !got.Final {
			t.Fatalf("expected a Final answer, but got: %+v", got)
		}

		r.wantTransition(StateInit, StateUp)

		// A nonzero requirement restores the periodic cadence.
		r.script.write(r.script.packet(StateUp))
		if got := r.script.nextState(StateUp); got.Final {
			t.Fatalf("expected a periodic packet, but got: %+v", got)
		}
	})
}

// TestSessionSlowStart verifies RFC 5880, section 6.8.3: until the session
// first reaches Up, the advertised transmit desire is clamped to one packet
// per second, however fast the configuration asks to go.
func TestSessionSlowStart(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{
			DesiredMinTX:  50 * time.Millisecond,
			RequiredMinRX: 50 * time.Millisecond,
		})

		first := r.script.read()
		if first.DesiredMinTX != slowStartTX {
			t.Fatalf("unexpected pre-Up DesiredMinTX: got %s, want %s", first.DesiredMinTX, slowStartTX)
		}

		if first.RequiredMinRX != 50*time.Millisecond {
			t.Fatalf("unexpected RequiredMinRX: %s", first.RequiredMinRX)
		}

		r.up()

		if p := r.script.nextState(StateUp); p.DesiredMinTX != 50*time.Millisecond {
			t.Fatalf("unexpected Up DesiredMinTX: got %s, want 50ms", p.DesiredMinTX)
		}
	})
}

// TestSessionTransmitSpeedup verifies that a shrunken transmit interval
// takes effect on the very next transmission. Reaching Up lifts the
// slow-start clamp, and a peer may lower its receive requirement at any
// time; a transmit timer still armed with the old spacing leaves one
// stale gap that can outlast the peer's now-faster detection time. A live
// FRR peer caught the stale gap as a single flap right after reaching Up.
func TestSessionTransmitSpeedup(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{DesiredMinTX: 50 * time.Millisecond})

		// The handshake completes well inside the initial one second
		// slow-start arm, learning the peer's 300ms requirement.
		r.up()

		// The first periodic Up packet arrives at the negotiated 300ms
		// spacing. The stale arm would hold it until one second: past the
		// 900ms detection time a peer computes from these intervals.
		start := time.Now()
		r.script.nextState(StateUp)
		if got, want := time.Since(start), 300*time.Millisecond; got != want {
			t.Fatalf("unexpected first Up transmit delay: got %s, want %s", got, want)
		}

		// The peer lowers its receive requirement below our desire; the
		// next packet honors the faster spacing immediately too.
		start = time.Now()
		p := r.script.packet(StateUp)
		p.RequiredMinRX = 50 * time.Millisecond
		r.script.write(p)

		r.script.read()
		if got, want := time.Since(start), 50*time.Millisecond; got != want {
			t.Fatalf("unexpected lowered transmit delay: got %s, want %s", got, want)
		}
	})
}

// TestSessionCancelFarewell verifies teardown from Up: cancellation is a
// Down like any other, firing OnDown with the administrative diagnostic,
// and transmits an AdminDown farewell so the peer learns this was
// deliberate.
func TestSessionCancelFarewell(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})
		r.up()
		r.cancel()

		if d := recv(t, r.downC, "OnDown"); d.Diag != DiagAdministrativelyDown || d.Err != nil {
			t.Fatalf("unexpected OnDown: %+v", d)
		}

		want := &ControlPacket{
			Diagnostic:        DiagAdministrativelyDown,
			State:             StateAdminDown,
			DetectMultiplier:  defaultDetectMultiplier,
			MyDiscriminator:   r.script.discr,
			YourDiscriminator: scriptDiscr,
			// AdminDown is not Up: the slow-start clamp reapplies.
			DesiredMinTX:  slowStartTX,
			RequiredMinRX: defaultInterval,
		}

		if d := diff(t, want, r.script.nextState(StateAdminDown)); d != "" {
			t.Fatalf("unexpected farewell (-want +got):\n%s", d)
		}

		r.wantTransition(StateUp, StateAdminDown)
	})
}

// TestSessionCancelBeforeUp verifies the boundary of the cancellation Down:
// a session which never reached Up did not fall from it, so OnDown stays
// silent while the farewell and OnStateChange still happen.
func TestSessionCancelBeforeUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newSessionRig(t, Config{})
		r.cancel()

		r.wantTransition(StateDown, StateAdminDown)
		if p := r.script.nextState(StateAdminDown); p.Diagnostic != DiagAdministrativelyDown {
			t.Fatalf("unexpected farewell diagnostic: %s", p.Diagnostic)
		}

		synctest.Wait()
		select {
		case d := <-r.downC:
			t.Fatalf("OnDown fired for a session which never reached Up: %+v", d)
		default:
		}
	})
}

func TestSessionTransportReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("it broke")
	s := must(NewSession(errTransport{err: readErr}, Config{
		Logger: testLogger(t),
	}))

	// The session never reached Up, so Run's return is the whole report.
	if err := s.Run(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("expected the transport's read error, but got: %v", err)
	}
}

// TestSessionTransportFailWhileUp verifies the transport dying mid-session:
// the one fall from Up no wire transition explains, so OnDown fires with
// DiagNone and the error, and Run returns the same failure.
func TestSessionTransportFailWhileUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		local, remote := memTransports()

		var (
			upC   = make(chan struct{}, 1)
			downC = make(chan down, 1)
		)

		s := must(NewSession(local, Config{
			OnUp:   func(*Session) { upC <- struct{}{} },
			OnDown: func(_ *Session, d Diagnostic, err error) { downC <- down{Diag: d, Err: err} },
			Logger: testLogger(t),
		}))
		s.jitter = func() float64 { return 1 }

		runC := make(chan error, 1)
		go func() { runC <- s.Run(context.Background()) }()

		script := &script{tb: t, t: remote, discr: s.LocalDiscriminator()}

		p := script.packet(StateDown)
		p.YourDiscriminator = 0
		script.write(p)
		script.write(script.packet(StateInit))
		recv(t, upC, "OnUp")

		readErr := errors.New("it broke")
		local.failRead(readErr)

		if err := recv(t, runC, "Run to return"); !errors.Is(err, readErr) {
			t.Fatalf("expected the transport's read error, but got: %v", err)
		}

		if d := recv(t, downC, "OnDown"); d.Diag != DiagNone || !errors.Is(d.Err, readErr) {
			t.Fatalf("unexpected OnDown: %+v", d)
		}
	})
}

// TestSessionPair runs two real sessions against each other over the
// in-memory pipe: both reach Up, and one side's cancellation farewell fells
// the other with the neighbor diagnostic.
func TestSessionPair(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		type end struct {
			cancel context.CancelFunc
			upC    chan struct{}
			downC  chan Diagnostic
			runC   chan error
		}

		at, bt := memTransports()
		start := func(tr Transport) *end {
			e := &end{
				upC:   make(chan struct{}, 4),
				downC: make(chan Diagnostic, 4),
				runC:  make(chan error, 1),
			}

			s := must(NewSession(tr, Config{
				OnUp:   func(*Session) { e.upC <- struct{}{} },
				OnDown: func(_ *Session, d Diagnostic, _ error) { e.downC <- d },
				Logger: testLogger(t),
			}))
			s.jitter = func() float64 { return 1 }

			ctx, cancel := context.WithCancel(context.Background())
			e.cancel = cancel
			go func() { e.runC <- s.Run(ctx) }()

			return e
		}

		a, b := start(at), start(bt)
		recv(t, a.upC, "session A to reach Up")
		recv(t, b.upC, "session B to reach Up")

		a.cancel()
		if err := recv(t, a.runC, "session A to return"); !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected session A Run error: %v", err)
		}

		// A's own cancellation is a Down to A as well, administrative.
		if d := recv(t, a.downC, "session A OnDown"); d != DiagAdministrativelyDown {
			t.Fatalf("unexpected session A diagnostic: %s", d)
		}

		// A's farewell reaches B as AdminDown: neighbor signaled, not
		// detection.
		if d := recv(t, b.downC, "session B OnDown"); d != DiagNeighborSignaledSessionDown {
			t.Fatalf("unexpected session B diagnostic: %s", d)
		}

		b.cancel()
		if err := recv(t, b.runC, "session B to return"); !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected session B Run error: %v", err)
		}
	})
}

// An errTransport fails every read with a fixed error: the terminal
// transport failure path.
type errTransport struct {
	err error
}

func (t errTransport) ReadPacket([]byte) (int, error) { return 0, t.err }
func (errTransport) WritePacket([]byte) error         { return nil }
func (errTransport) Close() error                     { return nil }
