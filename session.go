package bfd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

const (
	// defaultInterval is the DesiredMinTX and RequiredMinRX applied when a
	// Config leaves them zero: a conventional, conservative cadence giving
	// a 900ms detection time with the default multiplier.
	defaultInterval = 300 * time.Millisecond

	// defaultDetectMultiplier is the detection time multiplier applied
	// when a Config leaves it zero.
	defaultDetectMultiplier = 3

	// slowStartTX is the floor RFC 5880, section 6.8.3 sets on
	// DesiredMinTX before a session reaches Up: an unproductive session
	// must not flood its peer.
	slowStartTX = 1 * time.Second
)

// A Transport carries BFD control packets between two systems, one whole
// packet per call in each direction: the seam between a Session and its
// sockets. DialUDP builds the RFC 5881 single-hop UDP transport; callers
// may supply their own, such as an in-memory pair for tests.
//
// ReadPacket blocks until a packet arrives, then fills b with exactly one
// whole packet, never a fragment nor two coalesced. It must be unblocked
// by Close, which is called concurrently with a pending ReadPacket so a
// session can always tear down. WritePacket sends one packet, best effort:
// its failures are logged and dropped. A session learns of transport death
// only through ReadPacket: any read error not wrapping ErrDropped is
// terminal. Neither method may retain b after returning: the session
// reuses its buffers for every packet. One goroutine may call ReadPacket
// while another calls WritePacket. The transport owns everything below the
// packet: addressing, source filtering, and TTL enforcement.
type Transport interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) error
	Close() error
}

// ErrDropped reports a datagram a Transport received and discarded, such
// as one failing the RFC 5881 receive checks. A ReadPacket error wrapping
// ErrDropped is not terminal: the session logs the drop at Debug and
// reads again. ReadPacket still blocks for a datagram before reporting a
// drop, never returning ErrDropped for an empty read; the count returned
// beside it is ignored. Wrap ErrDropped with the reason, as in
// fmt.Errorf("%w: TTL 254", ErrDropped).
var ErrDropped = errors.New("bfd: datagram dropped")

// A Config configures a Session. The zero value is usable: every field has
// a default or is optional. Configuration is immutable once the Session is
// built. A runtime change would require the RFC 5880, section 6.5 poll
// sequence, which this package never initiates. It always answers a peer's
// Poll with Final.
type Config struct {
	// DesiredMinTX is the fastest this system wants to transmit, and
	// RequiredMinRX the fastest it can receive. Each side transmits at
	// the slower of its desire and its peer's requirement, jittered.
	// Intervals are whole microseconds, the wire's precision. The zero
	// value of each is 300ms. Until the session first reaches Up,
	// transmission is clamped to at most one packet per second whatever
	// DesiredMinTX asks (RFC 5880, section 6.8.3).
	DesiredMinTX, RequiredMinRX time.Duration

	// DetectMultiplier is the detection time multiplier, advertised to
	// the peer: the peer declares this system down after DetectMultiplier
	// of this system's transmit intervals pass in silence. This system's
	// own detection time is governed by the peer's multiplier in the same
	// way, not by this field. The zero value is 3.
	DetectMultiplier uint8

	// OnUp, if set, is called on each transition into Up. A session is
	// perpetual, so OnUp fires again after each recovery, signaling that
	// forwarding healed. A session begins Down, so treat the path as
	// down until the first OnUp: OnDown never fires before it.
	//
	// Hooks run on the session goroutine and must return promptly: a
	// stalled hook stalls transmission and detection. A hook which must
	// block, such as an RPC, a session reset, or an unbuffered send,
	// does that work on a new goroutine. s names the session which
	// fired: one hook function may serve many sessions.
	OnUp func(s *Session)

	// OnDown, if set, is called on each fall from Up with the reason:
	// the down signal to feed into the protocol the session protects.
	// Check err first. A non-nil err is a terminal transport failure
	// with DiagNone, and Run is about to return the same error. With a
	// nil err the Diagnostic explains the fall: a wire transition, or
	// DiagAdministrativelyDown when cancellation ends a session that
	// was Up.
	//
	// See OnUp for the hook contract.
	OnDown func(s *Session, d Diagnostic, err error)

	// OnStateChange, if set, observes every state transition, for metrics
	// and diagnostics; session logic belongs on OnUp and OnDown. A
	// transport failure appears here as an ordinary fall to Down, and
	// OnDown carries the attribution. It runs on the session goroutine
	// and must return promptly.
	OnStateChange func(s *Session, from, to State)

	// Logger, if set, records state transitions at Info, and dropped
	// packets and failed writes at Debug; nil discards everything.
	Logger *slog.Logger
}

// A Session runs the RFC 5880 state machine for one peer in asynchronous
// mode: transmitting control packets at the negotiated transmit interval,
// detecting the peer's silence, and reporting Up and Down to the caller's
// hooks. A Session takes only the active role of RFC 5880, section 6.1:
// it transmits from the start rather than waiting to hear its peer first.
// A Session is perpetual: Down is a state it keeps signaling from, not an
// exit. Run returns only when its ctx ends or its Transport fails.
type Session struct {
	t   Transport
	cfg Config
	log *slog.Logger

	// localDiscr identifies this half of the session, picked at random;
	// jitter is a hook for deterministic timing in tests.
	localDiscr uint32
	jitter     func() float64

	started atomic.Bool

	// The RFC 5880, section 6.8.1 state variables, owned by the session
	// goroutine.
	state                  State
	diag                   Diagnostic
	remoteDiscr            uint32
	remoteMinRX            time.Duration
	remoteDesiredTX        time.Duration
	remoteDetectMultiplier uint8

	// wb is the reused transmit marshal buffer.
	wb []byte
}

// NewSession validates the configuration and produces a Session over t in
// the Down state. Nothing runs until Run. Ownership of t passes only then:
// a caller which never reaches Run closes t itself.
func NewSession(t Transport, c Config) (*Session, error) {
	if c.DesiredMinTX == 0 {
		c.DesiredMinTX = defaultInterval
	}

	if c.RequiredMinRX == 0 {
		c.RequiredMinRX = defaultInterval
	}

	if c.DetectMultiplier == 0 {
		c.DetectMultiplier = defaultDetectMultiplier
	}

	for _, d := range []time.Duration{c.DesiredMinTX, c.RequiredMinRX} {
		if d < time.Microsecond || d/time.Microsecond > math.MaxUint32 {
			return nil, fmt.Errorf("bfd: intervals must fit the wire's 32 bit whole microseconds: %s", d)
		}
	}

	c.DesiredMinTX = c.DesiredMinTX.Truncate(time.Microsecond)
	c.RequiredMinRX = c.RequiredMinRX.Truncate(time.Microsecond)

	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	var discr uint32
	for discr == 0 {
		discr = rand.Uint32()
	}

	return &Session{
		t:          t,
		cfg:        c,
		log:        log.With("local_discr", discr),
		localDiscr: discr,
		jitter:     rand.Float64,
		state:      StateDown,

		// RFC 5880, section 6.8.1 initial values: the peer's receive
		// requirement is 1µs until its first packet says otherwise.
		remoteMinRX: time.Microsecond,
	}, nil
}

// LocalDiscriminator returns the discriminator identifying this half of
// the session, picked at NewSession and immutable. The peer echoes it as
// Your Discriminator once learned. A caller-built demultiplexing
// Transport routes a packet by its nonzero Your Discriminator. A first
// contact carries zero there and is routed by source address instead.
func (s *Session) LocalDiscriminator() uint32 { return s.localDiscr }

// Run runs the session until ctx ends: the perpetual RFC 5880 machine,
// through however many Up and Down transitions the path produces. On
// cancellation it fires the hooks for the transition to AdminDown,
// transmits an AdminDown farewell so the peer learns this was deliberate,
// and returns ctx's error. A Transport read failure also ends Run with its
// error, since BFD cannot run without its packets. Run never returns nil.
// A non-nil ctx.Err() after Run marks a clean shutdown, even for a
// Transport failure which raced the cancellation. A return with ctx still
// live is a Transport failure.
//
// Every exit closes the Transport as Run returns and never sooner. A
// redial of the same addresses waits for that return, and every hook has
// fired by then: nothing retries, so a caller wanting the session back
// redials and runs a fresh one. Run's error is the only end-of-session
// signal: a goroutine which discards it leaves nothing watching the
// session.
//
// Run may be called once per Session. A second call returns an error and
// touches nothing: the first call owns the Transport.
func (s *Session) Run(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("bfd: session is already running or has run")
	}

	// The reader goroutine forwards parsed packets; canceling ctx abandons
	// it, and closing the transport unblocks its read. The context is
	// rederived so every exit path stops the reader, not only the caller's
	// own cancellation; errC is buffered so a failing reader never blocks
	// against a session mid-teardown.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	packetC := make(chan *ControlPacket)
	errC := make(chan error, 1)
	go s.read(ctx, packetC, errC)

	txT := time.NewTimer(s.txInterval())
	defer txT.Stop()
	detectT := time.NewTimer(time.Hour)
	detectT.Stop()
	defer detectT.Stop()

	s.log.Info("session running", "state", s.state)
	for {
		select {
		case <-ctx.Done():
			// Cancellation is a Down like any other to the protected
			// protocol: the transition fires the hooks, OnDown included
			// when the session falls from Up. Then the farewell, best
			// effort, like a BGP Cease before close.
			s.transition(StateAdminDown, DiagAdministrativelyDown, nil)
			s.transmit(false)
			_ = s.t.Close()
			return ctx.Err()

		case err := <-errC:
			// A dead transport fells the session too: no wire transition
			// explains it, so the diagnostic is DiagNone and err carries
			// the reason into OnDown.
			err = fmt.Errorf("bfd: transport read failed: %w", err)
			s.transition(StateDown, DiagNone, err)
			_ = s.t.Close()
			return err

		case <-txT.C:
			// Periodic transmission, suppressed only when the peer
			// advertised a zero receive interval (RFC 5880, section
			// 6.8.7).
			if s.remoteMinRX != 0 {
				s.transmit(false)
			}

			txT.Reset(s.txInterval())

		case <-detectT.C:
			// The peer went silent for a full detection time.
			s.log.Info("detection time expired")
			s.transition(StateDown, DiagControlDetectionTimeExpired, nil)

		case p := <-packetC:
			s.receive(p, detectT)
		}
	}
}

// read is the reader goroutine: it parses each packet the transport
// delivers and forwards it to the session goroutine until ctx ends. A
// malformed packet is dropped, as RFC 5880, section 6.8.6 discards demand,
// and a read error wrapping ErrDropped records a datagram the transport
// discarded; any other read error is terminal for the session.
func (s *Session) read(ctx context.Context, packetC chan<- *ControlPacket, errC chan<- error) {
	// Larger than any valid packet, so an oversized datagram is read
	// whole and rejected by parse rather than silently truncated.
	buf := make([]byte, 4096)
	for {
		n, err := s.t.ReadPacket(buf)
		if err != nil {
			if errors.Is(err, ErrDropped) {
				s.log.Debug("dropped datagram", "err", err)
				continue
			}

			select {
			case errC <- err:
			case <-ctx.Done():
			}

			return
		}

		p, err := ParseControlPacket(buf[:n])
		if err != nil {
			s.log.Debug("dropped packet", "err", err)
			continue
		}

		select {
		case packetC <- p:
		case <-ctx.Done():
			return
		}
	}
}

// receive applies one valid packet to the state machine: RFC 5880, section
// 6.8.6.
func (s *Session) receive(p *ControlPacket, detectT *time.Timer) {
	// A nonzero Your Discriminator must name this session; zero is a peer
	// which has not learned it yet, which parse permits only in its Down
	// states.
	if p.YourDiscriminator != 0 && p.YourDiscriminator != s.localDiscr {
		s.log.Debug("dropped packet: unknown discriminator", "your_discr", p.YourDiscriminator)
		return
	}

	s.remoteDiscr = p.MyDiscriminator
	s.remoteMinRX = p.RequiredMinRX
	s.remoteDesiredTX = p.DesiredMinTX
	s.remoteDetectMultiplier = p.DetectMultiplier

	// A Poll is answered immediately with Final, outside the periodic
	// cadence (RFC 5880, section 6.8.7).
	if p.Poll {
		s.transmit(true)
	}

	switch {
	case p.State == StateAdminDown:
		if s.state != StateDown {
			s.transition(StateDown, DiagNeighborSignaledSessionDown, nil)
		}
	case s.state == StateDown && p.State == StateDown:
		s.transition(StateInit, s.diag, nil)
	case s.state == StateDown && p.State == StateInit:
		s.transition(StateUp, s.diag, nil)
	case s.state == StateInit && (p.State == StateInit || p.State == StateUp):
		s.transition(StateUp, s.diag, nil)
	case s.state == StateUp && p.State == StateDown:
		s.transition(StateDown, DiagNeighborSignaledSessionDown, nil)
	}

	// Periodic packets are expected only out of Down: each one restarts
	// the detection timer at the current detection time (RFC 5880,
	// section 6.8.4).
	if s.state == StateInit || s.state == StateUp {
		detectT.Reset(time.Duration(s.remoteDetectMultiplier) * max(s.cfg.RequiredMinRX, s.remoteDesiredTX))
	} else {
		detectT.Stop()
	}
}

// transition moves the state machine to a new state, firing the caller's
// hooks: OnStateChange always, OnUp entering Up, OnDown leaving it. err is
// non-nil only for the terminal transport failure, where it carries the
// reason no Diagnostic can.
func (s *Session) transition(to State, d Diagnostic, err error) {
	if to == s.state {
		return
	}

	from := s.state
	s.state, s.diag = to, d
	s.log.Info("state transition", "from", from, "to", to, "diagnostic", d)
	if h := s.cfg.OnStateChange; h != nil {
		h(s, from, to)
	}

	if from == StateUp {
		if h := s.cfg.OnDown; h != nil {
			h(s, d, err)
		}
	}

	if to == StateUp {
		if h := s.cfg.OnUp; h != nil {
			h(s)
		}
	}
}

// transmit sends one control packet reflecting the current state, with
// Final set when answering a Poll. Write failures are logged and dropped:
// BFD is lossy by design, and a dead transport surfaces through the reader.
func (s *Session) transmit(final bool) {
	p := &ControlPacket{
		Diagnostic:        s.diag,
		State:             s.state,
		Final:             final,
		DetectMultiplier:  s.cfg.DetectMultiplier,
		MyDiscriminator:   s.localDiscr,
		YourDiscriminator: s.remoteDiscr,
		DesiredMinTX:      s.desiredMinTX(),
		RequiredMinRX:     s.cfg.RequiredMinRX,
	}

	b, err := p.AppendBinary(s.wb[:0])
	if err != nil {
		s.log.Debug("failed to marshal packet", "err", err)
		return
	}

	s.wb = b
	if err := s.t.WritePacket(b); err != nil {
		s.log.Debug("failed to write packet", "err", err)
	}
}

// desiredMinTX is the transmit desire currently advertised and used: the
// configured value, clamped to slowStartTX until the session is Up (RFC
// 5880, section 6.8.3).
func (s *Session) desiredMinTX() time.Duration {
	if s.state != StateUp {
		return max(s.cfg.DesiredMinTX, slowStartTX)
	}

	return s.cfg.DesiredMinTX
}

// txInterval is the jittered pause before the next periodic transmission:
// the slower of this side's desire and the peer's requirement, scaled to
// 75-100% so peers do not synchronize, and to 75-90% when a single packet
// is the whole detection budget (RFC 5880, section 6.8.7).
func (s *Session) txInterval() time.Duration {
	iv := max(s.desiredMinTX(), s.remoteMinRX)
	span := 0.25
	if s.cfg.DetectMultiplier == 1 {
		span = 0.15
	}

	return time.Duration(float64(iv) * (0.75 + span*s.jitter()))
}
