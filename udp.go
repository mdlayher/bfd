package bfd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Source ports for single-hop BFD control packets, per RFC 5881, section 4.
const (
	sourcePortMin = 49152
	sourcePortMax = 65535
)

// queueDepth is how many routed datagrams a Listener holds for one session
// which has not read them yet. The listener never blocks on a session: one
// slow reader would stall every other session behind it, so a full queue
// drops instead, which the detection timer already covers. A session
// reading its transport promptly never reaches the depth.
const queueDepth = 16

// A ListenConfig configures a Listener. The zero value is usable: every
// field is optional.
type ListenConfig struct {
	// Logger, if set, records the datagrams the listener itself drops at
	// Debug, those routing to no session and those a session's queue had
	// no room for; nil discards everything. A datagram which reaches a
	// session is recorded by that session's own Logger instead, through
	// ErrDropped.
	Logger *slog.Logger
}

// ListenUDP binds the single-hop receiving socket of RFC 5881 to local on
// Port and returns the Listener which shares it, one session per peer
// dialed on it. local must be a unicast address. A link-local local keeps
// its zone, which every peer dialed on the listener must then carry.
//
// Use ListenUDP wherever one local address faces more than one neighbor,
// such as two routers on a LAN or a broadcast circuit with many. DialUDP
// claims the address's Port outright and serves the one session on it.
func ListenUDP(local netip.Addr, c ListenConfig) (*Listener, error) {
	local = local.Unmap()
	if !local.IsValid() {
		return nil, errors.New("bfd: a local address is required")
	}

	if err := checkUnicast(local); err != nil {
		return nil, err
	}

	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	rx, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, Port)))
	if err != nil {
		return nil, fmt.Errorf("bfd: failed to bind receive socket: %w", err)
	}

	l := &Listener{
		local:  local,
		log:    log.With("local", local),
		rx:     rx,
		done:   make(chan struct{}),
		peers:  make(map[netip.Addr]*listenerTransport),
		discrs: make(map[uint32]*listenerTransport),
	}

	if local.Is4() {
		// Reads go through the packet connection so each datagram carries
		// its TTL; the per-peer transmit sockets set the maximum on the
		// way out.
		p := ipv4.NewPacketConn(rx)
		if err := p.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			_ = rx.Close()
			return nil, fmt.Errorf("bfd: failed to request TTLs: %w", err)
		}

		l.read = func(b []byte) (int, net.Addr, int, error) {
			n, cm, src, err := p.ReadFrom(b)
			ttl := -1
			if cm != nil {
				ttl = cm.TTL
			}

			return n, src, ttl, err
		}
	} else {
		p := ipv6.NewPacketConn(rx)
		if err := p.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			_ = rx.Close()
			return nil, fmt.Errorf("bfd: failed to request hop limits: %w", err)
		}

		l.read = func(b []byte) (int, net.Addr, int, error) {
			n, cm, src, err := p.ReadFrom(b)
			hl := -1
			if cm != nil {
				hl = cm.HopLimit
			}

			return n, src, hl, err
		}
	}

	l.wg.Add(1)
	go l.serve()

	return l, nil
}

// A Listener shares one local address among many single-hop BFD sessions.
// It owns the single receiving socket bound to that address and routes
// each datagram to the Transport of the session it belongs to, so the
// sessions need no shared state and no awareness of one another.
//
// Routing follows the two rules the RFCs give. A nonzero Your
// Discriminator names one session and selects it (RFC 5880, section
// 6.8.6). A zero Your Discriminator is a peer which has not learned the
// session's discriminator yet, so the source address selects instead,
// which with the listener's local address is the address pair of RFC 5883,
// section 4.1. A datagram matching neither rule is the listener's to drop:
// no session hears of it, and ListenConfig's Logger records it.
//
// A Listener learns each session's discriminator from the session itself.
// My Discriminator is fixed for a session's life and sits in every packet
// it writes, so the first write through a per-peer Transport registers it
// and no caller registers anything.
//
// A Listener is safe for concurrent use.
type Listener struct {
	local netip.Addr
	log   *slog.Logger

	// rx is the shared receiving socket, and read takes one datagram from
	// it with the source address and TTL or hop limit the RFC 5881,
	// section 5 checks need.
	rx   *net.UDPConn
	read func(b []byte) (int, net.Addr, int, error)

	// done is closed when the read goroutine exits, with readErr holding
	// the error which ended it: the terminal error every open transport
	// then reports, so every session over this listener returns. wg joins
	// that goroutine, which done alone cannot: closing a channel is a
	// signal, not a return.
	done    chan struct{}
	readErr error
	wg      sync.WaitGroup

	// closeOnce guards the one-time teardown, whose result closeErr every
	// caller of Close reports.
	closeOnce sync.Once
	closeErr  error

	// mu guards the routing tables and the listener's own closed state.
	// peers keys the transports by peer address and discrs by the local
	// discriminator each session's first write reveals.
	mu     sync.Mutex
	closed bool
	peers  map[netip.Addr]*listenerTransport
	discrs map[uint32]*listenerTransport

	// sole is the one transport of a listener dialed for one session,
	// which DialUDP is, and nil on a listener shared among many. Every
	// datagram matching neither table falls to it, so an unwanted one is
	// judged by that session's own RFC 5881, section 5 checks and reported
	// as ErrDropped, which is how an operator sees a peer configured with
	// the wrong local address. A shared listener has no such session to
	// blame a stray datagram on, so it drops the datagram itself.
	sole *listenerTransport
}

// Dial produces the Transport for the session between the listener's local
// address and peer: a transmitting socket connected to peer on Port from a
// source port in [49152, 65535], receiving the datagrams the listener
// routes to it. peer must be a unicast address sharing the local address's
// family and zone.
//
// One transport exists per peer: a second Dial of the same peer fails
// until the first transport is closed, and a Dial after the listener is
// closed fails outright.
//
// The Generalized TTL Security Mechanism of RFC 5881, section 5 is
// enforced in both directions. Packets are sent with a TTL or hop limit of
// 255. A datagram routed here is dropped unless its own is 255 and its
// source address is peer, reported as an error wrapping ErrDropped. So a
// datagram carrying this session's discriminator from any other source is
// a drop here, never a delivery elsewhere.
func (l *Listener) Dial(peer netip.Addr) (Transport, error) {
	t, err := l.dial(peer, false)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// dial is Dial with the concrete transport type and the sole-session flag
// DialUDP needs. Registering the transport and marking it sole under one
// lock leaves no window where a datagram could arrive unroutable.
func (l *Listener) dial(peer netip.Addr, sole bool) (*listenerTransport, error) {
	peer = peer.Unmap()
	if err := checkPair(l.local, peer); err != nil {
		return nil, err
	}

	tx, err := dialSourcePort(l.local, peer)
	if err != nil {
		return nil, err
	}

	if l.local.Is4() {
		err = ipv4.NewConn(tx).SetTTL(255)
	} else {
		err = ipv6.NewConn(tx).SetHopLimit(255)
	}

	if err != nil {
		_ = tx.Close()
		return nil, fmt.Errorf("bfd: failed to set the outgoing TTL: %w", err)
	}

	t := &listenerTransport{
		l:       l,
		peer:    peer,
		tx:      tx,
		packets: make(chan datagram, queueDepth),
		done:    make(chan struct{}),
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		_ = tx.Close()
		return nil, errors.New("bfd: the listener is closed")
	}

	if _, ok := l.peers[peer]; ok {
		_ = tx.Close()
		return nil, fmt.Errorf("bfd: a transport for peer %s already exists on this listener", peer)
	}

	l.peers[peer] = t
	if sole {
		l.sole = t
	}

	return t, nil
}

// Close closes the receiving socket and every transport Dial produced,
// ending the sessions running over them: each pending ReadPacket fails
// with a terminal error, so every Run returns. Close returns only once the
// listener's read goroutine has stopped, leaving nothing of the listener
// running. It is idempotent and safe alongside a session closing its own
// transport, and every call reports the one teardown's result.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { l.closeErr = l.close() })

	// Every caller joins the read goroutine, not only the one which did
	// the closing.
	l.wg.Wait()

	return l.closeErr
}

// close is the one-time teardown: no further session may start, the
// receiving socket goes, which is what ends the read goroutine, and every
// open transport goes with it.
func (l *Listener) close() error {
	l.mu.Lock()
	l.closed = true
	ts := slices.Collect(maps.Values(l.peers))
	l.mu.Unlock()

	err := l.rx.Close()
	for _, t := range ts {
		err = errors.Join(err, t.Close())
	}

	return err
}

// serve is the listener's read goroutine: every datagram is read once into
// one buffer and routed below the Transport seam. Its exit is terminal for
// every session on the listener.
func (l *Listener) serve() {
	defer l.wg.Done()

	// Larger than any valid packet, so an oversized datagram is read whole
	// and rejected by a session's parse rather than silently truncated.
	buf := make([]byte, 4096)
	for {
		n, src, ttl, err := l.read(buf)
		if err != nil {
			l.readErr = err
			close(l.done)
			return
		}

		l.route(buf[:n], src, ttl)
	}
}

// route delivers one datagram to the session it belongs to, by the RFC
// 5880, section 6.8.6 discriminator rule and the RFC 5883, section 4.1
// address pair rule. It runs on the read goroutine and never blocks.
func (l *Listener) route(b []byte, src net.Addr, ttl int) {
	from, ok := sourceKey(src)
	if !ok {
		l.log.Debug("dropped datagram: source is not a UDP address", "src", src)
		return
	}

	// The control packet layout of RFC 5880, section 4.1 puts Your
	// Discriminator at bytes 8 to 11, readable without parsing the packet.
	// A datagram too short to hold one names no session, so it routes like
	// a first contact and the session's parse rejects it.
	var yourDiscr uint32
	if len(b) >= 12 {
		yourDiscr = binary.BigEndian.Uint32(b[8:12])
	}

	t := l.lookup(yourDiscr, from)
	if t == nil {
		l.log.Debug("dropped datagram: no session", "src", from, "your_discr", yourDiscr)
		return
	}

	// The datagram is copied because the read goroutine reuses one buffer.
	// A full queue drops rather than stalling the listener and every other
	// session behind one slow reader: BFD is lossy by design and the
	// detection timer covers the loss.
	select {
	case t.packets <- datagram{b: bytes.Clone(b), src: from, ttl: ttl}:
	default:
		l.log.Debug("dropped datagram: the session's queue is full", "peer", t.peer)
	}
}

// lookup selects the transport a datagram belongs to: the two routing
// tables first, then the sole session of a listener dialed for one, and
// nil when a shared listener matches neither.
func (l *Listener) lookup(yourDiscr uint32, from netip.Addr) *listenerTransport {
	l.mu.Lock()
	defer l.mu.Unlock()

	if yourDiscr != 0 {
		if t, ok := l.discrs[yourDiscr]; ok {
			return t
		}
	} else if t, ok := l.peers[from]; ok {
		return t
	}

	return l.sole
}

// remove unregisters t from both routing tables, leaving the shared
// receiving socket and every other session alone.
func (l *Listener) remove(t *listenerTransport) {
	l.mu.Lock()
	defer l.mu.Unlock()

	t.removed = true
	if l.sole == t {
		l.sole = nil
	}

	if l.peers[t.peer] == t {
		delete(l.peers, t.peer)
	}

	if t.discr != 0 && l.discrs[t.discr] == t {
		delete(l.discrs, t.discr)
	}
}

// A datagram is one routed datagram waiting for its session to read it:
// the listener's copy of the bytes, plus the evidence the RFC 5881,
// section 5 checks are made from.
type datagram struct {
	b   []byte
	src netip.Addr
	ttl int
}

// A listenerTransport is one peer's session on a Listener: the connected
// transmitting socket, and the queue of datagrams the listener routed to
// this session.
type listenerTransport struct {
	l    *Listener
	peer netip.Addr
	tx   *net.UDPConn

	packets chan datagram

	// done is closed by Close, unblocking a pending ReadPacket, and
	// closeErr records what closing the socket reported.
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	// discr is the session's local discriminator, learned from its first
	// write and zero until then, and removed marks a transport already
	// unregistered. Both are guarded by the listener's mutex.
	discr   uint32
	removed bool
}

// ReadPacket returns the next packet the listener routed to this session.
// A datagram failing an RFC 5881, section 5 check, a source address other
// than the peer's or a TTL or hop limit under 255, returns an error
// wrapping ErrDropped instead. Closing the transport or the listener ends
// a pending read with a terminal error.
func (t *listenerTransport) ReadPacket(b []byte) (int, error) {
	select {
	case d := <-t.packets:
		if d.src != t.peer {
			return 0, fmt.Errorf("%w: source %s is not the peer", ErrDropped, d.src)
		}

		if d.ttl != 255 {
			return 0, fmt.Errorf("%w: TTL %d from %s", ErrDropped, d.ttl, d.src)
		}

		return copy(b, d.b), nil

	case <-t.done:
		return 0, net.ErrClosed

	case <-t.l.done:
		return 0, fmt.Errorf("bfd: the listener stopped reading: %w", t.l.readErr)
	}
}

// WritePacket sends one packet to the peer. The first packet also teaches
// the listener this session's discriminator, so every later datagram
// echoing it routes here.
func (t *listenerTransport) WritePacket(b []byte) error {
	t.learn(b)
	_, err := t.tx.Write(b)
	return err
}

// learn registers the session's local discriminator with the listener,
// once. My Discriminator is at bytes 4 to 7 of every packet a session
// writes (RFC 5880, section 4.1) and is fixed for the session's life, so
// the first write is enough and no Session API is needed.
func (t *listenerTransport) learn(b []byte) {
	if len(b) < 8 {
		return
	}

	discr := binary.BigEndian.Uint32(b[4:8])
	if discr == 0 {
		return
	}

	t.l.mu.Lock()
	defer t.l.mu.Unlock()

	if t.removed || t.discr != 0 {
		return
	}

	if other, ok := t.l.discrs[discr]; ok && other != t {
		// Two sessions on one listener drew the same random
		// discriminator. The incumbent keeps it, and this session's
		// datagrams reach the incumbent and die on its source check, so
		// the session never comes up. A collision is a 1 in 2^32 draw and
		// a redial resolves it.
		t.l.log.Debug("discriminator collision", "peer", t.peer, "discr", discr)
		return
	}

	t.l.discrs[discr] = t
	t.discr = discr
}

// Close unregisters the session from the listener's routing, closes its
// transmitting socket, and unblocks a pending ReadPacket. It is idempotent
// and never touches the shared receiving socket: the listener's other
// sessions run on.
func (t *listenerTransport) Close() error {
	t.closeOnce.Do(func() {
		// done is the signal a pending read waits on; packets is
		// deliberately left open. Routing releases the listener's mutex
		// before it queues a datagram, so a session closing at that
		// moment is racing the send, and closing the queue here would
		// panic the listener's read goroutine. An open queue takes the
		// datagram, which nothing then reads.
		t.l.remove(t)
		close(t.done)
		t.closeErr = t.tx.Close()
	})

	return t.closeErr
}

// DialUDP produces the single-hop UDP Transport of RFC 5881 for the
// session between local and peer: a receiving socket bound to local on
// Port, and a transmitting socket connected to peer on Port from a source
// port in [49152, 65535]. The addresses must be unicast and share a family
// and a zone.
//
// The Generalized TTL Security Mechanism of RFC 5881, section 5 is
// enforced in both directions. Packets are sent with a TTL or hop limit of
// 255. Received packets are dropped unless theirs is 255 and their source
// address is peer, reported as an error wrapping ErrDropped. Both checks
// live below the Transport seam: a Session sees the drop report, never the
// packet.
//
// The receiving socket claims local's Port entirely, so one DialUDP
// transport serves one session, and Close releases the port. Dialing fails
// when anything else already holds the port on that address, such as
// another transport or another BFD daemon. ListenUDP is the way to run
// many sessions from one local address.
func DialUDP(local, peer netip.Addr) (Transport, error) {
	local, peer = local.Unmap(), peer.Unmap()
	if err := checkPair(local, peer); err != nil {
		return nil, err
	}

	// One session on a listener of its own: there is one receive path in
	// this package, and DialUDP is its exclusive-port case.
	l, err := ListenUDP(local, ListenConfig{})
	if err != nil {
		return nil, err
	}

	t, err := l.dial(peer, true)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	return &dialTransport{Transport: t, l: l}, nil
}

// A dialTransport is the sole session of a listener dialed for it alone.
type dialTransport struct {
	Transport
	l *Listener
}

// Close closes the session's sockets, the listener's receiving socket
// included, releasing the local address's Port and unblocking a blocked
// ReadPacket.
func (t *dialTransport) Close() error { return t.l.Close() }

// dialSourcePort connects the transmit socket to peer from a random source
// port in RFC 5881's range, retrying ports already in use.
func dialSourcePort(local, peer netip.Addr) (*net.UDPConn, error) {
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer, Port))
	var err error
	for range 16 {
		port := sourcePortMin + uint16(rand.IntN(sourcePortMax-sourcePortMin+1))
		laddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, port))

		var tx *net.UDPConn
		if tx, err = net.DialUDP("udp", laddr, raddr); err == nil {
			return tx, nil
		}
	}

	return nil, fmt.Errorf("bfd: failed to bind a source port in [%d, %d]: %w", sourcePortMin, sourcePortMax, err)
}

// checkPair validates the two addresses of one session: both present, both
// unicast, and one family and one zone between them.
func checkPair(local, peer netip.Addr) error {
	if !local.IsValid() || !peer.IsValid() {
		return errors.New("bfd: both local and peer addresses are required")
	}

	if local.Is4() != peer.Is4() {
		return fmt.Errorf("bfd: local %s and peer %s must share an address family", local, peer)
	}

	// A zoned local address is bound to one link, so its peer names the
	// same link or none of the session's datagrams can be attributed: the
	// kernel reports a link-local source with the receiving interface's
	// zone, and the zone is part of the routing key.
	if local.Zone() != peer.Zone() {
		return fmt.Errorf("bfd: local %s and peer %s must share a zone", local, peer)
	}

	for _, a := range []netip.Addr{local, peer} {
		if err := checkUnicast(a); err != nil {
			return err
		}
	}

	return nil
}

// checkUnicast rejects the addresses no BFD session can be built on.
func checkUnicast(a netip.Addr) error {
	if a.IsMulticast() || a.IsUnspecified() {
		return fmt.Errorf("bfd: local and peer must be unicast addresses: %s", a)
	}

	return nil
}

// sourceKey is a datagram's source as the routing key: 4-in-6 unmapped,
// and any zone kept, since a link-local peer is reachable on one link and
// the kernel names that link on every datagram it reports.
func sourceKey(src net.Addr) (netip.Addr, bool) {
	ua, ok := src.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}

	return ua.AddrPort().Addr().Unmap(), true
}
