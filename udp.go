package bfd

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Source ports for single-hop BFD control packets, per RFC 5881, section 4.
const (
	sourcePortMin = 49152
	sourcePortMax = 65535
)

// DialUDP produces the single-hop UDP Transport of RFC 5881 for the
// session between local and peer: a receiving socket bound to local on
// Port, and a transmitting socket connected to peer on Port from a source
// port in [49152, 65535]. The addresses must be unicast and share a
// family.
//
// The Generalized TTL Security Mechanism of RFC 5881, section 5 is
// enforced in both directions. Packets are sent with a TTL or hop limit of
// 255. Received packets are dropped unless theirs is 255 and their source
// address is peer, reported as an error wrapping ErrDropped. Both checks
// live below the Transport seam: a Session sees the drop report, never the
// packet.
//
// The receiving socket claims local's Port entirely, so one DialUDP
// transport serves one session. Dialing fails when anything else already
// holds the port on that address, such as another transport or another
// BFD daemon. This package provides no shared listener: many sessions take
// one local address each, or a caller-built Transport demultiplexes.
func DialUDP(local, peer netip.Addr) (Transport, error) {
	local, peer = local.Unmap(), peer.Unmap()
	if !local.IsValid() || !peer.IsValid() {
		return nil, errors.New("bfd: both local and peer addresses are required")
	}

	if local.Is4() != peer.Is4() {
		return nil, fmt.Errorf("bfd: local %s and peer %s must share an address family", local, peer)
	}

	for _, a := range []netip.Addr{local, peer} {
		if a.IsMulticast() || a.IsUnspecified() {
			return nil, fmt.Errorf("bfd: local and peer must be unicast addresses: %s", a)
		}
	}

	rx, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, Port)))
	if err != nil {
		return nil, fmt.Errorf("bfd: failed to bind receive socket: %w", err)
	}

	tx, err := dialSourcePort(local, peer)
	if err != nil {
		_ = rx.Close()
		return nil, err
	}

	t := &udpTransport{rx: rx, tx: tx, peer: peer}
	if local.Is4() {
		// Reads go through the packet connection so each datagram carries
		// its TTL; writes leave with the maximum.
		p := ipv4.NewPacketConn(rx)
		if err := p.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("bfd: failed to request TTLs: %w", err)
		}

		if err := ipv4.NewConn(tx).SetTTL(255); err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("bfd: failed to set TTL: %w", err)
		}

		t.read = func(b []byte) (int, net.Addr, int, error) {
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
			_ = t.Close()
			return nil, fmt.Errorf("bfd: failed to request hop limits: %w", err)
		}

		if err := ipv6.NewConn(tx).SetHopLimit(255); err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("bfd: failed to set hop limit: %w", err)
		}

		t.read = func(b []byte) (int, net.Addr, int, error) {
			n, cm, src, err := p.ReadFrom(b)
			hl := -1
			if cm != nil {
				hl = cm.HopLimit
			}

			return n, src, hl, err
		}
	}

	return t, nil
}

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

// A udpTransport is the RFC 5881 single-hop transport: an unconnected
// receive socket whose reads are filtered by source address and TTL, and a
// connected transmit socket.
type udpTransport struct {
	rx, tx *net.UDPConn
	read   func(b []byte) (int, net.Addr, int, error)
	peer   netip.Addr
}

// ReadPacket returns the next packet from the peer. A datagram failing an
// RFC 5881, section 5 check, a source address other than the peer's or a
// TTL or hop limit under 255, returns an error wrapping ErrDropped
// instead.
func (t *udpTransport) ReadPacket(b []byte) (int, error) {
	n, src, ttl, err := t.read(b)
	if err != nil {
		return 0, err
	}

	ua, ok := src.(*net.UDPAddr)
	if !ok || ua.AddrPort().Addr().Unmap() != t.peer {
		return 0, fmt.Errorf("%w: source %s is not the peer", ErrDropped, src)
	}

	if ttl != 255 {
		return 0, fmt.Errorf("%w: TTL %d from %s", ErrDropped, ttl, src)
	}

	return n, nil
}

// WritePacket sends one packet to the peer.
func (t *udpTransport) WritePacket(b []byte) error {
	_, err := t.tx.Write(b)
	return err
}

// Close closes both sockets, unblocking a blocked ReadPacket.
func (t *udpTransport) Close() error {
	return errors.Join(t.rx.Close(), t.tx.Close())
}
