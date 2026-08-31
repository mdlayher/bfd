// Package bfd implements the Bidirectional Forwarding Detection protocol
// (BFD), as described in RFC 5880 and RFC 5881: a fast liveness protocol for
// the forwarding path between two systems, independent of the protocols
// routing over it.
//
// The package is built in layers, each usable without the ones above it:
// ControlPacket and its binary encoding; Transport carrying packets between
// two systems, with DialUDP the RFC 5881 single-hop implementation; and
// Session running the RFC 5880 state machine in asynchronous mode,
// reporting Up and Down to the caller's hooks.
//
// The current scope is single-hop, asynchronous BFD: the echo function is
// declined on the wire, demand mode is carried faithfully but never
// operated, and authentication is not supported. RFC 5881's TTL check is
// the single-hop protection. A session runs until canceled, so an
// administrative down and up is a cancel and a redial.
package bfd

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	// Port is the destination UDP port for single-hop BFD control packets,
	// as assigned by IANA (RFC 5881, section 4).
	Port = 3784

	// version is the BFD version implemented by this package (RFC 5880).
	version = 1

	// packetLen is the size in bytes of a control packet's mandatory
	// section. A packet carrying authentication is longer; this package
	// does not support authentication.
	packetLen = 24
)

// A State is the state of a BFD session (RFC 5880, section 6.2), in its
// wire encoding (section 4.1). The values are the wire's: the zero value
// is StateAdminDown, not StateDown.
type State uint8

// State values, as described in RFC 5880, section 4.1.
const (
	StateAdminDown State = 0
	StateDown      State = 1
	StateInit      State = 2
	StateUp        State = 3
)

// String returns the RFC 5880 name of a State.
func (s State) String() string {
	switch s {
	case StateAdminDown:
		return "AdminDown"
	case StateDown:
		return "Down"
	case StateInit:
		return "Init"
	case StateUp:
		return "Up"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// A Diagnostic is the reason for a BFD session's last state change, as
// described in RFC 5880, section 4.1.
type Diagnostic uint8

// Diagnostic values, as assigned in the IANA BFD Diagnostic Codes
// registry: 0 through 8 by RFC 5880 and 9 by RFC 6428.
const (
	DiagNone                        Diagnostic = 0
	DiagControlDetectionTimeExpired Diagnostic = 1
	DiagEchoFunctionFailed          Diagnostic = 2
	DiagNeighborSignaledSessionDown Diagnostic = 3
	DiagForwardingPlaneReset        Diagnostic = 4
	DiagPathDown                    Diagnostic = 5
	DiagConcatenatedPathDown        Diagnostic = 6
	DiagAdministrativelyDown        Diagnostic = 7
	DiagReverseConcatenatedPathDown Diagnostic = 8
	DiagMisConnectivityDefect       Diagnostic = 9
)

// String returns the name of a Diagnostic.
func (d Diagnostic) String() string {
	switch d {
	case DiagNone:
		return "No Diagnostic"
	case DiagControlDetectionTimeExpired:
		return "Control Detection Time Expired"
	case DiagEchoFunctionFailed:
		return "Echo Function Failed"
	case DiagNeighborSignaledSessionDown:
		return "Neighbor Signaled Session Down"
	case DiagForwardingPlaneReset:
		return "Forwarding Plane Reset"
	case DiagPathDown:
		return "Path Down"
	case DiagConcatenatedPathDown:
		return "Concatenated Path Down"
	case DiagAdministrativelyDown:
		return "Administratively Down"
	case DiagReverseConcatenatedPathDown:
		return "Reverse Concatenated Path Down"
	case DiagMisConnectivityDefect:
		return "Mis-connectivity Defect"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(d))
	}
}

// Flag masks for a control packet's second byte, below the 2 bit state.
const (
	flagPoll         = 1 << 5
	flagFinal        = 1 << 4
	flagControlPlane = 1 << 3
	flagAuthPresent  = 1 << 2
	flagDemand       = 1 << 1
	flagMultipoint   = 1 << 0
)

// A ControlPacket is a BFD control packet's mandatory section, as described
// in RFC 5880, section 4.1. Authentication is not supported: a packet with
// the Authentication Present (A) bit set fails to parse, and there is no way
// to marshal one.
type ControlPacket struct {
	// Diagnostic is the reason for the sender's last session state change.
	Diagnostic Diagnostic

	// State is the sender's current session state.
	State State

	// Poll requests a packet with Final set, beginning the RFC 5880,
	// section 6.5 poll sequence which confirms a parameter change.
	Poll bool

	// Final answers a received Poll, completing the poll sequence. The
	// two bits are mutually exclusive.
	Final bool

	// ControlPlaneIndependent reports that the sender's BFD keeps running
	// while its control plane restarts: the C bit. It tells the peer
	// whether a detected failure still means the forwarding path died,
	// or may merely be a routing daemon restarting gracefully.
	ControlPlaneIndependent bool

	// Demand requests demand mode (RFC 5880, section 6.6), which this
	// package does not operate but carries faithfully.
	Demand bool

	// DetectMultiplier is the detection time multiplier: the peer
	// declares this session down after DetectMultiplier transmit
	// intervals of silence. It must be nonzero.
	DetectMultiplier uint8

	// MyDiscriminator identifies the sender's half of the session: a
	// nonzero value, unique among the sender's sessions.
	MyDiscriminator uint32

	// YourDiscriminator echoes the peer's discriminator. It is zero while
	// the peer is unknown, which the wire permits only in the AdminDown
	// and Down states.
	YourDiscriminator uint32

	// DesiredMinTX is the fastest the sender wants to transmit; the wire
	// encodes 32 bits of whole microseconds. Each transmit interval is
	// the slower of one side's desire and the other's requirement.
	DesiredMinTX time.Duration

	// RequiredMinRX is the fastest the sender can receive: DesiredMinTX's
	// counterpart in the interval negotiation.
	RequiredMinRX time.Duration

	// RequiredMinEchoRX bounds the echo function, or is zero to decline
	// it.
	RequiredMinEchoRX time.Duration
}

// AppendBinary implements encoding.BinaryAppender. It validates as
// ParseControlPacket does, so any packet which parses also marshals: a
// diagnostic within the wire's 5 bits is carried faithfully in both
// directions, named by this package or not. Call AppendBinary with a nil
// buffer for a standalone encoding.
func (p *ControlPacket) AppendBinary(b []byte) ([]byte, error) {
	if p.Diagnostic > 0x1f {
		return nil, fmt.Errorf("bfd: diagnostic %d does not fit the wire's 5 bits", uint8(p.Diagnostic))
	}

	if p.State > StateUp {
		return nil, fmt.Errorf("bfd: state %d does not exist", uint8(p.State))
	}

	if p.DetectMultiplier == 0 {
		return nil, fmt.Errorf("bfd: detection time multiplier must be nonzero")
	}

	if p.MyDiscriminator == 0 {
		return nil, fmt.Errorf("bfd: my discriminator must be nonzero")
	}

	if p.Poll && p.Final {
		return nil, fmt.Errorf("bfd: the poll and final bits are mutually exclusive")
	}

	if p.YourDiscriminator == 0 && p.State != StateDown && p.State != StateAdminDown {
		return nil, fmt.Errorf("bfd: your discriminator must be nonzero in state %s", p.State)
	}

	for _, d := range []time.Duration{p.DesiredMinTX, p.RequiredMinRX, p.RequiredMinEchoRX} {
		if d < 0 || d/time.Microsecond > math.MaxUint32 {
			return nil, fmt.Errorf("bfd: interval does not fit the wire's 32 bit whole microseconds: %s", d)
		}
	}

	b = append(b, version<<5|uint8(p.Diagnostic))

	var flags uint8
	for _, f := range []struct {
		set  bool
		mask uint8
	}{
		{p.Poll, flagPoll},
		{p.Final, flagFinal},
		{p.ControlPlaneIndependent, flagControlPlane},
		{p.Demand, flagDemand},
	} {
		if f.set {
			flags |= f.mask
		}
	}

	b = append(b, uint8(p.State)<<6|flags, p.DetectMultiplier, packetLen)

	b = binary.BigEndian.AppendUint32(b, p.MyDiscriminator)
	b = binary.BigEndian.AppendUint32(b, p.YourDiscriminator)
	for _, d := range []time.Duration{p.DesiredMinTX, p.RequiredMinRX, p.RequiredMinEchoRX} {
		b = binary.BigEndian.AppendUint32(b, uint32(d/time.Microsecond))
	}

	return b, nil
}

// ParseControlPacket parses a ControlPacket from b, which must contain
// exactly one control packet: one UDP datagram's payload.
//
// Structural checks at least as strict as RFC 5880, section 6.8.6 are
// applied: the version, length, detection time multiplier, and multipoint
// bit. Checks which need session state, such as discriminator matching,
// are the session's. A packet with the Authentication Present bit set is
// rejected, as this package supports no authentication.
func ParseControlPacket(b []byte) (*ControlPacket, error) {
	if len(b) != packetLen {
		return nil, fmt.Errorf("bfd: control packet must be %d bytes without authentication: %d bytes", packetLen, len(b))
	}

	if v := b[0] >> 5; v != version {
		return nil, fmt.Errorf("bfd: unsupported version %d", v)
	}

	if length := b[3]; int(length) != packetLen {
		return nil, fmt.Errorf("bfd: control packet length field %d does not match the %d bytes received", length, packetLen)
	}

	if b[1]&flagAuthPresent != 0 {
		return nil, fmt.Errorf("bfd: authentication is not supported")
	}

	if b[1]&flagMultipoint != 0 {
		return nil, fmt.Errorf("bfd: the multipoint bit must be zero (RFC 5880, section 6.8.6)")
	}

	p := &ControlPacket{
		Diagnostic:              Diagnostic(b[0] & 0x1f),
		State:                   State(b[1] >> 6),
		Poll:                    b[1]&flagPoll != 0,
		Final:                   b[1]&flagFinal != 0,
		ControlPlaneIndependent: b[1]&flagControlPlane != 0,
		Demand:                  b[1]&flagDemand != 0,
		DetectMultiplier:        b[2],
		MyDiscriminator:         binary.BigEndian.Uint32(b[4:8]),
		YourDiscriminator:       binary.BigEndian.Uint32(b[8:12]),
		DesiredMinTX:            time.Duration(binary.BigEndian.Uint32(b[12:16])) * time.Microsecond,
		RequiredMinRX:           time.Duration(binary.BigEndian.Uint32(b[16:20])) * time.Microsecond,
		RequiredMinEchoRX:       time.Duration(binary.BigEndian.Uint32(b[20:24])) * time.Microsecond,
	}

	if p.DetectMultiplier == 0 {
		return nil, fmt.Errorf("bfd: detection time multiplier must be nonzero")
	}

	if p.MyDiscriminator == 0 {
		return nil, fmt.Errorf("bfd: my discriminator must be nonzero")
	}

	if p.Poll && p.Final {
		return nil, fmt.Errorf("bfd: the poll and final bits are mutually exclusive")
	}

	if p.YourDiscriminator == 0 && p.State != StateDown && p.State != StateAdminDown {
		return nil, fmt.Errorf("bfd: your discriminator must be nonzero in state %s", p.State)
	}

	return p, nil
}
