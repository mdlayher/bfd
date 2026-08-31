# bfd

A Go library for Bidirectional Forwarding Detection (RFC 5880/5881):
fast forwarding-path liveness between two systems, independent of the
protocols routing over it: wire format, transport, and sessions.
Single-hop asynchronous mode without authentication is the current
scope: echo, demand mode, multihop (RFC 5883), and authentication may
come later, and GTSM protects single-hop in the meantime. A shared
listener demultiplexing many sessions on one local address is planned
but unbuilt: DialUDP serves one session per local address today. No
import edge with any routing protocol package in either direction: the
caller wires a down signal into its own protocol.

## Language

**Control packet**:
One BFD protocol unit on the wire (RFC 5880, section 4.1): the
mandatory section, since authentication is unsupported. One UDP
datagram carries exactly one.

**Discriminator**:
A nonzero 32 bit value identifying one side's half of a session,
unique among that system's sessions. Each side picks its own (My
Discriminator) and echoes the peer's (Your Discriminator, zero until
learned).

**Detection time**:
The silence after which a peer is declared down: the detection
multiplier times the agreed receive interval. BFD's counterpart of
BGP's hold time, but measured in milliseconds.

**Asynchronous mode**:
The mode this package implements: both systems transmit control
packets on their own cadence, and each detects the other's silence.
_Avoid_: assuming echo or demand mode; both are out of scope

**Poll sequence**:
The RFC 5880, section 6.5 handshake confirming a parameter change: a
Poll bit answered by a Final bit.

**Down signal**:
A session's transition out of Up, delivered to the caller, who feeds
it into the protocol the session protects — for BGP, a session reset
carrying BFD Down (RFC 9384).
