# bfd [![Test Status](https://github.com/mdlayher/bfd/workflows/Test/badge.svg)](https://github.com/mdlayher/bfd/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/bfd.svg)](https://pkg.go.dev/github.com/mdlayher/bfd)

Package `bfd` implements the Bidirectional Forwarding Detection protocol
(BFD), as described in RFC 5880 and RFC 5881: a fast liveness protocol for
the forwarding path between two systems, independent of the protocols
routing over it. MIT Licensed.

The current scope is single-hop, asynchronous BFD. See the
[package documentation](https://pkg.go.dev/github.com/mdlayher/bfd) for
details.
