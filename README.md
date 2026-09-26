# bfd [![Test Status][test-badge]][test] [![Go Reference][ref-badge]][ref]

Package `bfd` implements the Bidirectional Forwarding Detection protocol
(BFD), as described in RFC 5880 and RFC 5881: a fast liveness protocol for
the forwarding path between two systems, independent of the protocols
routing over it. MIT Licensed.

The current scope is single-hop, asynchronous BFD. See the
[package documentation](https://pkg.go.dev/github.com/mdlayher/bfd) for
details.

[test-badge]: https://github.com/mdlayher/bfd/workflows/Test/badge.svg
[test]: https://github.com/mdlayher/bfd/actions
[ref-badge]: https://pkg.go.dev/badge/github.com/mdlayher/bfd.svg
[ref]: https://pkg.go.dev/github.com/mdlayher/bfd
