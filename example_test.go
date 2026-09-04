package bfd_test

import (
	"context"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/mdlayher/bfd"
)

// A single-hop session protecting the path to one peer: dial the RFC 5881
// UDP transport, wire the up and down signals into the protected protocol,
// and run until interrupted or the transport fails.
func Example() {
	local, peer := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	t, err := bfd.DialUDP(local, peer)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}

	// The zero value works: 300ms intervals, a multiplier of 3, a 900ms
	// detection time.
	s, err := bfd.NewSession(t, bfd.Config{
		OnUp: func(_ *bfd.Session) {
			// Forwarding to the peer is healthy: announce routes. A session
			// is perpetual, so OnUp fires again after each recovery.
			log.Println("up")
		},

		OnDown: func(_ *bfd.Session, d bfd.Diagnostic, err error) {
			// The session fell from Up: withdraw routes and reset the
			// protected protocol's session. Check err first: non-nil is
			// the transport dying and Run returning. Otherwise d explains
			// the fall, the session's own cancellation included as
			// DiagAdministrativelyDown. Hooks run on the session
			// goroutine: blocking work belongs on another.
			if err != nil {
				log.Printf("down, transport failed: %v", err)
			} else {
				log.Printf("down: %v", d)
			}
		},

		// A Session knows discriminators, not addresses: scope the logger
		// by peer so many sessions stay legible in one log.
		Logger: slog.With("peer", peer),
	})
	if err != nil {
		_ = t.Close()
		log.Fatalf("failed to build session: %v", err)
	}

	// Run blocks for the session's whole life, owns the transport from its
	// first instant, and never returns nil. Cancellation fires OnDown like
	// any other fall from Up and tells the peer AdminDown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := s.Run(ctx); ctx.Err() == nil {
		// The transport failed; OnDown already reported it if the session
		// was Up.
		log.Printf("session failed: %v", err)
	}
}

// An authenticated session: both peers configure the same Simple Password
// key, every packet carries it, and a packet that fails to authenticate
// is discarded before it can touch the state machine. Simple Password
// guards against misconfiguration, such as a link rewired to the wrong
// neighbor, not against an attacker who can read the wire.
func Example_authentication() {
	local, peer := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	t, err := bfd.DialUDP(local, peer)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}

	s, err := bfd.NewSession(t, bfd.Config{
		OnUp:   func(_ *bfd.Session) { log.Println("up") },
		OnDown: func(_ *bfd.Session, d bfd.Diagnostic, err error) { log.Printf("down: %v %v", d, err) },

		// The peer must agree on the type, key ID, and key. Like the rest
		// of Config, Auth is immutable: rotating the key is a cancel and a
		// redial.
		Auth: &bfd.AuthConfig{
			Type:  bfd.AuthTypeSimplePassword,
			KeyID: 1,
			Key:   []byte("hunter2"),
		},
	})
	if err != nil {
		_ = t.Close()
		log.Fatalf("failed to build session: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := s.Run(ctx); ctx.Err() == nil {
		log.Printf("session failed: %v", err)
	}
}

// A session under a supervisor: a transport failure ends Run, since BFD
// cannot run without its packets, so the caller redials with backoff to
// bring the peering back. Run closes the transport before returning, so
// the redial never races the old sockets.
func Example_supervision() {
	local, peer := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for ctx.Err() == nil {
		err := func() error {
			t, err := bfd.DialUDP(local, peer)
			if err != nil {
				return err
			}

			s, err := bfd.NewSession(t, bfd.Config{
				OnUp:   func(_ *bfd.Session) { log.Println("up") },
				OnDown: func(_ *bfd.Session, d bfd.Diagnostic, err error) { log.Printf("down: %v %v", d, err) },
			})
			if err != nil {
				_ = t.Close()
				return err
			}

			return s.Run(ctx)
		}()
		if ctx.Err() == nil {
			log.Printf("session failed, redialing: %v", err)
			time.Sleep(1 * time.Second)
		}
	}
}
