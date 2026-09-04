//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/bfd"
)

// authKeyChain is the key chain name shared by the auth scenarios and the
// FRR config they render.
const authKeyChain = "bfdauth"

// Scenario 6: authenticated establishment. The library and FRR share a
// Simple Password key chain, so each authenticates the other's packets and
// the session reaches Up. FRR's JSON confirms it negotiated authentication.
func TestFRRAuthSimplePassword(t *testing.T) {
	const secret = "hunter2"

	f, host := startFRRAuthPeer(t, secret)

	_, upC, _ := runAuthSession(t, host, f.Addr, &bfd.AuthConfig{
		Type:  bfd.AuthTypeSimplePassword,
		KeyID: 1,
		Key:   []byte(secret),
	})
	await(t, upC, "OnUp")

	p := f.awaitStatus(t, host, "up")
	if !p.Authentication.Enabled {
		t.Error("FRR does not report authentication enabled")
	}

	if got, want := p.Authentication.CryptoName, "simple-password"; got != want {
		t.Errorf("FRR reports unexpected authentication type: got %q, want %q", got, want)
	}
}

// Scenario 7: a wrong password never establishes. FRR discards the
// library's packets and the library discards FRR's, so neither side leaves
// Down and no OnUp or OnDown ever fires.
func TestFRRAuthMismatch(t *testing.T) {
	f, host := startFRRAuthPeer(t, "correct")

	_, upC, downC := runAuthSession(t, host, f.Addr, &bfd.AuthConfig{
		Type:  bfd.AuthTypeSimplePassword,
		KeyID: 1,
		Key:   []byte("wrong"),
	})

	// An absence has no signal to await: hold against the oracle's real
	// timers for several detection times, the same exception as poll.
	select {
	case <-upC:
		t.Fatal("session reached Up despite mismatched passwords")
	case d := <-downC:
		t.Fatalf("unexpected OnDown before ever reaching Up: %+v", d)
	case <-time.After(4 * time.Second):
	}

	if p, err := f.peer(t, host); err != nil || p.Status == "up" {
		t.Fatalf("FRR unexpectedly reports the peer up: %+v (err %v)", p, err)
	}
}

// startFRRAuthPeer starts an FRR instance whose single IPv4 peer
// authenticates with a Simple Password key chain carrying secret.
func startFRRAuthPeer(t *testing.T, secret string) (*frr, netip.Addr) {
	t.Helper()

	host := hostAddr4
	f := startFRR(t, frrConfig{
		KeyChains: []frrKeyChain{{Name: authKeyChain, KeyID: 1, Secret: secret}},
		Peers: []frrPeer{{
			Addr:         host,
			Local:        netip.MustParseAddr(frrV4),
			Multiplier:   multiplier,
			RXMS:         intervalMS,
			TXMS:         intervalMS,
			AuthKeyChain: authKeyChain,
		}},
	})

	return f, host
}

// runAuthSession is runSession with authentication configured: it dials the
// transport and runs a Session carrying auth, returning the Session and its
// OnUp and OnDown channels. Teardown cancels Run and joins it when t ends.
func runAuthSession(t *testing.T, local, peer netip.Addr, auth *bfd.AuthConfig) (*bfd.Session, <-chan struct{}, <-chan sessionDown) {
	t.Helper()

	tr, err := bfd.DialUDP(local, peer)
	if err != nil {
		t.Fatalf("failed to dial transport: %v", err)
	}

	upC := make(chan struct{}, 4)
	downC := make(chan sessionDown, 4)
	s, err := bfd.NewSession(tr, bfd.Config{
		Auth:   auth,
		OnUp:   func(_ *bfd.Session) { upC <- struct{}{} },
		OnDown: func(_ *bfd.Session, d bfd.Diagnostic, err error) { downC <- sessionDown{Diag: d, Err: err} },
	})
	if err != nil {
		_ = tr.Close()
		t.Fatalf("failed to build session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Run(ctx); ctx.Err() == nil {
			t.Logf("session run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return s, upC, downC
}
