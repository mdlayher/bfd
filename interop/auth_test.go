//go:build interop && linux

package interop

import (
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
	t.Parallel()

	const secret = "hunter2"

	f, host := startFRRAuthPeer(t, secret)

	ls := runTransport(t, dialUDP(t, host, f.Addr), &bfd.AuthConfig{
		Type:  bfd.AuthTypeSimplePassword,
		KeyID: 1,
		Key:   []byte(secret),
	})

	await(t, ls.upC, "OnUp")

	want := frrAuthJSON{
		Enabled:    true,
		CryptoName: "simple-password",
	}

	if d := diff(t, want, f.awaitStatus(t, host, "up").Authentication); d != "" {
		t.Errorf("FRR reports unexpected authentication (-want +got):\n%s", d)
	}
}

// Scenario 7: a wrong password never establishes. FRR discards the
// library's packets and the library discards FRR's, so neither side leaves
// Down and no OnUp or OnDown ever fires.
func TestFRRAuthMismatch(t *testing.T) {
	t.Parallel()

	f, host := startFRRAuthPeer(t, "correct")

	ls := runTransport(t, dialUDP(t, host, f.Addr), &bfd.AuthConfig{
		Type:  bfd.AuthTypeSimplePassword,
		KeyID: 1,
		Key:   []byte("wrong"),
	})

	// An absence has no signal to await: hold against the oracle's real
	// timers for several detection times, the same exception as poll.
	select {
	case <-ls.upC:
		t.Fatal("session reached Up despite mismatched passwords")
	case d := <-ls.downC:
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

	f := startFRR(t, frrConfig{
		KeyChains: []frrKeyChain{{
			Name:   authKeyChain,
			KeyID:  1,
			Secret: secret,
		}},
		Peers: []frrPeer{{
			Addr:         hostAddr4,
			Local:        netip.MustParseAddr(frrV4),
			Multiplier:   multiplier,
			RXMS:         intervalMS,
			TXMS:         intervalMS,
			AuthKeyChain: authKeyChain,
		}},
	})

	return f, hostAddr4
}
