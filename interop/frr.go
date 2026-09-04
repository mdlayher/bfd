//go:build interop && linux

package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"text/template"
	"time"
)

// frrVersion pins the FRR oracle release, enforced against the
// daemons' own reported version at startup. A silent oracle change
// must never be observable as a test result — it would be
// indistinguishable from a regression in this library — so upgrades
// are deliberate bumps of this constant together with the nix flake
// lock that supplies FRR to dev shells and CI.
const frrVersion = "10.7.0"

// frrHostname pins the instance's kernel hostname via its UTS
// namespace, keeping daemon logs stable across hosts.
const frrHostname = "frr-interop"

// An frrConfig parameterizes testdata/frr/base.conf.tmpl.
type frrConfig struct {
	KeyChains []frrKeyChain
	Peers     []frrPeer
}

// An frrKeyChain is a BFD authentication key chain. Only cleartext
// (Simple Password) is modeled: the pinned FRR build has no other
// algorithm compiled in.
type frrKeyChain struct {
	// Name is the key chain's name, referenced by a peer's AuthKeyChain.
	Name string

	// KeyID and Secret are the single key's identifier and password.
	KeyID  int
	Secret string
}

// An frrPeer is one single-hop BFD peer of an frrConfig. FRR's knobs
// mirror the wire: intervals are milliseconds on the vtysh surface.
type frrPeer struct {
	// Addr is the peer's address and Local the instance's own, the
	// `peer <addr> local-address <addr>` statement.
	Addr, Local netip.Addr

	// Multiplier, RXMS, and TXMS fill the peer's detect-multiplier,
	// receive-interval, and transmit-interval statements.
	Multiplier int
	RXMS, TXMS int

	// AuthKeyChain, when set, names the key chain the peer authenticates
	// with. It must match an frrKeyChain in the same config.
	AuthKeyChain string
}

// An frr is a running FRR instance on the harness network.
type frr struct {
	// Addr and Addr6 are the instance's addresses: the peers of a
	// library session running in the test binary.
	Addr  netip.Addr
	Addr6 netip.Addr

	name string
	vt   *nsFRR
}

// startFRR renders cfg and starts an FRR instance running it, torn
// down when t ends. It returns once bfdd is answering vtysh.
func startFRR(t *testing.T, cfg frrConfig) *frr {
	t.Helper()

	tmpl, err := template.ParseFiles(filepath.Join("testdata", "frr", "base.conf.tmpl"))
	if err != nil {
		t.Fatalf("failed to parse FRR config template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		t.Fatalf("failed to render FRR config: %v", err)
	}

	name := instanceName(t)
	f := &frr{
		Addr:  netip.MustParseAddr(frrV4),
		Addr6: netip.MustParseAddr(frrV6),
		name:  name,
		vt:    rt.startFRR(t, name, buf.Bytes()),
	}

	f.poll(t, "bfdd never answered vtysh", func() bool {
		var v []json.RawMessage
		return f.vtysh(t, "show bfd peers json", &v) == nil
	})

	return f
}

// vtysh runs one vtysh command against the instance and unmarshals its
// JSON output into v, which may be nil to discard the output.
func (f *frr) vtysh(t *testing.T, cmd string, v any) error {
	t.Helper()

	out, err := f.vt.vtysh(cmd)
	if err != nil {
		return fmt.Errorf("vtysh %q: %w: %s", cmd, err, out)
	}

	if v == nil {
		return nil
	}

	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("vtysh %q: failed to unmarshal: %w: %s", cmd, err, out)
	}

	return nil
}

// An frrPeerJSON is the narrow slice of `show bfd peers json` output
// the tests assert on; FRR's full schema is deliberately not modeled.
// The remote-* fields are FRR's record of what our session put on the
// wire: the oracle's view of this library.
type frrPeerJSON struct {
	Peer   string `json:"peer"`
	Status string `json:"status"`

	// ID is FRR's own discriminator; RemoteID is ours, learned from
	// our My Discriminator field.
	ID       uint32 `json:"id"`
	RemoteID uint32 `json:"remote-id"`

	Diagnostic       string `json:"diagnostic"`
	RemoteDiagnostic string `json:"remote-diagnostic"`

	// Milliseconds, as FRR reports them.
	RemoteReceiveInterval  int `json:"remote-receive-interval"`
	RemoteTransmitInterval int `json:"remote-transmit-interval"`
	RemoteDetectMultiplier int `json:"remote-detect-multiplier"`

	// Authentication is FRR's view of the session's authentication, present
	// only when a key chain is configured on the peer.
	Authentication struct {
		Enabled    bool   `json:"enabled"`
		CryptoName string `json:"cryptoName"`
	} `json:"authentication"`
}

// peer fetches FRR's current view of the BFD peer at addr.
func (f *frr) peer(t *testing.T, addr netip.Addr) (frrPeerJSON, error) {
	t.Helper()

	var peers []frrPeerJSON
	if err := f.vtysh(t, "show bfd peers json", &peers); err != nil {
		return frrPeerJSON{}, err
	}

	for _, p := range peers {
		if p.Peer == addr.String() {
			return p, nil
		}
	}

	return frrPeerJSON{}, fmt.Errorf("FRR reports no BFD peer %s", addr)
}

// awaitStatus polls until FRR reports the peer at addr with the given
// session status ("up" or "down"), and returns that view.
func (f *frr) awaitStatus(t *testing.T, addr netip.Addr, status string) frrPeerJSON {
	t.Helper()

	var p frrPeerJSON
	f.poll(t, fmt.Sprintf("peer %s never reached status %q", addr, status), func() bool {
		var err error
		p, err = f.peer(t, addr)
		return err == nil && p.Status == status
	})

	return p
}

// configure applies configuration lines through vtysh, entering
// configure terminal first; vtysh retains mode across -c arguments,
// so nested lines (bfd, then peer statements) work as they would
// interactively.
func (f *frr) configure(t *testing.T, lines ...string) {
	t.Helper()

	if out, err := f.vt.vtysh(append([]string{"configure terminal"}, lines...)...); err != nil {
		t.Fatalf("failed to configure FRR (%q): %v: %s", lines, err, out)
	}
}

// poll invokes fn every 250ms until it reports true, failing t after a
// generous deadline. Polling an external process is the documented
// exception to the repo's no-sleep rule: the oracle's state machine is
// not ours to synchronize on, and every wait involving only library
// code blocks on a real signal instead.
func (f *frr) poll(t *testing.T, msg string, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out polling %s: %s", f.name, msg)
		}

		time.Sleep(250 * time.Millisecond)
	}
}
