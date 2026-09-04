package bfd

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestControlPacketRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    *ControlPacket
	}{
		{
			name: "down minimal",
			p: &ControlPacket{
				State:            StateDown,
				DetectMultiplier: 1,
				MyDiscriminator:  1,
			},
		},
		{
			// Unassigned within the wire's 5 bits: carried faithfully in
			// both directions.
			name: "unassigned diagnostic",
			p: &ControlPacket{
				Diagnostic:       Diagnostic(0x1f),
				State:            StateDown,
				DetectMultiplier: 1,
				MyDiscriminator:  1,
			},
		},
		{
			name: "admin down farewell",
			p: &ControlPacket{
				Diagnostic:        DiagAdministrativelyDown,
				State:             StateAdminDown,
				DetectMultiplier:  3,
				MyDiscriminator:   0x01020304,
				YourDiscriminator: 0x05060708,
				DesiredMinTX:      time.Second,
				RequiredMinRX:     300 * time.Millisecond,
			},
		},
		{
			name: "up poll",
			p: &ControlPacket{
				Diagnostic:              DiagControlDetectionTimeExpired,
				State:                   StateUp,
				Poll:                    true,
				ControlPlaneIndependent: true,
				DetectMultiplier:        3,
				MyDiscriminator:         0xaabbccdd,
				YourDiscriminator:       0x11223344,
				DesiredMinTX:            300 * time.Millisecond,
				RequiredMinRX:           300 * time.Millisecond,
				RequiredMinEchoRX:       50 * time.Millisecond,
			},
		},
		{
			name: "init final demand",
			p: &ControlPacket{
				State:             StateInit,
				Final:             true,
				Demand:            true,
				DetectMultiplier:  5,
				MyDiscriminator:   2,
				YourDiscriminator: 3,
				DesiredMinTX:      time.Second,
				RequiredMinRX:     time.Second,
			},
		},
		{
			name: "maximums",
			p: &ControlPacket{
				Diagnostic:        DiagReverseConcatenatedPathDown,
				State:             StateUp,
				DetectMultiplier:  math.MaxUint8,
				MyDiscriminator:   math.MaxUint32,
				YourDiscriminator: math.MaxUint32,
				DesiredMinTX:      math.MaxUint32 * time.Microsecond,
				RequiredMinRX:     math.MaxUint32 * time.Microsecond,
				RequiredMinEchoRX: math.MaxUint32 * time.Microsecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.p.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal packet: %v", err)
			}

			got, err := ParseControlPacket(b)
			if err != nil {
				t.Fatalf("failed to parse packet: %v", err)
			}

			if d := diff(t, tt.p, got); d != "" {
				t.Fatalf("unexpected packet (-want +got):\n%s", d)
			}

			// The parsed packet must reproduce the marshaled bytes exactly.
			b2, err := got.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal parsed packet: %v", err)
			}

			if d := diff(t, b, b2); d != "" {
				t.Fatalf("unexpected packet bytes (-want +got):\n%s", d)
			}
		})
	}
}

func TestControlPacketWireFormat(t *testing.T) {
	t.Parallel()

	p := &ControlPacket{
		Diagnostic:              DiagControlDetectionTimeExpired,
		State:                   StateUp,
		Poll:                    true,
		ControlPlaneIndependent: true,
		DetectMultiplier:        3,
		MyDiscriminator:         0x01020304,
		YourDiscriminator:       0x0a0b0c0d,
		DesiredMinTX:            300 * time.Millisecond,
		RequiredMinRX:           100 * time.Millisecond,
		RequiredMinEchoRX:       50 * time.Millisecond,
	}

	// AppendBinary must append: the prefix survives.
	b, err := p.AppendBinary([]byte{0xff})
	if err != nil {
		t.Fatalf("failed to marshal packet: %v", err)
	}

	want := []byte{
		0xff,
		// Version 1, diagnostic 1.
		0x21,
		// State Up, poll, control plane independent.
		0xe8,
		// Detection multiplier and length.
		0x03, 0x18,
		// My and your discriminators.
		0x01, 0x02, 0x03, 0x04,
		0x0a, 0x0b, 0x0c, 0x0d,
		// 300ms, 100ms, and 50ms in whole microseconds.
		0x00, 0x04, 0x93, 0xe0,
		0x00, 0x01, 0x86, 0xa0,
		0x00, 0x00, 0xc3, 0x50,
	}

	if d := diff(t, want, b); d != "" {
		t.Fatalf("unexpected wire encoding (-want +got):\n%s", d)
	}
}

func TestControlPacketAppendBinaryErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mod  func(p *ControlPacket)
	}{
		{
			name: "oversized diagnostic",
			mod:  func(p *ControlPacket) { p.Diagnostic = Diagnostic(0x20) },
		},
		{
			name: "poll and final",
			mod: func(p *ControlPacket) {
				p.Poll = true
				p.Final = true
			},
		},
		{
			name: "zero your discriminator up",
			mod:  func(p *ControlPacket) { p.YourDiscriminator = 0 },
		},
		{
			name: "nonexistent state",
			mod:  func(p *ControlPacket) { p.State = StateUp + 1 },
		},
		{
			name: "zero detection multiplier",
			mod:  func(p *ControlPacket) { p.DetectMultiplier = 0 },
		},
		{
			name: "zero my discriminator",
			mod:  func(p *ControlPacket) { p.MyDiscriminator = 0 },
		},
		{
			name: "negative interval",
			mod:  func(p *ControlPacket) { p.DesiredMinTX = -time.Second },
		},
		{
			name: "oversized interval",
			mod:  func(p *ControlPacket) { p.RequiredMinRX = (math.MaxUint32 + 1) * time.Microsecond },
		},
		{
			name: "oversized echo interval",
			mod:  func(p *ControlPacket) { p.RequiredMinEchoRX = (math.MaxUint32 + 1) * time.Microsecond },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := validPacket()
			tt.mod(p)

			b, err := p.AppendBinary(nil)
			if err == nil {
				t.Fatalf("expected an error, but marshaled: %x", b)
			}
		})
	}
}

func TestParseControlPacketErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mod  func(b []byte) []byte
	}{
		{
			name: "empty",
			mod:  func(b []byte) []byte { return nil },
		},
		{
			name: "short",
			mod:  func(b []byte) []byte { return b[:packetLen-1] },
		},
		{
			name: "long",
			mod:  func(b []byte) []byte { return append(b, 0x00) },
		},
		{
			name: "version zero",
			mod: func(b []byte) []byte {
				b[0] &^= 0xe0
				return b
			},
		},
		{
			name: "length field mismatch",
			mod: func(b []byte) []byte {
				b[3] = packetLen - 1
				return b
			},
		},
		{
			name: "authentication present without a section",
			mod: func(b []byte) []byte {
				b[1] |= flagAuthPresent
				return b
			},
		},
		{
			name: "multipoint",
			mod: func(b []byte) []byte {
				b[1] |= flagMultipoint
				return b
			},
		},
		{
			name: "zero detection multiplier",
			mod: func(b []byte) []byte {
				b[2] = 0
				return b
			},
		},
		{
			name: "zero my discriminator",
			mod: func(b []byte) []byte {
				clear(b[4:8])
				return b
			},
		},
		{
			name: "poll and final",
			mod: func(b []byte) []byte {
				b[1] |= flagPoll | flagFinal
				return b
			},
		},
		{
			name: "zero your discriminator up",
			mod: func(b []byte) []byte {
				clear(b[8:12])
				return b
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := must(validPacket().AppendBinary(nil))
			p, err := ParseControlPacket(tt.mod(b))
			if p != nil {
				t.Fatalf("expected nil packet, but got: %+v", p)
			}

			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

// TestControlPacketAuth covers the Simple Password Authentication Section:
// its round trip, its exact wire encoding, and the marshal and parse checks
// that guard it.
func TestControlPacketAuthRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *AuthSection
	}{
		{
			name: "one byte password",
			auth: &AuthSection{Type: AuthTypeSimplePassword, KeyID: 1, Data: []byte("x")},
		},
		{
			name: "typical password",
			auth: &AuthSection{Type: AuthTypeSimplePassword, KeyID: 7, Data: []byte("hunter2")},
		},
		{
			name: "sixteen byte password",
			auth: &AuthSection{Type: AuthTypeSimplePassword, KeyID: 255, Data: []byte("0123456789abcdef")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := validPacket()
			p.Auth = tt.auth

			b, err := p.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal packet: %v", err)
			}

			got, err := ParseControlPacket(b)
			if err != nil {
				t.Fatalf("failed to parse packet: %v", err)
			}

			if d := diff(t, p, got); d != "" {
				t.Fatalf("unexpected packet (-want +got):\n%s", d)
			}
		})
	}
}

func TestControlPacketAuthWireFormat(t *testing.T) {
	t.Parallel()

	p := &ControlPacket{
		State:             StateUp,
		DetectMultiplier:  3,
		MyDiscriminator:   0x01020304,
		YourDiscriminator: 0x05060708,
		DesiredMinTX:      300 * time.Millisecond,
		RequiredMinRX:     300 * time.Millisecond,
		Auth:              &AuthSection{Type: AuthTypeSimplePassword, KeyID: 7, Data: []byte("hunter2")},
	}

	b, err := p.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal packet: %v", err)
	}

	want := []byte{
		// Version 1, diagnostic 0.
		0x20,
		// State Up and the Authentication Present bit.
		0xc4,
		// Detection multiplier and the length: 24 plus a 10 byte section.
		0x03, 0x22,
		// My and your discriminators.
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		// 300ms, 300ms, and a declined echo in whole microseconds.
		0x00, 0x04, 0x93, 0xe0,
		0x00, 0x04, 0x93, 0xe0,
		0x00, 0x00, 0x00, 0x00,
		// Auth Type 1, Auth Len 10, Key ID 7, then "hunter2".
		0x01, 0x0a, 0x07,
		0x68, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x32,
	}

	if d := diff(t, want, b); d != "" {
		t.Fatalf("unexpected wire encoding (-want +got):\n%s", d)
	}
}

func TestControlPacketAuthAppendBinaryErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *AuthSection
	}{
		{
			name: "empty password",
			auth: &AuthSection{Type: AuthTypeSimplePassword},
		},
		{
			name: "oversize password",
			auth: &AuthSection{Type: AuthTypeSimplePassword, Data: bytes.Repeat([]byte{'a'}, 17)},
		},
		{
			name: "unsupported type",
			auth: &AuthSection{Type: AuthTypeKeyedSHA1, Data: bytes.Repeat([]byte{'a'}, 20)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := validPacket()
			p.Auth = tt.auth

			if b, err := p.AppendBinary(nil); err == nil {
				t.Fatalf("expected an error, but marshaled: %x", b)
			}
		})
	}
}

func TestParseControlPacketAuthErrors(t *testing.T) {
	t.Parallel()

	// A valid simple password packet as the base for corruption.
	base := func() []byte {
		p := validPacket()
		p.Auth = &AuthSection{Type: AuthTypeSimplePassword, KeyID: 1, Data: []byte("hunter2")}
		return must(p.AppendBinary(nil))
	}

	tests := []struct {
		name string
		mod  func(b []byte) []byte
	}{
		{
			name: "auth length field disagrees",
			mod: func(b []byte) []byte {
				b[25]++
				return b
			},
		},
		{
			name: "unsupported auth type",
			mod: func(b []byte) []byte {
				b[24] = byte(AuthTypeKeyedSHA1)
				return b
			},
		},
		{
			name: "section header truncated",
			mod: func(b []byte) []byte {
				// A bit set, length claims 25 bytes, only the type byte
				// present: too short for the section's own header.
				b = b[:packetLen+1]
				b[3] = packetLen + 1
				return b
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := ParseControlPacket(tt.mod(base()))
			if p != nil {
				t.Fatalf("expected nil packet, but got: %+v", p)
			}

			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s    State
		want string
	}{
		{s: StateAdminDown, want: "AdminDown"},
		{s: StateDown, want: "Down"},
		{s: StateInit, want: "Init"},
		{s: StateUp, want: "Up"},
		{s: State(0xff), want: "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDiagnosticString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		d    Diagnostic
		want string
	}{
		{d: DiagNone, want: "No Diagnostic"},
		{d: DiagControlDetectionTimeExpired, want: "Control Detection Time Expired"},
		{d: DiagEchoFunctionFailed, want: "Echo Function Failed"},
		{d: DiagNeighborSignaledSessionDown, want: "Neighbor Signaled Session Down"},
		{d: DiagForwardingPlaneReset, want: "Forwarding Plane Reset"},
		{d: DiagPathDown, want: "Path Down"},
		{d: DiagConcatenatedPathDown, want: "Concatenated Path Down"},
		{d: DiagAdministrativelyDown, want: "Administratively Down"},
		{d: DiagReverseConcatenatedPathDown, want: "Reverse Concatenated Path Down"},
		{d: DiagMisConnectivityDefect, want: "Mis-connectivity Defect"},
		{d: Diagnostic(0xff), want: "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzParseControlPacket(f *testing.F) {
	// Seed with valid packets covering each state and flag, plus raw bytes
	// no marshaler produces.
	seeds := []*ControlPacket{
		validPacket(),
		{
			State:            StateDown,
			DetectMultiplier: 1,
			MyDiscriminator:  1,
		},
		{
			Diagnostic:       DiagAdministrativelyDown,
			State:            StateAdminDown,
			DetectMultiplier: 3,
			MyDiscriminator:  2,
			DesiredMinTX:     time.Second,
		},
		{
			State:                   StateInit,
			Final:                   true,
			Demand:                  true,
			ControlPlaneIndependent: true,
			DetectMultiplier:        3,
			MyDiscriminator:         3,
			YourDiscriminator:       4,
			DesiredMinTX:            300 * time.Millisecond,
			RequiredMinRX:           300 * time.Millisecond,
			RequiredMinEchoRX:       50 * time.Millisecond,
		},
		{
			State:             StateUp,
			Poll:              true,
			DetectMultiplier:  255,
			MyDiscriminator:   math.MaxUint32,
			YourDiscriminator: math.MaxUint32,
			DesiredMinTX:      math.MaxUint32 * time.Microsecond,
			RequiredMinRX:     math.MaxUint32 * time.Microsecond,
		},
		{
			State:             StateUp,
			DetectMultiplier:  3,
			MyDiscriminator:   5,
			YourDiscriminator: 6,
			Auth:              &AuthSection{Type: AuthTypeSimplePassword, KeyID: 1, Data: []byte("hunter2")},
		},
	}

	for _, p := range seeds {
		b, err := p.AppendBinary(nil)
		if err != nil {
			f.Fatalf("failed to marshal seed: %v", err)
		}

		f.Add(b)
	}

	f.Add(bytes.Repeat([]byte{0xff}, packetLen))

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseControlPacket(b)
		if err != nil {
			if p != nil {
				t.Fatal("non-nil packet with non-nil error")
			}

			return
		}

		// Marshal and parse apply the same validation, so a parsed packet
		// always re-marshals; and every wire bit is represented in the
		// struct, so it must reproduce the input exactly.
		b1, err := p.AppendBinary(nil)
		if err != nil {
			t.Fatalf("a parsed packet must re-marshal: %v", err)
		}

		if !bytes.Equal(b, b1) {
			t.Fatalf("marshaling a parsed packet is not the identity:\n b:  %x\n b1: %x", b, b1)
		}
	})
}

// validPacket returns a packet which every marshal and parse check accepts,
// for tests which break one property at a time.
func validPacket() *ControlPacket {
	return &ControlPacket{
		State:             StateUp,
		DetectMultiplier:  3,
		MyDiscriminator:   0x01020304,
		YourDiscriminator: 0x05060708,
		DesiredMinTX:      300 * time.Millisecond,
		RequiredMinRX:     300 * time.Millisecond,
	}
}

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()
	return cmp.Diff(want, got)
}
