# CLAUDE.md

Guidance for AI agents working in this repository.

## Verification

Run these on every Go change, alongside `go build` and `go test`:

- `gofumpt -l .` (CI enforces gofumpt; keep stderr visible so a bad path
  can't look like a clean run)
- `go vet ./...`
- `staticcheck ./...` (CI enforces it; if the system binary is too old for
  the toolchain, use `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`)
- `gopls check -severity=hint <changed files>` (catches unusedfunc,
  modernize, typeargs, and other hint-level findings vet and staticcheck
  miss)

This repository is a single module: `./...` from the root covers
everything.

## Code style

Blank lines:

- Leave an empty line after a closing brace and after a `var (` / `const (`
  block when another statement or declaration follows at the same indent
  level. Keep `}`, `)`, `case`, `default:`, and `else` continuations tight
  against what precedes them.
- Break dense bodies, especially tests, with blank lines at logical seams:
  between multi-line handler fields in a config struct literal, between one
  actor's cluster of steps and the next, before non-blocking `select`
  assertion checks and final verdict assertions, and between constructing a
  fixture and the next setup statement.
- A single multi-line struct literal is one logical unit: never split it
  mid-literal.

Declaration layout:

- A type and all of its methods stay contiguous. Supporting enums and codes
  go before the type that uses them. Constructor/decoder pairs sit together
  (e.g. `ControlPacket.AppendBinary` beside `ParseControlPacket`).
- Paired values described by one doc comment share one declaration
  (`DesiredMinTX, RequiredMinRX time.Duration`). A doc comment attaches to
  the declaration, so separate lines leave every name after the first
  undocumented in go doc and IDE hover.
- Exception: files deliberately organized by theme or flow keep that layout
  (e.g. `udp.go` in dial-then-transport order).
- Keep groups of one-line method stubs compact and aligned, with no blank
  lines between them.

Exported doc comments:

- State the contract directly. ADR references belong only in unexported
  identifiers' comments and inline code comments; readers of pkg.go.dev
  cannot follow them.
- Plain prose: short sentences, no em dashes. Prefer separate sentences, a
  colon, or "such as X or Y" over parenthetical asides. Internal comments
  are exempt.

## Tests

- Never sleep in tests. Every awaited condition must be signaled; poll
  loops with sleep intervals count as sleeping.
- Test scenarios, not coverage. Cover paths a plausible real-world scenario
  hits, framed on behavior; 100% coverage is not a goal.
- Test helpers, rig types, and shared fixtures go at the end of test files,
  after every Test/Fuzz/Benchmark/Example function. Shared consts may stay
  at the top.
