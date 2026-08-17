# Contributing

ReFineID is security-sensitive identity middleware. Small, reviewable changes
with evidence are preferred.

Before submitting:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
dotnet format apps/ReFineID/ReFineID.csproj --verify-no-changes
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Architecture x64,arm64
```

## Commit gate

`.github/workflows/ci.yml` is the authoritative gate: it runs formatting,
lint, tests, and the requester build on a Windows runner, and every pull
request must pass it.

Enable the local pre-commit hook once per clone so a badly formatted change
is caught before it leaves the machine:

```sh
git config core.hooksPath .githooks
```

The hook always checks `cargo fmt`. `cargo clippy` and `dotnet format` need
the Windows target and workload, so the hook runs them only on Windows; on
other hosts CI is what enforces them.

Rules:

- Never log or commit a PIN, personal certificate, identity code, or private
  card trace.
- Keep protocol and parsing logic in safe Rust.
- New `unsafe` code belongs only at a documented Windows ABI boundary and must
  state its pointer, length, ownership, and lifetime invariants.
- Replace magic protocol values with named constants and cite the primary
  specification or Windows SDK contract.
- Fail closed on malformed input and unsupported operations.
- Hardware claims require sanitized card/reader evidence.
- Do not add AI attribution trailers to commits.
