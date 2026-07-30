# Contributing

ReFineID is security-sensitive identity middleware. Small, reviewable changes
with evidence are preferred.

Before submitting:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Architecture x64,arm64
```

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
