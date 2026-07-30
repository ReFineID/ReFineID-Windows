# ReFineID Windows agent rules

- ASCII only in source and project prose unless a protocol fixture requires
  exact UTF-8.
- No AI attribution in commits.
- Never log or commit PIN values, personal certificates, identity codes, or
  private traces.
- Safe Rust owns protocol, parsing, and secret handling. Keep `unsafe` inside
  the Windows Card Module or PC/SC boundary.
- Every Windows ABI pointer access must validate nullability and length before
  dereferencing.
- Use named constants instead of naked protocol or status values.
- Verify claims from Microsoft, DVV, ICAO, eIDAS, or another primary source.
- Compile, lint, and test before committing. Hardware claims additionally
  require a real reader and card.
- Do not publish unsigned or test-signed binaries as production releases.
