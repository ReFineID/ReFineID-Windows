# ReFineID Windows agent rules

- Source and project prose may use the ISO-8859-15 character repertoire,
  including meaningful specification symbols such as `§`; do not degrade them
  to ASCII. Store each source file in the encoding required by its toolchain
  (Rust `.rs` files must be valid UTF-8). Preserve a protocol fixture's exact
  specified byte encoding.
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
