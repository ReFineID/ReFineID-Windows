# Security

ReFineID for Windows is alpha software handling identity-card credentials.

## Reporting

Do not open a public issue for a vulnerability, PIN exposure, certificate
privacy leak, or signing-policy bypass. Use GitHub private vulnerability
reporting for this repository. If that is unavailable, contact the maintainer
listed in `Cargo.toml`.

Include the affected commit, Windows architecture, card generation, reader,
minimal reproduction, and sanitized status/APDU evidence. Never include a PIN,
private key, full personal certificate, personal identity code, or an
unredacted event log.

## Supported versions

Only the current `main` branch is supported during alpha development.

## Release policy

CI artifacts are development builds. A public end-user release requires:

- successful formatting, lint, unit-test, and x64/ARM64 release builds;
- hardware acceptance on supported FINEID card generations;
- Authenticode signing with the ReFineID production certificate;
- published SHA-256 checksums and provenance;
- a documented rollback and uninstall path.
