# ReFineID for Windows

Public, native Windows middleware for Finnish FINEID citizen cards.

The first component is a Rust smart-card minidriver. It implements the
Microsoft Card Module ABI and connects the Windows Base Smart Card CSP/KSP
stack to a FINEID card through PC/SC.

```text
Edge / Chrome / Schannel / .NET / VPN / RDP / EAP-TLS
                         |
              Microsoft Base CSP/KSP
                         |
             refineid_minidriver.dll
                         |
                       PC/SC
                         |
                    FINEID card
```

This is a user-mode DLL, not a kernel driver. No C++ compatibility layer is
used. Windows requires a small `unsafe extern "system"` boundary for the Card
Module function table and caller-owned pointers; the protocol, parsing, PIN
handling, and cryptographic state machines remain safe Rust.

Status: alpha. The imported reference implementation has been hardware-tested
with FINEID S4-1 v3.1 and v4.0 cards, including:

- authentication and qualified-signature certificate enumeration;
- PIN1 and PIN2 verification;
- RSA-3072 PKCS#1 v1.5 and RSA-PSS signing;
- ECDSA P-384 signing;
- Windows certificate propagation and Edge client authentication.

The public repository rebuilds and revalidates those paths. Hardware acceptance
still requires a real card and reader; CI cannot replace that proof.

### Contactless NFC status

The browser and Windows KSP tests above currently use the contact interface.
The FINEID S4-1 v4.0 card and an ACS ACR1581 PICC reader have separately passed
the shared Rust core's contactless `EF.CardAccess`, PACE, and protected eMRTD
read on Windows.

The alpha minidriver does not yet expose that path to Windows applications:

- Windows receives a PC/SC contactless pseudo-ATR instead of the card's contact
  ATR, so the current installer registration does not select this minidriver.
- The card keeps PKCS #15 certificates and keys behind PACE on the contactless
  interface. The minidriver needs a secure, card-bound CAN provisioning flow
  before `CardAcquireContext` can read those certificates.

Registering the pseudo-ATR alone is not a fix: it would select the DLL, but the
first certificate read would still fail before PACE. Use the contact interface
for Edge, Chrome, Schannel, and CNG until the Windows NFC prime flow is present.

## Build

Requirements:

- Windows 11;
- Rust 1.97.1 through `rustup`;
- Visual Studio 2022 Build Tools with the MSVC C++ workload.

Build both supported architectures:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build.ps1 -Architecture x64,arm64
```

Outputs:

```text
dist/x64/refineid_minidriver.dll
dist/arm64/refineid_minidriver.dll
dist/SHA256SUMS
```

Run the host checks:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
```

## Development install

Production Windows binaries must be Authenticode-signed. Do not distribute an
unsigned or test-signed DLL to end users.

For an isolated development machine with Windows test-signing policy configured,
build the matching architecture and run an elevated PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/install-dev.ps1 `
  -DllPath dist/x64/refineid_minidriver.dll `
  -AllowUnsigned
```

Validate with a reader and card:

```powershell
certutil -scinfo
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/test-card-sign.ps1
```

Remove the development installation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/uninstall-dev.ps1
```

## Security boundary

- PIN values and private card material must never be logged.
- Secret byte containers are zeroized on drop.
- `unsafe_code` is denied workspace-wide and explicitly expected only in the
  Windows ABI adapter.
- Every operation is bounded by the card and Windows API result; unsupported
  Card Module operations fail closed.
- Release optimization keeps integer overflow checks enabled.
- x64 and ARM64 release DLLs enable high-entropy ASLR, NX, and Windows
  Control Flow Guard.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[CONTRIBUTING.md](CONTRIBUTING.md) for the public review rules.

## License

Apache License 2.0.
