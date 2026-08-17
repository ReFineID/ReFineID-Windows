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

Status: beta. The imported reference implementation has been hardware-tested
with FINEID S4-1 v3.1 and v4.0 cards, including:

- authentication and qualified-signature certificate enumeration;
- PIN1 and PIN2 verification;
- RSA-3072 PKCS#1 v1.5 and RSA-PSS signing;
- ECDSA P-384 signing;
- Windows certificate propagation and Edge client authentication.

This public port has revalidated the contact path locally with a real FINEID
S4-1 v3.1 RSA card and an ACR39U reader:

- `certutil -scinfo -silent` selected the ReFineID Card Module without an
  unknown-card error;
- the settings app restored PIN2 with the recovery code and the card reported
  five attempts plus the changed-from-factory flag afterwards; and
- Microsoft KSP calls completed and locally verified RSA-3072 PKCS #1 v1.5 and
  RSA-PSS signatures with both PIN1 and PIN2.

CI still cannot replace that hardware proof, and the separate NFC acceptance
boundary is documented below.

### Contactless NFC status

The browser and Windows KSP acceptance tests above currently use the contact
interface. The repository now contains an experimental end-to-end contactless
path:

- ReFineID Settings proves the printed six-digit CAN with the Apple-reference
  `SELECT MF`, PACE, and protected PKCS #15 sequence before saving it;
- only the CAN is stored in the current Windows user's Credential Manager,
  keyed by the complete PC/SC contactless ATR; no PIN or PUK is stored;
- the minidriver retrieves that CAN before certificate discovery and opens a
  fresh PACE secure-messaging session whenever Windows replaces the PC/SC
  handle; and
- the development installer can register the exact observed contactless ATR
  with an all-bytes mask.

The FINEID S4-1 v4.0 PACE and protected-read sequence has passed separately with
an ACS ACR1581 PICC reader. The new Windows Credential Manager-to-minidriver
handoff still needs real-reader acceptance before contactless browser use can be
called supported. Contact mode remains the supported path meanwhile.

### ReFineID Settings

`apps/ReFineID.Settings` is a native WinUI 3 desktop settings application with
a narrow C# UI and a Rust card-service DLL. It can:

- inspect a card and show counter-safe PIN1, PIN2, and recovery status;
- change PIN1 or PIN2;
- restore either PIN with the recovery code;
- activate a new card while binding every modifying command to the inspected
  reader and card serial; and
- prove and save the printed CAN for the experimental contactless path.

PIN, recovery, and activation values cross the FFI as bounded byte arrays, are
zeroized in the Rust domain types, and never enter the JSON response or event
stream. The CAN is saved only after a live PACE proof. No PIN or recovery code
is placed in Windows Credential Manager.

## Build

Requirements:

- Windows 11;
- Rust 1.97.1 through `rustup`;
- .NET SDK 10 for the WinUI apps;
- Visual Studio 2026 (Community or Build Tools) with the *Desktop development
  with C++* workload, including the MSVC build tools for the host architecture.

See [docs/toolchain.md](docs/toolchain.md) for the architecture-specific tool
requirements and for cross-building the Windows target from macOS or Linux.

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

Build the unpackaged x64 settings app:

```powershell
dotnet build apps/ReFineID.Settings/ReFineID.Settings.csproj `
  -c Release `
  -p:Platform=x64 `
  -p:WindowsPackageType=None `
  -p:EnableMsixTooling=false
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

For an experimental contactless install, first read the complete ATR reported
for the ACR1581 PICC interface with `certutil -scinfo`. Register that exact
value rather than a family-wide mask:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/install-dev.ps1 `
  -DllPath dist/x64/refineid_minidriver.dll `
  -ContactlessAtrHex '<exact ATR from certutil -scinfo>' `
  -AllowUnsigned
```

Then use ReFineID Settings once to prove and save the card's printed CAN. The
CAN argument is deliberately not accepted by the installer or command line.

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

## Remote authorization (RAPP)

`crates/refineid-rapp-core` implements the requester role of the Remote
Authorization Proxy Protocol, review draft 26.8.17.213, vendored verbatim
under `docs/protocol/`. RAPP lets this Windows machine use an identity
card held by the holder's phone: pairing starts from a high-entropy QR
offer, the one Noise pairing handshake creates a mutually authenticated
channel that continues as the live session, each operation is typed and
explicitly approved on the phone, and no CAN, PIN, or private key ever
reaches the requester. A pairing is that single live connection — its keys
exist only in memory, every close ends the session and the pairing
together, and recovery is a fresh QR ceremony. The crate carries the
deterministic CBOR wire form, the handshake, the full message schema, the
transcribed state-machine tables the engine is checked against, and a
loopback conformance suite. The crate also implements the
`fi.refineid.stream.v1` transport profile: the listener, the connection
preamble, and the offer candidate parameters, replayed against the vendored
conformance corpus. `refineid-rapp-cli` is the development requester that
proves the live path against a phone proxy. The phone-side proxies live in
their own platform repositories; the bridge from the minidriver to a
RAPP-backed remote card is future work here.

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
