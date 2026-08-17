// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The remote-card arm of the Card Module.
//!
//! A remote card has no reader and no APDU stream: its certificate and its
//! signatures come from the holder's phone over the local pipe served by the
//! `ReFineID` app (`refineid-remote-card-pipe`). This arm is deliberately not a
//! `CardTransport` -- there are no protocol bytes to tunnel. It answers the
//! three operations the design note names: read the authentication
//! certificate, report the PIN as externally verified, and sign a digest.
//!
//! Presence is a synthetic ATR the virtual reader will present when a paired
//! phone is available (that reader is separate, later work). Until it lands,
//! `CardAcquireContext` recognizes [`REMOTE_READER_ATR`] and builds this arm;
//! the settings application and CLI reach the same pipe directly.
//!
//! PIN entry never happens on Windows. The card model reports `ExternalPinType`
//! and `CardAuthenticateEx` succeeds without collecting a PIN; the holder
//! approves and enters PIN1 on the phone when the signature runs.

#![expect(
    clippy::redundant_pub_crate,
    reason = "this private module uses pub(crate) consistently for its crate-internal remote-arm surface, matching the sibling modules"
)]

use core::ffi::c_void;
use std::io::{Read, Write};

use refineid_remote_card_pipe::{
    KeyProfile, PIPE_NAME, Request, Response, SignatureAlgorithm, exchange,
};

use crate::cardmod::KeyAlgorithm;
use refineid_lib_core::x509::EcCurve;

/// The synthetic ATR the virtual reader presents for a reachable remote card.
/// `CardAcquireContext` matches it to choose this arm. The bytes are a private,
/// non-ISO historical pattern that no physical FINEID card carries, so it never
/// collides with a real card's ATR.
pub(crate) const REMOTE_READER_ATR: [u8; 8] = [0x3B, 0x8F, 0x52, 0x46, 0x49, 0x44, 0x52, 0x21];

/// The reader name the virtual reader will publish, for diagnostics and the
/// later driver's device registration.
pub(crate) const REMOTE_READER_NAME: &str = "ReFineID Remote Reader";

/// How many times a sign retries when the live pairing is momentarily busy
/// with the app's liveness check before giving up.
const BUSY_RETRIES: u32 = 20;

/// The signature padding the Base CSP asked for, reduced to the two shapes the
/// card performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignPadding {
    /// RSA PKCS #1 v1.5, or ECDSA (which has no padding).
    Pkcs1OrEcdsa,
    /// RSA PSS.
    Pss,
}

/// A remote-card failure, mapped to a Card Module status word by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteError {
    /// No paired card is reachable: the pipe is absent or reported unavailable.
    NoCard,
    /// The live session is busy after every retry.
    Busy,
    /// The holder denied the request on the phone.
    Denied,
    /// The request is not one the remote card can honor.
    Unsupported,
    /// The pipe framing or the peer misbehaved.
    Protocol,
}

/// The remote card. It holds no connection: each request opens the pipe, does
/// one exchange, and closes, so a dropped app or ended pairing surfaces as a
/// clean [`RemoteError`] on the next call rather than a stale handle.
pub(crate) struct RemoteCard;

impl RemoteCard {
    /// Fetch the authentication certificate (DER) for the card model.
    pub(crate) fn fetch_auth_certificate() -> Result<Vec<u8>, RemoteError> {
        match Self::request(&Request::AuthCertificate)? {
            Response::Certificate(der) => Ok(der),
            Response::Unavailable => Err(RemoteError::NoCard),
            _ => Err(RemoteError::Protocol),
        }
    }

    /// Sign `digest` with the given key and algorithm on the phone. Returns the
    /// card's raw signature bytes; the caller adapts the byte order Windows
    /// expects. Retries a busy session a bounded number of times.
    pub(crate) fn sign(
        key_profile: KeyProfile,
        algorithm: SignatureAlgorithm,
        digest: Vec<u8>,
    ) -> Result<Vec<u8>, RemoteError> {
        let request = Request::SignDigest {
            key_profile,
            algorithm,
            digest,
        };
        for _attempt in 0..BUSY_RETRIES {
            match Self::request(&request)? {
                Response::Signature(bytes) => return Ok(bytes),
                Response::Busy => sleep_briefly(),
                Response::Denied => return Err(RemoteError::Denied),
                Response::Unavailable => return Err(RemoteError::NoCard),
                Response::Protocol => return Err(RemoteError::Unsupported),
                Response::Status(_) | Response::Certificate(_) => {
                    return Err(RemoteError::Protocol);
                }
            }
        }
        Err(RemoteError::Busy)
    }

    /// One request/response over a fresh pipe connection.
    fn request(request: &Request) -> Result<Response, RemoteError> {
        let mut pipe = PipeConnection::open()?;
        exchange(&mut pipe, request).map_err(|_error| RemoteError::Protocol)
    }
}

/// Choose the RAPP key profile and algorithm for a Windows sign request, given
/// the container's key and the requested padding and digest length. `None` if
/// the combination is outside the registry the card serves.
pub(crate) fn map_sign(
    key_alg: KeyAlgorithm,
    padding: SignPadding,
    digest_len: usize,
) -> Option<(KeyProfile, SignatureAlgorithm)> {
    match key_alg {
        KeyAlgorithm::Rsa { bits } => {
            let profile = match bits {
                2048 => KeyProfile::Rsa2048,
                3072 => KeyProfile::Rsa3072,
                _ => return None,
            };
            let algorithm = match (padding, digest_len) {
                (SignPadding::Pss, 32) => SignatureAlgorithm::RsaPssSha256,
                (SignPadding::Pkcs1OrEcdsa, 32) => SignatureAlgorithm::RsaPkcs1Sha256,
                (SignPadding::Pkcs1OrEcdsa, 48) => SignatureAlgorithm::RsaPkcs1Sha384,
                (SignPadding::Pkcs1OrEcdsa, 64) => SignatureAlgorithm::RsaPkcs1Sha512,
                _ => return None,
            };
            Some((profile, algorithm))
        }
        KeyAlgorithm::Ec(curve) => {
            if padding == SignPadding::Pss {
                return None;
            }
            let profile = match curve {
                EcCurve::Secp256r1 => KeyProfile::EcdsaP256,
                EcCurve::Secp384r1 => KeyProfile::EcdsaP384,
                _ => return None,
            };
            let algorithm = match digest_len {
                28 => SignatureAlgorithm::EcdsaSha224,
                32 => SignatureAlgorithm::EcdsaSha256,
                48 => SignatureAlgorithm::EcdsaSha384,
                64 => SignatureAlgorithm::EcdsaSha512,
                _ => return None,
            };
            Some((profile, algorithm))
        }
    }
}

/// Whether `atr` is the synthetic ATR that selects the remote arm.
pub(crate) fn is_remote_atr(atr: &[u8]) -> bool {
    atr == REMOTE_READER_ATR
}

/// Sleep between busy retries. The app's liveness check holds the session for
/// only a moment, so a short wait clears the contention.
fn sleep_briefly() {
    std::thread::sleep(std::time::Duration::from_millis(150));
}

// ----- Windows named-pipe client -----

type Handle = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security_attributes: *mut c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn ReadFile(
        handle: Handle,
        buffer: *mut u8,
        to_read: u32,
        read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn WriteFile(
        handle: Handle,
        buffer: *const u8,
        to_write: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE_VALUE: isize = -1;

/// Encode a path as a NUL-terminated UTF-16 string for the wide Win32 API.
fn wide(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(core::iter::once(0)).collect()
}

/// One open client connection to the app's remote-card pipe.
struct PipeConnection {
    handle: Handle,
}

impl PipeConnection {
    fn open() -> Result<Self, RemoteError> {
        let name = wide(PIPE_NAME);
        // SAFETY: opening the local pipe as a client; the handle is owned by
        // this value and closed on drop.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        if handle as isize == INVALID_HANDLE_VALUE {
            return Err(RemoteError::NoCard);
        }
        Ok(Self { handle })
    }
}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        // SAFETY: a handle this value owns, closed exactly once.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let to_read = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut read = 0_u32;
        // SAFETY: `handle` is an open pipe; `buffer` is valid for `to_read`.
        let ok = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr(),
                to_read,
                &raw mut read,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        Ok(read as usize)
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let to_write = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut written = 0_u32;
        // SAFETY: `handle` is an open pipe; `buffer` is valid for `to_write`.
        let ok = unsafe {
            WriteFile(
                self.handle,
                buffer.as_ptr(),
                to_write,
                &raw mut written,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{REMOTE_READER_ATR, SignPadding, is_remote_atr, map_sign};
    use crate::cardmod::KeyAlgorithm;
    use refineid_lib_core::x509::EcCurve;
    use refineid_remote_card_pipe::{KeyProfile, SignatureAlgorithm};

    #[test]
    fn rsa_maps_padding_and_digest_length() {
        assert_eq!(
            map_sign(
                KeyAlgorithm::Rsa { bits: 3072 },
                SignPadding::Pkcs1OrEcdsa,
                32
            ),
            Some((KeyProfile::Rsa3072, SignatureAlgorithm::RsaPkcs1Sha256))
        );
        assert_eq!(
            map_sign(
                KeyAlgorithm::Rsa { bits: 3072 },
                SignPadding::Pkcs1OrEcdsa,
                48
            ),
            Some((KeyProfile::Rsa3072, SignatureAlgorithm::RsaPkcs1Sha384))
        );
        assert_eq!(
            map_sign(KeyAlgorithm::Rsa { bits: 2048 }, SignPadding::Pss, 32),
            Some((KeyProfile::Rsa2048, SignatureAlgorithm::RsaPssSha256))
        );
        // PSS is only registered for SHA-256.
        assert_eq!(
            map_sign(KeyAlgorithm::Rsa { bits: 3072 }, SignPadding::Pss, 48),
            None
        );
        // An unsupported modulus.
        assert_eq!(
            map_sign(
                KeyAlgorithm::Rsa { bits: 4096 },
                SignPadding::Pkcs1OrEcdsa,
                32
            ),
            None
        );
    }

    #[test]
    fn ecdsa_maps_by_curve_and_digest_and_rejects_pss() {
        assert_eq!(
            map_sign(
                KeyAlgorithm::Ec(EcCurve::Secp256r1),
                SignPadding::Pkcs1OrEcdsa,
                32
            ),
            Some((KeyProfile::EcdsaP256, SignatureAlgorithm::EcdsaSha256))
        );
        assert_eq!(
            map_sign(
                KeyAlgorithm::Ec(EcCurve::Secp384r1),
                SignPadding::Pkcs1OrEcdsa,
                48
            ),
            Some((KeyProfile::EcdsaP384, SignatureAlgorithm::EcdsaSha384))
        );
        assert_eq!(
            map_sign(KeyAlgorithm::Ec(EcCurve::Secp256r1), SignPadding::Pss, 32),
            None
        );
    }

    #[test]
    fn only_the_synthetic_atr_selects_the_remote_arm() {
        assert!(is_remote_atr(&REMOTE_READER_ATR));
        assert!(!is_remote_atr(&[0x3B, 0x00]));
        assert!(!is_remote_atr(&[]));
    }
}
