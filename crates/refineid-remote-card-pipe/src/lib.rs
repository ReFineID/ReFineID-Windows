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

//! Local request/response protocol for the remote-card bridge.
//!
//! The `ReFineID` app, holding a live RAPP pairing, publishes the paired card
//! to Windows over a local named pipe.
//!
//! The minidriver's remote arm connects to that pipe and asks three things:
//! the card's status, its authentication certificate, and a signature over a
//! digest. Every signature is a typed, phone-approved RAPP
//! `browser_authenticate`; the pipe never carries a CAN, a PIN, or arbitrary
//! APDU bytes, only a digest and its algorithm.
//!
//! This crate is the wire form and its framing alone. It performs no I/O of
//! its own beyond the caller-supplied [`std::io::Read`]/[`std::io::Write`],
//! so the codec and the exchange are portable and unit-tested on any host;
//! the named-pipe endpoints live in the two Windows consumers.
//!
//! Every frame is length-prefixed and every field is bounded. Decoding is
//! fail-closed: any malformed, truncated, oversized, or unknown input is a
//! [`PipeError`], never a partial or guessed value.

use std::io::{Read, Write};

/// The local named-pipe path the app serves and the minidriver dials.
///
/// One pipe per interactive user; the app and the minidriver run as the same
/// user, so the pipe's default security descriptor (creator plus system) is
/// the intended audience. The server additionally rejects remote clients.
pub const PIPE_NAME: &str = r"\\.\pipe\refineid-remote-card";

/// Largest frame body accepted in either direction, in bytes. A frame is a
/// four-byte little-endian length followed by this many body bytes at most.
pub const MAX_FRAME_BYTES: usize = 16_384;

/// Largest digest accepted in a sign request (SHA-512 is 64 bytes).
pub const MAX_DIGEST_BYTES: usize = 64;

/// Largest certificate returned (a FINEID end-entity certificate is well
/// under this).
pub const MAX_CERTIFICATE_BYTES: usize = 8_192;

/// Largest signature returned (an RSA-4096 signature is 512 bytes).
pub const MAX_SIGNATURE_BYTES: usize = 1_024;

/// Largest holder hint returned in a status reply, in UTF-8 bytes.
pub const MAX_HOLDER_BYTES: usize = 256;

// Request opcodes: the first body byte of a request frame.
const OP_STATUS: u8 = 0x01;
const OP_AUTH_CERTIFICATE: u8 = 0x02;
const OP_SIGN_DIGEST: u8 = 0x03;

// Response status codes: the first body byte of a response frame.
const STATUS_OK: u8 = 0x00;
const STATUS_BUSY: u8 = 0x01;
const STATUS_UNAVAILABLE: u8 = 0x02;
const STATUS_DENIED: u8 = 0x03;
const STATUS_PROTOCOL: u8 = 0x04;

/// The signing key a request selects. The proxy independently verifies the
/// profile against the card, so this is a hint the card confirms, never a
/// trusted assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    /// ECDSA over the P-256 curve.
    EcdsaP256,
    /// ECDSA over the P-384 curve.
    EcdsaP384,
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    Rsa3072,
}

impl KeyProfile {
    /// The registered RAPP wire name of the profile.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa_p256",
            Self::EcdsaP384 => "ecdsa_p384",
            Self::Rsa2048 => "rsa_2048",
            Self::Rsa3072 => "rsa_3072",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::EcdsaP256 => 1,
            Self::EcdsaP384 => 2,
            Self::Rsa2048 => 3,
            Self::Rsa3072 => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::EcdsaP256),
            2 => Some(Self::EcdsaP384),
            3 => Some(Self::Rsa2048),
            4 => Some(Self::Rsa3072),
            _ => None,
        }
    }
}

/// The exact signature algorithm a sign request names: a digest family is
/// not enough, since PKCS #1, PSS, and ECDSA are distinct card commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over a SHA-224 digest.
    EcdsaSha224,
    /// ECDSA over a SHA-256 digest.
    EcdsaSha256,
    /// ECDSA over a SHA-384 digest.
    EcdsaSha384,
    /// ECDSA over a SHA-512 digest.
    EcdsaSha512,
    /// RSA PKCS #1 v1.5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSA PKCS #1 v1.5 over a SHA-384 digest.
    RsaPkcs1Sha384,
    /// RSA PKCS #1 v1.5 over a SHA-512 digest.
    RsaPkcs1Sha512,
    /// RSA PSS over a SHA-256 digest.
    RsaPssSha256,
}

impl SignatureAlgorithm {
    /// The registered RAPP wire name of the algorithm.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaSha224 => "ecdsa_sha224",
            Self::EcdsaSha256 => "ecdsa_sha256",
            Self::EcdsaSha384 => "ecdsa_sha384",
            Self::EcdsaSha512 => "ecdsa_sha512",
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            Self::RsaPssSha256 => "rsa_pss_sha256",
        }
    }

    /// The exact digest length in bytes the algorithm requires.
    #[must_use]
    pub const fn digest_length(self) -> usize {
        match self {
            Self::EcdsaSha224 => 28,
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => 32,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 => 48,
            Self::EcdsaSha512 | Self::RsaPkcs1Sha512 => 64,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::EcdsaSha224 => 1,
            Self::EcdsaSha256 => 2,
            Self::EcdsaSha384 => 3,
            Self::EcdsaSha512 => 4,
            Self::RsaPkcs1Sha256 => 5,
            Self::RsaPkcs1Sha384 => 6,
            Self::RsaPkcs1Sha512 => 7,
            Self::RsaPssSha256 => 8,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::EcdsaSha224),
            2 => Some(Self::EcdsaSha256),
            3 => Some(Self::EcdsaSha384),
            4 => Some(Self::EcdsaSha512),
            5 => Some(Self::RsaPkcs1Sha256),
            6 => Some(Self::RsaPkcs1Sha384),
            7 => Some(Self::RsaPkcs1Sha512),
            8 => Some(Self::RsaPssSha256),
            _ => None,
        }
    }
}

/// One request the minidriver sends over the pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Is a paired card present, and whose is it?
    Status,
    /// The card's authentication certificate, DER-encoded.
    AuthCertificate,
    /// A signature over `digest` with the named key and algorithm.
    SignDigest {
        /// The key the signature must use.
        key_profile: KeyProfile,
        /// The exact algorithm the signature must use.
        algorithm: SignatureAlgorithm,
        /// The already-hashed input, of the algorithm's digest length.
        digest: Vec<u8>,
    },
}

/// The paired card's presence and a display hint for the holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardStatus {
    /// Whether a paired card is currently reachable.
    pub card_present: bool,
    /// A short holder hint for diagnostics; never a credential.
    pub holder: String,
}

/// One response the app returns over the pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The card's presence and holder hint.
    Status(CardStatus),
    /// The DER-encoded authentication certificate.
    Certificate(Vec<u8>),
    /// The signature bytes.
    Signature(Vec<u8>),
    /// The session is busy with another operation; retry shortly.
    Busy,
    /// No paired card is available; the pairing ended or was never present.
    Unavailable,
    /// The holder denied the request on the phone.
    Denied,
    /// The request could not be honored: unsupported, malformed, or refused.
    Protocol,
}

/// A framing or decoding failure. Every variant is terminal for the frame in
/// hand; the caller closes or retries the connection, never guesses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// The peer closed before a whole frame arrived.
    Closed,
    /// A frame body exceeded [`MAX_FRAME_BYTES`], or a field its own bound.
    TooLarge,
    /// A frame body was structurally invalid for its opcode or status.
    Malformed,
    /// The underlying reader or writer failed.
    Io,
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Closed => "the remote-card pipe closed",
            Self::TooLarge => "a remote-card frame exceeded its bound",
            Self::Malformed => "a remote-card frame was malformed",
            Self::Io => "the remote-card pipe failed",
        };
        formatter.write_str(text)
    }
}

impl core::error::Error for PipeError {}

impl Request {
    /// Encode the request as a frame body (opcode plus payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Self::Status => body.push(OP_STATUS),
            Self::AuthCertificate => body.push(OP_AUTH_CERTIFICATE),
            Self::SignDigest {
                key_profile,
                algorithm,
                digest,
            } => {
                body.push(OP_SIGN_DIGEST);
                body.push(key_profile.code());
                body.push(algorithm.code());
                body.extend_from_slice(digest);
            }
        }
        body
    }

    /// Decode a request from a frame body. Fail-closed on any deviation,
    /// including a digest whose length does not match the algorithm.
    ///
    /// # Errors
    /// [`PipeError::Malformed`] for an empty body, unknown opcode, unknown
    /// profile or algorithm code, or wrong digest length; [`PipeError::TooLarge`]
    /// for a digest past [`MAX_DIGEST_BYTES`].
    pub fn decode(body: &[u8]) -> Result<Self, PipeError> {
        let (&opcode, rest) = body.split_first().ok_or(PipeError::Malformed)?;
        match opcode {
            OP_STATUS if rest.is_empty() => Ok(Self::Status),
            OP_AUTH_CERTIFICATE if rest.is_empty() => Ok(Self::AuthCertificate),
            OP_SIGN_DIGEST => {
                let (&profile_code, rest) = rest.split_first().ok_or(PipeError::Malformed)?;
                let (&algorithm_code, digest) = rest.split_first().ok_or(PipeError::Malformed)?;
                let key_profile =
                    KeyProfile::from_code(profile_code).ok_or(PipeError::Malformed)?;
                let algorithm =
                    SignatureAlgorithm::from_code(algorithm_code).ok_or(PipeError::Malformed)?;
                if digest.len() > MAX_DIGEST_BYTES {
                    return Err(PipeError::TooLarge);
                }
                if digest.len() != algorithm.digest_length() {
                    return Err(PipeError::Malformed);
                }
                Ok(Self::SignDigest {
                    key_profile,
                    algorithm,
                    digest: digest.to_vec(),
                })
            }
            _ => Err(PipeError::Malformed),
        }
    }
}

impl Response {
    /// Encode the response as a frame body (status byte plus payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Self::Status(card) => {
                body.push(STATUS_OK);
                body.push(u8::from(card.card_present));
                let holder = card.holder.as_bytes();
                let len = u16::try_from(holder.len().min(MAX_HOLDER_BYTES)).unwrap_or(u16::MAX);
                body.extend_from_slice(&len.to_le_bytes());
                body.extend_from_slice(holder.get(..usize::from(len)).unwrap_or_default());
            }
            Self::Certificate(der) => {
                body.push(STATUS_OK);
                body.extend_from_slice(der);
            }
            Self::Signature(signature) => {
                body.push(STATUS_OK);
                body.extend_from_slice(signature);
            }
            Self::Busy => body.push(STATUS_BUSY),
            Self::Unavailable => body.push(STATUS_UNAVAILABLE),
            Self::Denied => body.push(STATUS_DENIED),
            Self::Protocol => body.push(STATUS_PROTOCOL),
        }
        body
    }

    /// Decode a response for `request` from a frame body. The request kind
    /// selects how an OK payload is read, so a status reply is never confused
    /// with a certificate or a signature.
    ///
    /// # Errors
    /// [`PipeError::Malformed`] for an empty body, unknown status, or a
    /// structurally invalid OK payload; [`PipeError::TooLarge`] for a payload
    /// past its field bound.
    pub fn decode(request: &Request, body: &[u8]) -> Result<Self, PipeError> {
        let (&code, rest) = body.split_first().ok_or(PipeError::Malformed)?;
        match code {
            STATUS_OK => Self::decode_ok(request, rest),
            STATUS_BUSY if rest.is_empty() => Ok(Self::Busy),
            STATUS_UNAVAILABLE if rest.is_empty() => Ok(Self::Unavailable),
            STATUS_DENIED if rest.is_empty() => Ok(Self::Denied),
            STATUS_PROTOCOL if rest.is_empty() => Ok(Self::Protocol),
            _ => Err(PipeError::Malformed),
        }
    }

    fn decode_ok(request: &Request, rest: &[u8]) -> Result<Self, PipeError> {
        match request {
            Request::Status => {
                let (&present, rest) = rest.split_first().ok_or(PipeError::Malformed)?;
                let present = match present {
                    0 => false,
                    1 => true,
                    _ => return Err(PipeError::Malformed),
                };
                let (len_bytes, holder_bytes) =
                    rest.split_at_checked(2).ok_or(PipeError::Malformed)?;
                let len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
                if len > MAX_HOLDER_BYTES || holder_bytes.len() != len {
                    return Err(PipeError::Malformed);
                }
                let holder = String::from_utf8(holder_bytes.to_vec())
                    .map_err(|_invalid| PipeError::Malformed)?;
                Ok(Self::Status(CardStatus {
                    card_present: present,
                    holder,
                }))
            }
            Request::AuthCertificate => {
                if rest.len() > MAX_CERTIFICATE_BYTES {
                    return Err(PipeError::TooLarge);
                }
                if rest.is_empty() {
                    return Err(PipeError::Malformed);
                }
                Ok(Self::Certificate(rest.to_vec()))
            }
            Request::SignDigest { .. } => {
                if rest.len() > MAX_SIGNATURE_BYTES {
                    return Err(PipeError::TooLarge);
                }
                if rest.is_empty() {
                    return Err(PipeError::Malformed);
                }
                Ok(Self::Signature(rest.to_vec()))
            }
        }
    }
}

/// Write one length-prefixed frame body to `writer`.
///
/// # Errors
/// [`PipeError::TooLarge`] if `body` exceeds [`MAX_FRAME_BYTES`];
/// [`PipeError::Io`] if the write fails.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> Result<(), PipeError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(PipeError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_overflow| PipeError::TooLarge)?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|_error| PipeError::Io)?;
    writer.write_all(body).map_err(|_error| PipeError::Io)?;
    writer.flush().map_err(|_error| PipeError::Io)?;
    Ok(())
}

/// Read one length-prefixed frame body from `reader`.
///
/// # Errors
/// [`PipeError::Closed`] on end of input before a whole frame;
/// [`PipeError::TooLarge`] if the announced length exceeds [`MAX_FRAME_BYTES`];
/// [`PipeError::Io`] if the read fails.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, PipeError> {
    let mut len_bytes = [0_u8; 4];
    read_exact(reader, &mut len_bytes)?;
    let len =
        usize::try_from(u32::from_le_bytes(len_bytes)).map_err(|_overflow| PipeError::TooLarge)?;
    if len > MAX_FRAME_BYTES {
        return Err(PipeError::TooLarge);
    }
    let mut body = vec![0_u8; len];
    read_exact(reader, &mut body)?;
    Ok(body)
}

/// Read exactly `buffer.len()` bytes, mapping a short read to [`PipeError::Closed`].
fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), PipeError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Err(PipeError::Closed),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_error) => return Err(PipeError::Io),
        }
    }
    Ok(())
}

/// Send `request` over `io` and read the matching response. One round trip.
///
/// # Errors
/// Any [`PipeError`] from framing, or a response body that does not decode for
/// `request`.
pub fn exchange<T: Read + Write>(io: &mut T, request: &Request) -> Result<Response, PipeError> {
    write_frame(io, &request.encode())?;
    let body = read_frame(io)?;
    Response::decode(request, &body)
}

/// Read one request from `io`, hand it to `handle`, and write the response.
///
/// Returns the request served, or a [`PipeError`] (including [`PipeError::Closed`]
/// at end of input) so a server loop can stop cleanly.
///
/// # Errors
/// Any [`PipeError`] from framing or decoding. A structurally invalid request
/// is answered with [`Response::Protocol`] and returns [`PipeError::Malformed`]
/// so the caller can close the connection.
pub fn serve_one<T, F>(io: &mut T, handle: F) -> Result<Request, PipeError>
where
    T: Read + Write,
    F: FnOnce(&Request) -> Response,
{
    let body = read_frame(io)?;
    match Request::decode(&body) {
        Ok(request) => {
            let response = handle(&request);
            write_frame(io, &response.encode())?;
            Ok(request)
        }
        Err(error) => {
            let _ignored = write_frame(io, &Response::Protocol.encode());
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CardStatus, KeyProfile, MAX_FRAME_BYTES, PipeError, Request, Response, SignatureAlgorithm,
        exchange, read_frame, serve_one, write_frame,
    };
    use std::io::{Cursor, Read, Write};

    /// An in-memory byte stream: reads drain `inbox`, writes append to `outbox`.
    /// Enough to drive both the client `exchange` and the server `serve_one`
    /// over pre-primed and captured buffers.
    struct MemStream {
        inbox: Cursor<Vec<u8>>,
        outbox: Vec<u8>,
    }

    impl MemStream {
        fn new(inbox: Vec<u8>) -> Self {
            Self {
                inbox: Cursor::new(inbox),
                outbox: Vec::new(),
            }
        }
    }

    impl Read for MemStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.inbox.read(buffer)
        }
    }

    impl Write for MemStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.outbox.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn round_trip_request(request: &Request) {
        let decoded = Request::decode(&request.encode()).expect("request decodes");
        assert_eq!(&decoded, request);
    }

    fn round_trip_response(request: &Request, response: &Response) {
        let decoded = Response::decode(request, &response.encode()).expect("response decodes");
        assert_eq!(&decoded, response);
    }

    #[test]
    fn every_request_round_trips() {
        round_trip_request(&Request::Status);
        round_trip_request(&Request::AuthCertificate);
        round_trip_request(&Request::SignDigest {
            key_profile: KeyProfile::Rsa3072,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![7_u8; 32],
        });
        round_trip_request(&Request::SignDigest {
            key_profile: KeyProfile::EcdsaP384,
            algorithm: SignatureAlgorithm::EcdsaSha384,
            digest: vec![9_u8; 48],
        });
    }

    #[test]
    fn every_response_round_trips_against_its_request() {
        round_trip_response(
            &Request::Status,
            &Response::Status(CardStatus {
                card_present: true,
                holder: "Petri".to_owned(),
            }),
        );
        round_trip_response(
            &Request::AuthCertificate,
            &Response::Certificate(vec![1, 2, 3]),
        );
        round_trip_response(
            &Request::SignDigest {
                key_profile: KeyProfile::Rsa3072,
                algorithm: SignatureAlgorithm::RsaPssSha256,
                digest: vec![0_u8; 32],
            },
            &Response::Signature(vec![4_u8; 384]),
        );
        for status in [
            Response::Busy,
            Response::Unavailable,
            Response::Denied,
            Response::Protocol,
        ] {
            round_trip_response(&Request::Status, &status);
        }
    }

    #[test]
    fn sign_digest_rejects_wrong_length_digest() {
        let body = Request::SignDigest {
            key_profile: KeyProfile::Rsa3072,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![0_u8; 31],
        }
        .encode();
        assert_eq!(Request::decode(&body), Err(PipeError::Malformed));
    }

    #[test]
    fn decode_rejects_empty_and_unknown() {
        assert_eq!(Request::decode(&[]), Err(PipeError::Malformed));
        assert_eq!(Request::decode(&[0xFF]), Err(PipeError::Malformed));
        assert_eq!(
            Request::decode(&[0x01, 0x00]),
            Err(PipeError::Malformed),
            "status opcode with trailing bytes"
        );
        assert_eq!(
            Response::decode(&Request::Status, &[]),
            Err(PipeError::Malformed)
        );
        assert_eq!(
            Response::decode(&Request::Status, &[0x09]),
            Err(PipeError::Malformed),
            "unknown status code"
        );
    }

    #[test]
    fn status_reply_rejects_bad_present_byte_and_length() {
        // present byte 2 is neither false nor true.
        let bad_present = [0x00, 0x02, 0x00, 0x00];
        assert_eq!(
            Response::decode(&Request::Status, &bad_present),
            Err(PipeError::Malformed)
        );
        // announced holder length 5 with no holder bytes.
        let bad_len = [0x00, 0x01, 0x05, 0x00];
        assert_eq!(
            Response::decode(&Request::Status, &bad_len),
            Err(PipeError::Malformed)
        );
    }

    #[test]
    fn certificate_and_signature_reject_empty_ok_payload() {
        assert_eq!(
            Response::decode(&Request::AuthCertificate, &[0x00]),
            Err(PipeError::Malformed)
        );
        let sign = Request::SignDigest {
            key_profile: KeyProfile::Rsa3072,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![0_u8; 32],
        };
        assert_eq!(Response::decode(&sign, &[0x00]), Err(PipeError::Malformed));
    }

    #[test]
    fn frame_round_trips_and_bounds() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &[1, 2, 3, 4]).expect("write");
        let mut cursor = Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).expect("read"), vec![1, 2, 3, 4]);

        let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            write_frame(&mut Vec::new(), &oversized),
            Err(PipeError::TooLarge)
        );
    }

    #[test]
    fn read_frame_reports_closed_and_too_large() {
        // Truncated length prefix.
        let mut short = Cursor::new(vec![0x01, 0x02]);
        assert_eq!(read_frame(&mut short), Err(PipeError::Closed));
        // Announced length beyond the ceiling.
        let mut huge = Cursor::new(0xFF_FF_FF_FF_u32.to_le_bytes().to_vec());
        assert_eq!(read_frame(&mut huge), Err(PipeError::TooLarge));
    }

    #[test]
    fn serve_one_reads_a_request_and_writes_the_response() {
        let request = Request::SignDigest {
            key_profile: KeyProfile::EcdsaP256,
            algorithm: SignatureAlgorithm::EcdsaSha256,
            digest: vec![3_u8; 32],
        };
        let mut request_frame = Vec::new();
        write_frame(&mut request_frame, &request.encode()).expect("prime request");

        let mut endpoint = MemStream::new(request_frame);
        let handled = serve_one(&mut endpoint, |req| {
            assert_eq!(req, &request);
            Response::Signature(vec![5_u8; 64])
        })
        .expect("server serves one");
        assert_eq!(handled, request);

        // The server's captured output decodes back to the response it gave.
        let body = read_frame(&mut Cursor::new(endpoint.outbox)).expect("read response frame");
        assert_eq!(
            Response::decode(&request, &body).expect("decodes"),
            Response::Signature(vec![5_u8; 64])
        );
    }

    #[test]
    fn exchange_helper_pairs_write_then_read() {
        // Prime the stream with the response the server would send; exchange
        // writes the request (captured, unused) then reads that response.
        let mut response_frame = Vec::new();
        write_frame(
            &mut response_frame,
            &Response::Status(CardStatus {
                card_present: true,
                holder: String::new(),
            })
            .encode(),
        )
        .expect("prime response");
        let mut io = MemStream::new(response_frame);
        let response = exchange(&mut io, &Request::Status).expect("exchange");
        assert_eq!(
            response,
            Response::Status(CardStatus {
                card_present: true,
                holder: String::new(),
            })
        );
        // exchange wrote the request frame out first.
        let sent = read_frame(&mut Cursor::new(io.outbox)).expect("request frame was written");
        assert_eq!(Request::decode(&sent).expect("decodes"), Request::Status);
    }
}
