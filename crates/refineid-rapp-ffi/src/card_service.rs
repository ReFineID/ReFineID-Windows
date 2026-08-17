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

//! The local card service: the app side of the remote-card bridge.
//!
//! Once a pairing is live and the authentication certificate is cached, the
//! app publishes the paired card on a local named pipe. The minidriver's
//! remote arm dials that pipe and asks for the certificate or a signature.
//! Certificate and status answers come from the cache with no card contact;
//! a signature is one typed, phone-approved RAPP `browser_authenticate` run
//! on the live pairing, so the holder still consents on the phone and no PIN
//! ever reaches Windows.
//!
//! The named pipe is Windows-only. The mapping from the pipe's key/algorithm
//! vocabulary to the RAPP registry is portable and unit-tested here; the pipe
//! endpoint lives behind `#[cfg(windows)]`.
#![expect(
    clippy::redundant_pub_crate,
    reason = "this private module uses pub(crate) consistently for its crate-internal service surface, matching the sibling minidriver modules"
)]
#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the pipe-to-RAPP mapping is used by the Windows named-pipe server and by this module's tests; a non-Windows library-only cross-check has neither, so it reads as dead there"
    )
)]

use refineid_rapp_core::operations::{
    CardOperation, KeyProfile as RappKeyProfile, SignatureAlgorithm as RappSignatureAlgorithm,
};
use refineid_remote_card_pipe::{KeyProfile, SignatureAlgorithm};

/// The origin the holder sees on the phone for a Windows signature. The true
/// relying party is not visible at the Card Module layer, so this states
/// plainly what the request is: a Windows client-authentication signature.
pub(crate) const BROWSER_AUTH_ORIGIN: &str = "Windows client authentication";

/// Map the pipe's key profile to the RAPP registry profile.
pub(crate) const fn rapp_key_profile(profile: KeyProfile) -> RappKeyProfile {
    match profile {
        KeyProfile::EcdsaP256 => RappKeyProfile::EcdsaP256,
        KeyProfile::EcdsaP384 => RappKeyProfile::EcdsaP384,
        KeyProfile::Rsa2048 => RappKeyProfile::Rsa2048,
        KeyProfile::Rsa3072 => RappKeyProfile::Rsa3072,
    }
}

/// Map the pipe's algorithm to the RAPP registry algorithm.
pub(crate) const fn rapp_algorithm(algorithm: SignatureAlgorithm) -> RappSignatureAlgorithm {
    match algorithm {
        SignatureAlgorithm::EcdsaSha224 => RappSignatureAlgorithm::EcdsaSha224,
        SignatureAlgorithm::EcdsaSha256 => RappSignatureAlgorithm::EcdsaSha256,
        SignatureAlgorithm::EcdsaSha384 => RappSignatureAlgorithm::EcdsaSha384,
        SignatureAlgorithm::EcdsaSha512 => RappSignatureAlgorithm::EcdsaSha512,
        SignatureAlgorithm::RsaPkcs1Sha256 => RappSignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384 => RappSignatureAlgorithm::RsaPkcs1Sha384,
        SignatureAlgorithm::RsaPkcs1Sha512 => RappSignatureAlgorithm::RsaPkcs1Sha512,
        SignatureAlgorithm::RsaPssSha256 => RappSignatureAlgorithm::RsaPssSha256,
    }
}

/// Build the RAPP `browser_authenticate` operation for a pipe sign request.
pub(crate) fn browser_authenticate(
    key_profile: KeyProfile,
    algorithm: SignatureAlgorithm,
    digest: Vec<u8>,
) -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: BROWSER_AUTH_ORIGIN.to_owned(),
        key_profile: rapp_key_profile(key_profile),
        algorithm: rapp_algorithm(algorithm),
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::{BROWSER_AUTH_ORIGIN, browser_authenticate, rapp_algorithm, rapp_key_profile};
    use refineid_rapp_core::operations::CardOperation;
    use refineid_remote_card_pipe::{KeyProfile, SignatureAlgorithm};

    #[test]
    fn every_profile_and_algorithm_maps_to_the_same_wire_name() {
        for profile in [
            KeyProfile::EcdsaP256,
            KeyProfile::EcdsaP384,
            KeyProfile::Rsa2048,
            KeyProfile::Rsa3072,
        ] {
            assert_eq!(
                rapp_key_profile(profile).wire_name(),
                profile.wire_name(),
                "profile wire name mismatch"
            );
        }
        for algorithm in [
            SignatureAlgorithm::EcdsaSha224,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
            SignatureAlgorithm::RsaPkcs1Sha256,
            SignatureAlgorithm::RsaPkcs1Sha384,
            SignatureAlgorithm::RsaPkcs1Sha512,
            SignatureAlgorithm::RsaPssSha256,
        ] {
            assert_eq!(
                rapp_algorithm(algorithm).wire_name(),
                algorithm.wire_name(),
                "algorithm wire name mismatch"
            );
        }
    }

    #[test]
    fn browser_authenticate_carries_the_digest_and_origin() {
        let operation = browser_authenticate(
            KeyProfile::Rsa3072,
            SignatureAlgorithm::RsaPkcs1Sha256,
            vec![1_u8; 32],
        );
        match operation {
            CardOperation::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            } => {
                assert_eq!(origin, BROWSER_AUTH_ORIGIN);
                assert_eq!(key_profile.wire_name(), "rsa_3072");
                assert_eq!(algorithm.wire_name(), "rsa_pkcs1_sha256");
                assert_eq!(digest, vec![1_u8; 32]);
            }
            _ => panic!("expected browser_authenticate"),
        }
    }
}

#[cfg(windows)]
pub(crate) use windows_pipe::CardService;

#[cfg(not(windows))]
pub(crate) use stub::CardService;

/// The Windows named-pipe server. One background thread accepts connections
/// and serves requests until stopped; stopping wakes a blocked accept by
/// dialing the pipe once.
#[cfg(windows)]
mod windows_pipe {
    use core::ffi::c_void;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;

    use refineid_remote_card_pipe::{PIPE_NAME, Request, Response, serve_one};

    type Handle = *mut c_void;

    // A minimal slice of the Win32 named-pipe API, linked directly the way the
    // sibling minidriver links winscard -- no windows-sys dependency.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer_size: u32,
            in_buffer_size: u32,
            default_timeout: u32,
            security_attributes: *mut c_void,
        ) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlapped: *mut c_void) -> i32;
        fn DisconnectNamedPipe(pipe: Handle) -> i32;
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
        fn GetLastError() -> u32;
    }

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const PIPE_BUFFER_BYTES: u32 = 16_384;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: isize = -1;

    /// Encode a path as a NUL-terminated UTF-16 string for the wide Win32 API.
    fn wide(path: &str) -> Vec<u16> {
        path.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// A connected pipe instance as a byte stream for the shared framing.
    struct PipeStream {
        handle: Handle,
    }

    impl Read for PipeStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let to_read = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            let mut read = 0_u32;
            // SAFETY: `handle` is a connected pipe instance; `buffer` is valid
            // for `to_read` bytes; `read` receives the count.
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

    impl Write for PipeStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let to_write = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            let mut written = 0_u32;
            // SAFETY: `handle` is a connected pipe instance; `buffer` is valid
            // for `to_write` bytes; `written` receives the count.
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

    /// The published card served over the pipe: the running requester handle,
    /// the cached certificate, and the holder hint.
    pub(crate) struct CardService {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl CardService {
        /// Start serving the paired card for `handle_id` on the local pipe.
        /// The certificate and holder are answered from the cache; a sign
        /// request is delegated to [`crate::service_sign`].
        pub(crate) fn start(handle_id: u64, cert_der: Vec<u8>, holder: String) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                serve_loop(handle_id, &cert_der, &holder, &thread_stop);
            });
            Self {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for CardService {
        /// Stop the service and join its thread, waking a blocked accept by
        /// dialing the pipe once. The drop never runs while the registry lock
        /// is held, so the joined thread's own registry access cannot deadlock.
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            wake_accept();
            if let Some(thread) = self.thread.take() {
                let _ignored = thread.join();
            }
        }
    }

    /// Dial the pipe once so a thread blocked in `ConnectNamedPipe` returns
    /// and observes the stop flag. The connection is closed immediately.
    fn wake_accept() {
        let name = wide(PIPE_NAME);
        // SAFETY: opening the pipe as a client; the handle is closed at once.
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
        if handle as isize != INVALID_HANDLE_VALUE {
            // SAFETY: a handle we just opened.
            unsafe {
                CloseHandle(handle);
            }
        }
    }

    fn serve_loop(handle_id: u64, cert_der: &[u8], holder: &str, stop: &AtomicBool) {
        let name = wide(PIPE_NAME);
        while !stop.load(Ordering::SeqCst) {
            // SAFETY: creating a byte-mode duplex pipe instance that rejects
            // remote clients; a default security descriptor limits it to the
            // creating user and system.
            let pipe = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER_BYTES,
                    PIPE_BUFFER_BYTES,
                    0,
                    core::ptr::null_mut(),
                )
            };
            if pipe as isize == INVALID_HANDLE_VALUE {
                return;
            }
            // SAFETY: `pipe` is a fresh server instance.
            let connect = unsafe { ConnectNamedPipe(pipe, core::ptr::null_mut()) };
            let connected = connect != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if stop.load(Ordering::SeqCst) {
                // SAFETY: `pipe` is owned here and closed exactly once.
                unsafe {
                    CloseHandle(pipe);
                }
                return;
            }
            if connected {
                let mut stream = PipeStream { handle: pipe };
                serve_connection(handle_id, cert_der, holder, stop, &mut stream);
            }
            // SAFETY: `pipe` is owned here; disconnect then close exactly once.
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
        }
    }

    fn serve_connection(
        handle_id: u64,
        cert_der: &[u8],
        holder: &str,
        stop: &AtomicBool,
        stream: &mut PipeStream,
    ) {
        while !stop.load(Ordering::SeqCst) {
            let served = serve_one(stream, |request| {
                respond(handle_id, cert_der, holder, request)
            });
            if served.is_err() {
                return;
            }
        }
    }

    fn respond(handle_id: u64, cert_der: &[u8], holder: &str, request: &Request) -> Response {
        match request {
            Request::Status => Response::Status(refineid_remote_card_pipe::CardStatus {
                card_present: true,
                holder: holder.to_owned(),
            }),
            Request::AuthCertificate => Response::Certificate(cert_der.to_vec()),
            Request::SignDigest {
                key_profile,
                algorithm,
                digest,
            } => crate::service_sign(handle_id, *key_profile, *algorithm, digest.clone()),
        }
    }
}

/// The non-Windows placeholder: there is no local named pipe to serve, so
/// publishing is inert. Keeps the workspace building and testing off Windows.
#[cfg(not(windows))]
mod stub {
    pub(crate) struct CardService;

    impl CardService {
        pub(crate) fn start(_handle_id: u64, _cert_der: Vec<u8>, _holder: String) -> Self {
            Self
        }
    }

    impl Drop for CardService {
        /// Mirrors the Windows service's stop-on-drop so callers drop the
        /// service the same way on every target; there is nothing to stop.
        fn drop(&mut self) {}
    }
}
