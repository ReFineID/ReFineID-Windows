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

//! Narrow C ABI for the `ReFineID` Windows remote-card UI.
//!
//! Raw pointers end in this crate. Listen addresses, advertised endpoints,
//! and display names are copied into owned Rust strings before use. The
//! requester never holds a CAN, PIN, or PUK, so none can cross this boundary;
//! the phone-side proxy owns every credential. Public identity fields (the
//! cardholder name and personal identifier) do cross in the JSON reply
//! because the UI displays them, but they never enter a log.
//!
//! This ABI is handle-based: a caller begins a pairing, polls its state,
//! confirms it, then reads the paired card. Each handle owns one background
//! pairing thread and, after pairing, the live `Requester`. The pairing lives
//! only in that requester's memory and is gone when the handle ends: a pairing
//! lasts the app session, never longer.

#![expect(
    unsafe_code,
    reason = "this crate is the deliberately narrow C ABI boundary used by the C# UI process"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::TcpStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::thread::JoinHandle;

use refineid_rapp_core::engine::{
    OperationOutcome, PeerIntroduction, Requester, RequesterConfig, Session,
};
use refineid_rapp_core::ids::{OfferId, PairingSecret};
use refineid_rapp_core::limits::OFFER_TTL_MAX_MS;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::{PairingOffer, TransportCandidate};
use refineid_rapp_core::operations::{CardOperation, CardOperationResult, CertificateKind};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore};
use refineid_rapp_core::stream::{StreamListener, stream_candidate_parameters};
use refineid_rapp_core::transport::{STREAM_PROFILE, TcpFrameTransport};
use refineid_rapp_core::{PAIRING_SUITE, WIRE_VERSION};
#[cfg(windows)]
use refineid_remote_card_pipe::{KeyProfile, Response, SignatureAlgorithm};
use serde::Serialize;

mod card_service;

/// The one stream candidate this requester advertises.
const CANDIDATE_ID: &str = "stream-1";

/// Frame receive deadline used by the stream listener.
const RECEIVE_DEADLINE_MS: u64 = 180_000;

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 120_000;

/// Longest listen address or advertised endpoint accepted, in bytes.
const MAX_ADDRESS_BYTES: usize = 1_024;

/// Longest requester display name accepted, in bytes.
const MAX_NAME_BYTES: usize = 256;

/// Longest granted-profile JSON array accepted, in bytes.
const MAX_GRANTED_BYTES: usize = 4_096;

/// The requester engine specialised to the in-memory stores: a pairing lasts
/// only as long as this process, never longer.
type StreamRequester = Requester<MemoryPairingStore, MemoryJournal>;

#[derive(Debug)]
struct ApiFailure {
    code: &'static str,
    message: String,
}

impl ApiFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
struct ApiError<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct ApiEnvelope<'a, T> {
    ok: bool,
    data: Option<&'a T>,
    error: Option<ApiError<'a>>,
}

#[derive(Serialize)]
struct BeginPairingDto {
    handle: u64,
    offer_uri: String,
}

#[derive(Serialize)]
struct PairingStateDto {
    state: &'static str,
    peer: Option<PeerDto>,
    pair_id_hex: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
struct PeerDto {
    display_name: String,
    platform: String,
    profiles: Vec<String>,
}

#[derive(Serialize)]
struct AckDto {
    ok: bool,
}

#[derive(Serialize)]
struct CardReadDto {
    identity: IdentityDto,
}

#[derive(Serialize)]
struct IdentityDto {
    display_name: String,
    person_id: String,
}

/// The phase of one pairing handle, shared between the background thread and
/// the calling threads that poll and confirm it.
enum Phase {
    Offer,
    AwaitingConfirmation {
        display_name: String,
        platform: String,
        profiles: Vec<String>,
    },
    Paired {
        pair_id_hex: String,
    },
    Denied,
    Cancelled,
}

/// The live requester and the session its pairing channel became, parked
/// here once pairing succeeds so a later read can drive the card on the
/// caller's thread. The listener is dropped at pairing: the one connection
/// is the pairing, and nothing exists for another connection to reach.
struct Paired {
    requester: StreamRequester,
    session: Session<TcpFrameTransport>,
}

/// State a pairing handle shares across threads.
struct Shared {
    phase: Phase,
    decision_tx: Option<Sender<Option<Vec<String>>>>,
    end_requested: bool,
    paired: Option<Paired>,
    /// The local pipe service publishing this pairing's card to Windows, once
    /// the caller has published it. Dropped (which stops and joins the service
    /// thread) when the pairing ends or the card is unpublished.
    service: Option<card_service::CardService>,
}

/// One pairing handle: its shared state, the background pairing thread, and
/// the listen port used to wake a thread still blocked on `accept`.
struct Handle {
    shared: Mutex<Shared>,
    thread: Option<JoinHandle<()>>,
    port: u16,
}

static REGISTRY: LazyLock<Mutex<HashMap<u64, Handle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Free a UTF-8 JSON string returned by this library.
///
/// `json` must be either null or a pointer returned by one of the
/// `refineid_rapp_*` functions in this library.
///
/// # Safety
///
/// A non-null `json` must be an unmodified pointer returned by this library,
/// and the caller must pass it to this function exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_string_free(json: *mut c_char) {
    if json.is_null() {
        return;
    }
    // SAFETY: The C ABI contract above requires a pointer produced by
    // CString::into_raw in reply_json. Reconstructing it exactly once returns
    // the allocation to Rust.
    drop(unsafe { CString::from_raw(json) });
}

/// Begin a pairing: bind a listener, publish an offer, and start accepting.
///
/// Returns `{ handle, offer_uri }` immediately. The URI is the exact text a
/// QR must encode. The background thread accepts the phone's connection and
/// runs the pairing handshake; the caller drives confirmation through
/// [`refineid_rapp_poll_pairing`] and [`refineid_rapp_confirm_pairing`].
///
/// # Safety
///
/// Each pointer must address the accompanying number of readable bytes for
/// the duration of the call. `listen` and each byte of `advertise`/`name`
/// must be UTF-8. `advertise` is a newline-separated list of `host:port`
/// endpoints reachable by the phone.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_begin_pairing(
    listen: *const u8,
    listen_length: usize,
    advertise: *const u8,
    advertise_length: usize,
    name: *const u8,
    name_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: Each input is pointer- and bound-checked before the slice
        // is formed, then copied into owned Rust before use.
        let listen = unsafe { copy_utf8(listen, listen_length, MAX_ADDRESS_BYTES, "listen") }?;
        // SAFETY: As above.
        let advertise_raw =
            unsafe { copy_utf8(advertise, advertise_length, MAX_ADDRESS_BYTES, "advertise") }?;
        // SAFETY: As above.
        let name = unsafe { copy_utf8(name, name_length, MAX_NAME_BYTES, "name") }?;
        let advertise: Vec<String> = advertise_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if advertise.is_empty() {
            return Err(ApiFailure::new(
                "no_advertised_endpoint",
                "At least one advertised host:port endpoint is required.",
            ));
        }
        begin_pairing(&listen, &advertise, name)
    })
}

/// Poll the state of a pairing handle.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_poll_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        let registry = lock_registry()?;
        let entry = registry
            .get(&handle)
            .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
        let shared = lock_shared(&entry.shared)?;
        Ok(state_dto(&shared.phase))
    })
}

/// Confirm a pairing awaiting the caller's decision.
///
/// `granted` is a JSON array of profile names, or empty to grant exactly the
/// profiles the peer requested.
///
/// # Safety
///
/// `granted` must address `granted_length` readable UTF-8 bytes, or be null
/// with a zero length to grant every requested profile.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_confirm_pairing(
    handle: u64,
    granted: *const u8,
    granted_length: usize,
) -> *mut c_char {
    reply_json(|| {
        let profiles = if granted_length == 0 {
            Vec::new()
        } else {
            // SAFETY: pointer- and bound-checked before the slice is formed.
            let text = unsafe { copy_utf8(granted, granted_length, MAX_GRANTED_BYTES, "granted") }?;
            serde_json::from_str::<Vec<String>>(&text).map_err(|_| {
                ApiFailure::new(
                    "invalid_granted",
                    "The granted profiles must be a JSON array of strings.",
                )
            })?
        };
        deliver_decision(handle, Some(profiles))?;
        Ok(AckDto { ok: true })
    })
}

/// Deny or cancel a pairing awaiting the caller's decision.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_cancel_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        deliver_decision(handle, None)?;
        Ok(AckDto { ok: true })
    })
}

/// Read the paired card's identity over the live pairing channel.
///
/// The pairing connection is already the session, so the read runs
/// immediately and blocks only for the phone's card read; the session stays
/// live until [`refineid_rapp_end_pairing`].
///
/// The returned identity fields are shown to the user; no card data is
/// logged. Signing is not yet exposed: `browser_authenticate` and
/// `sign_document` need a digest input and a per-operation approval on the
/// phone and will be added here next.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_read_card(handle: u64) -> *mut c_char {
    reply_json(|| {
        // Take the paired card out under a brief lock so the blocking read
        // does not hold the global registry while it waits for a session.
        let mut paired = take_paired(handle)?;
        let result = read_paired_card(&mut paired);
        restore_paired(handle, paired);
        result
    })
}

/// Check that the live pairing still answers.
///
/// Sends one liveness ping and waits for the echo, answering the phone's own
/// pings while waiting. On success the pairing stays live. On any failure —
/// the phone closed, vanished, or violated the protocol — the pairing is
/// already over and its keys destroyed; the caller should end the handle and
/// clear the identity it showed.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_check_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        let mut paired = take_paired(handle)?;
        match paired.requester.check_liveness(&mut paired.session) {
            Ok(()) => {
                restore_paired(handle, paired);
                Ok(AckDto { ok: true })
            }
            Err(_error) => {
                // The engine has ended the pairing; dropping `paired` destroys
                // the in-memory keys and the socket.
                Err(ApiFailure::new(
                    "pairing_ended",
                    "The pairing ended; the phone closed or stopped answering.",
                ))
            }
        }
    })
}

/// Publish the paired card to Windows over the local named pipe.
///
/// Reads and caches the authentication certificate over the live pairing (one
/// phone approval), then starts the pipe service that answers the minidriver's
/// certificate, status, and sign requests. Publishing again replaces the
/// service. The certificate and status are served from the cache; only a
/// signature reaches the phone, as a typed `browser_authenticate`.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_publish_card(handle: u64) -> *mut c_char {
    reply_json(|| {
        let cert_der = {
            let mut paired = take_paired(handle)?;
            let result = run_operation(
                &mut paired,
                &CardOperation::ReadCertificate {
                    kind: CertificateKind::Authentication,
                },
            );
            restore_paired(handle, paired);
            match result? {
                CardOperationResult::Certificate(der) => der,
                _ => return Err(unexpected_result("read_certificate")),
            }
        };
        // Replace any prior service, dropping it outside the registry lock, so
        // its join never contends with a request thread holding that lock.
        drop(take_card_service(handle));
        let service = card_service::CardService::start(handle, cert_der, String::new());
        if registry_entry_apply(handle, move |shared| shared.service = Some(service)).is_none() {
            return Err(ApiFailure::new("unknown_handle", "No such pairing handle."));
        }
        Ok(AckDto { ok: true })
    })
}

/// Unpublish the paired card: stop the pipe service. The pairing stays live.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_unpublish_card(handle: u64) -> *mut c_char {
    reply_json(|| {
        drop(take_card_service(handle));
        Ok(AckDto { ok: true })
    })
}

/// Sign a digest for the pipe service over the live pairing. Runs one typed
/// `browser_authenticate`; the holder approves and enters PIN1 on the phone.
/// A busy session yields [`Response::Busy`] so the client retries rather than
/// blocks; a session-ending outcome yields [`Response::Unavailable`].
#[cfg(windows)]
pub(crate) fn service_sign(
    handle_id: u64,
    key_profile: KeyProfile,
    algorithm: SignatureAlgorithm,
    digest: Vec<u8>,
) -> Response {
    let mut paired = match take_paired(handle_id) {
        Ok(paired) => paired,
        Err(failure) => {
            return if failure.code == "not_paired" {
                Response::Busy
            } else {
                Response::Unavailable
            };
        }
    };
    let operation = card_service::browser_authenticate(key_profile, algorithm, digest);
    let result = run_operation(&mut paired, &operation);
    restore_paired(handle_id, paired);
    match result {
        Ok(CardOperationResult::Signature(bytes)) => Response::Signature(bytes),
        Ok(_) => Response::Protocol,
        Err(failure) => match failure.code {
            "denied" | "cancelled" => Response::Denied,
            _ => Response::Unavailable,
        },
    }
}

/// Take the pipe service out of a handle's shared state under the lock,
/// returning it so the caller drops it without holding the lock.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn take_card_service(handle_id: u64) -> Option<card_service::CardService> {
    let registry = REGISTRY.lock().ok()?;
    let entry = registry.get(&handle_id)?;
    let mut shared = entry.shared.lock().ok()?;
    shared.service.take()
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn take_paired(handle: u64) -> Result<Paired, ApiFailure> {
    let registry = lock_registry()?;
    let entry = registry
        .get(&handle)
        .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
    let mut shared = lock_shared(&entry.shared)?;
    shared.paired.take().ok_or_else(|| {
        ApiFailure::new(
            "not_paired",
            "This handle has no paired card, or a read is already in progress.",
        )
    })
}

fn restore_paired(handle: u64, paired: Paired) {
    if let Ok(registry) = REGISTRY.lock()
        && let Some(entry) = registry.get(&handle)
        && let Ok(mut shared) = entry.shared.lock()
    {
        shared.paired = Some(paired);
    }
}

/// End the pairing: close its live session, stop the thread, free the handle.
///
/// The pairing lives only in memory, so this destroys the pair keys after a
/// best-effort clean close notice; the phone drops its side when it sees the
/// close or the connection end.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_end_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        let removed = {
            let mut registry = lock_registry()?;
            registry.remove(&handle)
        };
        let Some(mut entry) = removed else {
            return Ok(AckDto { ok: true });
        };
        // Wake the background thread if it is still blocked on accept, then
        // let its own drop release the listener and requester.
        let (paired, service) = entry.shared.lock().map_or((None, None), |mut shared| {
            shared.end_requested = true;
            if let Some(decision_tx) = shared.decision_tx.take() {
                let _ = decision_tx.send(None);
            }
            (shared.paired.take(), shared.service.take())
        });
        // Stop the pipe service now, with the lock released, so its join does
        // not contend with a request thread reaching for the registry.
        drop(service);
        if let Some(mut paired) = paired {
            let Paired { requester, session } = &mut paired;
            requester.disconnect(session, CloseReason::UserDisconnect);
        }
        let _ = TcpStream::connect(("127.0.0.1", entry.port));
        if let Some(thread) = entry.thread.take() {
            let _ = thread.join();
        }
        Ok(AckDto { ok: true })
    })
}

fn begin_pairing(
    listen: &str,
    advertise: &[String],
    name: String,
) -> Result<BeginPairingDto, ApiFailure> {
    let listener =
        StreamListener::bind(listen, CANDIDATE_ID, receive_deadline()).map_err(|_error| {
            ApiFailure::new(
                "listen_failed",
                "Could not open the network port to wait for the phone. \
                 Another ReFineID window may already be waiting for a connection; \
                 close it and try again.",
            )
        })?;
    let port = listener.local_port().map_err(|_error| {
        ApiFailure::new(
            "port_unavailable",
            "The network port opened but its number could not be read.",
        )
    })?;

    let requester = Requester::new(
        RequesterConfig {
            display_name: name,
            platform: "Windows".to_owned(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    );

    let requested_profiles = vec![
        PROFILE_CARD_STATUS.to_owned(),
        PROFILE_AUTHENTICATION.to_owned(),
        PROFILE_DOCUMENT_SIGNING.to_owned(),
    ];
    let parameters = stream_candidate_parameters(advertise)
        .map_err(|error| ApiFailure::new("invalid_endpoints", format!("{error:?}")))?;
    let offer = PairingOffer {
        version: WIRE_VERSION,
        offer_id: OfferId::random()
            .map_err(|_| ApiFailure::new("random_unavailable", "Secure random is unavailable."))?,
        suites: vec![PAIRING_SUITE.to_owned()],
        profiles: requested_profiles.clone(),
        transports: vec![TransportCandidate {
            profile: STREAM_PROFILE.to_owned(),
            candidate_id: CANDIDATE_ID.to_owned(),
            parameters,
        }],
        offer_ttl_ms: OFFER_TTL_MAX_MS,
    };
    let secret = PairingSecret::random()
        .map_err(|_| ApiFailure::new("random_unavailable", "Secure random is unavailable."))?;
    let offer_uri = offer
        .to_uri(&secret)
        .map_err(|error| ApiFailure::new("offer_encoding_failed", format!("{error:?}")))?;
    let secret_bytes = secret.0;

    let handle_id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let shared = Mutex::new(Shared {
        phase: Phase::Offer,
        decision_tx: None,
        end_requested: false,
        paired: None,
        service: None,
    });
    {
        let mut registry = lock_registry()?;
        registry.insert(
            handle_id,
            Handle {
                shared,
                thread: None,
                port,
            },
        );
    }
    // The thread reaches the shared state through the registry by handle id,
    // owning the pieces it moves and locking only briefly each time.
    let thread = std::thread::spawn(move || {
        pairing_thread(
            handle_id,
            requester,
            listener,
            offer,
            secret_bytes,
            requested_profiles,
        );
    });
    if let Ok(mut registry) = lock_registry()
        && let Some(entry) = registry.get_mut(&handle_id)
    {
        entry.thread = Some(thread);
    }
    Ok(BeginPairingDto {
        handle: handle_id,
        offer_uri,
    })
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the offer and profiles are moved into this spawned thread and owned for its life"
)]
fn pairing_thread(
    handle_id: u64,
    mut requester: StreamRequester,
    listener: StreamListener,
    offer: PairingOffer,
    secret_bytes: [u8; 32],
    requested_profiles: Vec<String>,
) {
    loop {
        if ended(handle_id) {
            return;
        }
        let Ok(transport) = listener.accept() else {
            continue;
        };
        if ended(handle_id) {
            return;
        }

        let (decision_tx, decision_rx) = channel::<Option<Vec<String>>>();
        if !publish_decision_sender(handle_id, decision_tx) {
            return;
        }
        let attempt_profiles = requested_profiles.clone();
        let confirm = |peer: &PeerIntroduction, offered: &[String]| -> Option<Vec<String>> {
            set_awaiting(handle_id, peer, offered);
            match decision_rx.recv() {
                Ok(Some(granted)) => Some(if granted.is_empty() {
                    offered.to_vec()
                } else {
                    granted
                }),
                Ok(None) | Err(_) => None,
            }
        };
        let outcome = requester.pair(
            &offer,
            PairingSecret(secret_bytes),
            &attempt_profiles,
            transport,
            confirm,
        );
        match outcome {
            Ok(session) => {
                // The one connection is the pairing: the listener closes so
                // any further connection is refused by construction.
                drop(listener);
                finish_pairing(handle_id, requester, session);
                return;
            }
            Err(error) => {
                if reset_after_failure(handle_id, error) {
                    return;
                }
            }
        }
    }
}

fn finish_pairing(handle_id: u64, requester: StreamRequester, session: Session<TcpFrameTransport>) {
    let pair_id_hex = hex::encode(session.pair_id().0);
    // If the handle is gone, the closure is never run and the moved
    // requester and session are dropped here instead, which ends the
    // pairing.
    let _stored = registry_entry_apply(handle_id, move |shared| {
        shared.decision_tx = None;
        shared.phase = Phase::Paired { pair_id_hex };
        shared.paired = Some(Paired { requester, session });
    });
}

fn read_paired_card(paired: &mut Paired) -> Result<CardReadDto, ApiFailure> {
    // The pairing channel is already the live session: the read runs on it
    // immediately, and the session stays live afterwards until the caller
    // ends the pairing. The requester screen shows only the holder identity,
    // so the read is one operation and the phone reads the card once.
    let identity = match run_operation(paired, &CardOperation::ReadIdentity)? {
        CardOperationResult::Identity {
            display_name,
            person_id,
        } => IdentityDto {
            display_name,
            person_id,
        },
        _ => return Err(unexpected_result("read_identity")),
    };

    Ok(CardReadDto { identity })
}

fn run_operation(
    paired: &mut Paired,
    operation: &CardOperation,
) -> Result<CardOperationResult, ApiFailure> {
    let Paired { requester, session } = paired;
    let outcome = requester
        .execute(session, operation, OPERATION_EXPIRY_MS)
        .map_err(|error| ApiFailure::new("operation_not_admitted", format!("{error:?}")))?;
    match outcome {
        OperationOutcome::Completed(result) => Ok(result),
        OperationOutcome::Denied => Err(ApiFailure::new(
            "denied",
            "The holder denied the request on the phone.",
        )),
        OperationOutcome::Cancelled => Err(ApiFailure::new(
            "cancelled",
            "The request was cancelled or expired.",
        )),
        OperationOutcome::Rejected(reason) => Err(ApiFailure::new(
            "rejected",
            reason.unwrap_or_else(|| "The request was rejected.".to_owned()),
        )),
        OperationOutcome::CredentialRejected => Err(ApiFailure::new(
            "credential_rejected",
            "A credential was rejected; the pairing is revoked on both devices.",
        )),
        OperationOutcome::Ambiguous => Err(ApiFailure::new(
            "ambiguous",
            "The card result is unproven and will not be retried.",
        )),
    }
}

fn unexpected_result(action: &str) -> ApiFailure {
    ApiFailure::new(
        "unexpected_result",
        format!("The card returned an unexpected result for {action}."),
    )
}

fn state_dto(phase: &Phase) -> PairingStateDto {
    match phase {
        Phase::Offer => PairingStateDto {
            state: "offer",
            peer: None,
            pair_id_hex: None,
            message: None,
        },
        Phase::AwaitingConfirmation {
            display_name,
            platform,
            profiles,
        } => PairingStateDto {
            state: "awaiting_confirmation",
            peer: Some(PeerDto {
                display_name: display_name.clone(),
                platform: platform.clone(),
                profiles: profiles.clone(),
            }),
            pair_id_hex: None,
            message: None,
        },
        Phase::Paired { pair_id_hex } => PairingStateDto {
            state: "paired",
            peer: None,
            pair_id_hex: Some(pair_id_hex.clone()),
            message: None,
        },
        Phase::Denied => PairingStateDto {
            state: "denied",
            peer: None,
            pair_id_hex: None,
            message: None,
        },
        Phase::Cancelled => PairingStateDto {
            state: "cancelled",
            peer: None,
            pair_id_hex: None,
            message: None,
        },
    }
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn deliver_decision(handle: u64, decision: Option<Vec<String>>) -> Result<(), ApiFailure> {
    let registry = lock_registry()?;
    let entry = registry
        .get(&handle)
        .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
    let mut shared = lock_shared(&entry.shared)?;
    let is_deny = decision.is_none();
    let Some(decision_tx) = shared.decision_tx.take() else {
        return Err(ApiFailure::new(
            "not_awaiting",
            "This pairing is not awaiting a decision.",
        ));
    };
    decision_tx.send(decision).map_err(|_| {
        ApiFailure::new(
            "decision_undeliverable",
            "The pairing thread is no longer waiting.",
        )
    })?;
    if is_deny {
        shared.phase = Phase::Denied;
    }
    Ok(())
}

fn set_awaiting(handle_id: u64, peer: &PeerIntroduction, offered: &[String]) {
    registry_entry_apply(handle_id, |shared| {
        shared.phase = Phase::AwaitingConfirmation {
            display_name: peer.display_name.clone(),
            platform: peer.platform.clone(),
            profiles: offered.to_vec(),
        };
    });
}

fn publish_decision_sender(handle_id: u64, decision_tx: Sender<Option<Vec<String>>>) -> bool {
    registry_entry_apply(handle_id, move |shared| {
        shared.decision_tx = Some(decision_tx);
    })
    .is_some()
}

fn reset_after_failure(handle_id: u64, error: refineid_rapp_core::engine::PairingError) -> bool {
    // A denial or an authenticated failure ends the attempt; anything else
    // leaves the offer live for another candidate.
    let denied = matches!(
        error,
        refineid_rapp_core::engine::PairingError::DeniedLocally
            | refineid_rapp_core::engine::PairingError::AbortedByPeer
    );
    registry_entry_apply(handle_id, |shared| {
        shared.decision_tx = None;
        if shared.end_requested {
            shared.phase = Phase::Cancelled;
        } else if denied {
            shared.phase = Phase::Denied;
        } else {
            shared.phase = Phase::Offer;
        }
    });
    // Stop the thread on a denial, a cancel, or a lost handle.
    denied || ended(handle_id)
}

/// Applies `update` to a handle's shared state, returning `Some(())` when the
/// handle still exists.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn registry_entry_apply<F: FnOnce(&mut Shared)>(handle_id: u64, update: F) -> Option<()> {
    let registry = REGISTRY.lock().ok()?;
    let entry = registry.get(&handle_id)?;
    let mut shared = entry.shared.lock().ok()?;
    update(&mut shared);
    Some(())
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn ended(handle_id: u64) -> bool {
    let Ok(registry) = REGISTRY.lock() else {
        return true;
    };
    let Some(entry) = registry.get(&handle_id) else {
        return true;
    };
    let Ok(shared) = entry.shared.lock() else {
        return true;
    };
    shared.end_requested
}

const fn receive_deadline() -> std::time::Duration {
    std::time::Duration::from_millis(RECEIVE_DEADLINE_MS)
}

fn lock_registry() -> Result<MutexGuard<'static, HashMap<u64, Handle>>, ApiFailure> {
    REGISTRY
        .lock()
        .map_err(|_| ApiFailure::new("state_poisoned", "The requester registry is unusable."))
}

fn lock_shared(shared: &Mutex<Shared>) -> Result<MutexGuard<'_, Shared>, ApiFailure> {
    shared
        .lock()
        .map_err(|_| ApiFailure::new("state_poisoned", "The pairing state is unusable."))
}

unsafe fn copy_utf8(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<String, ApiFailure> {
    // SAFETY: copy_bytes validates the pointer and bound before reading.
    let bytes = unsafe { copy_bytes(input, length, maximum, label) }?;
    String::from_utf8(bytes)
        .map_err(|_| ApiFailure::new("invalid_utf8", format!("{label} was not valid UTF-8")))
}

unsafe fn copy_bytes(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, ApiFailure> {
    if length == 0 {
        return Err(ApiFailure::new(
            "empty_input",
            format!("{label} must not be empty"),
        ));
    }
    if length > maximum {
        return Err(ApiFailure::new(
            "input_too_long",
            format!("{label} exceeds the accepted length"),
        ));
    }
    if input.is_null() {
        return Err(ApiFailure::new(
            "null_input",
            format!("{label} pointer was null"),
        ));
    }
    // SAFETY: The caller's C ABI obligation is that input points to at least
    // length readable bytes. The checks above reject null and cap length
    // before the slice is formed; to_vec immediately detaches it.
    Ok(unsafe { core::slice::from_raw_parts(input, length) }.to_vec())
}

fn reply_json<T, F>(operation: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> Result<T, ApiFailure>,
{
    let result = catch_unwind(AssertUnwindSafe(operation));
    let json = match result {
        Ok(Ok(data)) => serialize_envelope(&ApiEnvelope {
            ok: true,
            data: Some(&data),
            error: None,
        }),
        Ok(Err(error)) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: error.code,
                message: &error.message,
            }),
        }),
        Err(_) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: "internal_panic",
                message: "The native requester stopped unexpectedly.",
            }),
        }),
    };
    CString::new(json).map_or(core::ptr::null_mut(), CString::into_raw)
}

fn serialize_envelope<T: Serialize>(envelope: &ApiEnvelope<'_, T>) -> String {
    serde_json::to_string(envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialization_failed\",\"message\":\"The native response could not be encoded.\"}}".to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::{Phase, state_dto};

    #[test]
    fn state_labels_are_closed() {
        assert_eq!(state_dto(&Phase::Offer).state, "offer");
        assert_eq!(state_dto(&Phase::Denied).state, "denied");
        assert_eq!(state_dto(&Phase::Cancelled).state, "cancelled");
        assert_eq!(
            state_dto(&Phase::Paired {
                pair_id_hex: "00".to_owned()
            })
            .state,
            "paired"
        );
    }

    #[test]
    fn awaiting_state_carries_the_peer() {
        let dto = state_dto(&Phase::AwaitingConfirmation {
            display_name: "iPhone".to_owned(),
            platform: "iOS".to_owned(),
            profiles: vec!["fi.eid.card-status.v1".to_owned()],
        });
        assert_eq!(dto.state, "awaiting_confirmation");
        let peer = dto.peer.expect("peer present");
        assert_eq!(peer.display_name, "iPhone");
        assert_eq!(peer.profiles.len(), 1);
    }
}
