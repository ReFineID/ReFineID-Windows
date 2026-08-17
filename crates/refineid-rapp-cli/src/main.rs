//! Development requester CLI for the RAPP remote-card path.
//!
//! `refineid-rapp pair-demo` proves the full stream-profile path against a
//! real phone proxy in one process: it displays the pairing QR, accepts the
//! phone's connection, confirms grants on both devices, then serves inbound
//! sessions and runs typed card operations that the holder approves on the
//! phone. The pair keys live only for the process; a pairing is never stored.
//!
//! This is a development tool. It prints operation results to the terminal
//! and must not be distributed to end users.

use std::io::Write as _;
use std::time::{Duration, Instant};

use refineid_rapp_core::engine::{OperationOutcome, PeerIntroduction, Requester, RequesterConfig};
use refineid_rapp_core::ids::{Challenge, OfferId, PairId, PairingSecret, RendezvousToken};
use refineid_rapp_core::limits::OFFER_TTL_MAX_MS;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::{PairingOffer, TransportCandidate};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, CertificateKind, KeyProfile, SignatureAlgorithm,
};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::{StreamAccept, StreamListener, stream_candidate_parameters};
use refineid_rapp_core::transport::STREAM_PROFILE;
use refineid_rapp_core::{PAIRING_SUITE, WIRE_VERSION};

/// The one stream candidate this CLI advertises.
const CANDIDATE_ID: &str = "stream-1";

/// Frame receive deadline; also the accept-loop poll bound.
const RECEIVE_DEADLINE: Duration = Duration::from_mins(3);

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 120_000;

/// Visible prefix of a personal identifier in development output.
const PERSON_ID_VISIBLE_CHARS: usize = 6;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) != Some("pair-demo") {
        eprintln!("usage: refineid-rapp pair-demo --listen <bind-address> \\");
        eprintln!("           --advertise <host:port> [--advertise <host:port> ...] \\");
        eprintln!("           [--name <label>] [--sign-profile rsa3072|ecdsa384]");
        std::process::exit(2);
    }
    let outcome = pair_demo(&arguments[1..]);
    if let Err(message) = outcome {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

struct DemoOptions {
    listen: String,
    advertise: Vec<String>,
    name: String,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
}

fn parse_options(arguments: &[String]) -> Result<DemoOptions, String> {
    let mut listen = None;
    let mut advertise = Vec::new();
    let mut name = "ReFineID Windows".to_owned();
    let mut sign_profile = None;
    let mut cursor = arguments.iter();
    while let Some(flag) = cursor.next() {
        let mut value = || {
            cursor
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--listen" => listen = Some(value()?),
            "--advertise" => advertise.push(value()?),
            "--name" => name = value()?,
            "--sign-profile" => {
                sign_profile = Some(match value()?.as_str() {
                    "rsa3072" => (KeyProfile::Rsa3072, SignatureAlgorithm::RsaPkcs1Sha256),
                    "ecdsa384" => (KeyProfile::EcdsaP384, SignatureAlgorithm::EcdsaSha384),
                    other => return Err(format!("unknown sign profile {other}")),
                });
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(DemoOptions {
        listen: listen.ok_or("--listen is required")?,
        advertise,
        name,
        sign_profile,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the demo is one linear ceremony and reads best unsplit"
)]
fn pair_demo(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.advertise.is_empty() {
        return Err("--advertise is required at least once".into());
    }
    let listener = StreamListener::bind(&options.listen, CANDIDATE_ID, RECEIVE_DEADLINE)
        .map_err(|error| format!("cannot bind {}: {error:?}", options.listen))?;
    let port = listener
        .local_port()
        .map_err(|error| format!("cannot read bound port: {error:?}"))?;
    println!("listening on {} (port {port})", options.listen);

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: options.name.clone(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    );

    let requested_profiles = vec![
        PROFILE_CARD_STATUS.to_owned(),
        PROFILE_AUTHENTICATION.to_owned(),
        PROFILE_DOCUMENT_SIGNING.to_owned(),
    ];
    let offer = PairingOffer {
        version: WIRE_VERSION,
        offer_id: OfferId::random().map_err(|_| "secure random unavailable")?,
        suites: vec![PAIRING_SUITE.into()],
        profiles: requested_profiles.clone(),
        transports: vec![TransportCandidate {
            profile: STREAM_PROFILE.into(),
            candidate_id: CANDIDATE_ID.into(),
            parameters: stream_candidate_parameters(&options.advertise)
                .map_err(|error| format!("invalid advertised endpoints: {error:?}"))?,
        }],
        offer_ttl_ms: OFFER_TTL_MAX_MS,
    };
    let secret = PairingSecret::random().map_err(|_| "secure random unavailable")?;
    let secret_bytes = secret.0;
    let uri = offer
        .to_uri(&secret)
        .map_err(|error| format!("offer encoding failed: {error:?}"))?;

    let qr = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|error| format!("QR encoding failed: {error}"))?;
    println!(
        "{}",
        qr.render::<qrcode::render::unicode::Dense1x2>().build()
    );
    println!("scan with ReFineID on the iPhone; the offer expires in three minutes");
    println!();
    println!("offer text (the QR encodes exactly this):");
    println!("{uri}");
    flush_now();

    let deadline = Instant::now() + Duration::from_millis(OFFER_TTL_MAX_MS);
    let pair_id = loop {
        if Instant::now() >= deadline {
            return Err("the pairing offer expired".into());
        }
        let accepted = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                println!("discarded connection: {error:?}");
                continue;
            }
        };
        let StreamAccept::Pairing(transport) = accepted else {
            println!("discarded a session attempt before any pairing exists");
            continue;
        };
        match requester.pair(
            &offer,
            PairingSecret(secret_bytes),
            &requested_profiles,
            transport,
            confirm_grants,
        ) {
            Ok(pair_id) => break pair_id,
            Err(error) => {
                println!("pairing attempt failed: {error:?}; the offer stays live");
            }
        }
    };
    drop(PairingSecret(secret_bytes));

    let expected_token = {
        let record = requester
            .store()
            .get(pair_id)
            .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
        println!(
            "paired with {} ({}); granted: {}",
            record.peer_display_name,
            record.peer_platform,
            record.granted_profiles.join(", ")
        );
        record.rendezvous_token
    };
    flush_now();

    serve_sessions(
        &mut requester,
        &listener,
        pair_id,
        expected_token,
        options.sign_profile,
    )
}

/// Serves inbound sessions for one pairing until interrupted: for each session
/// the phone dials, it connects, runs the read operations and an optional
/// signature, and disconnects. Shared by `pair-demo` and `reconnect`.
fn serve_sessions<S: PairingStore>(
    requester: &mut Requester<S, MemoryJournal>,
    listener: &StreamListener,
    pair_id: PairId,
    expected_token: RendezvousToken,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
) -> Result<(), String> {
    println!("waiting for the phone to connect; open ReFineID and choose this computer");
    flush_now();
    loop {
        let accepted = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                println!("discarded connection: {error:?}");
                continue;
            }
        };
        let StreamAccept::Session {
            rendezvous_token,
            transport,
        } = accepted
        else {
            println!("discarded a pairing attempt; no offer is active");
            continue;
        };
        if rendezvous_token != expected_token {
            println!("discarded a session for an unknown rendezvous token");
            continue;
        }
        let mut session = match requester.connect(pair_id, transport) {
            Ok(session) => session,
            Err(error) => {
                println!("session establishment failed: {error:?}");
                continue;
            }
        };
        println!("session healthy; running operations (approve each on the phone)");
        flush_now();

        let mut operations = vec![
            CardOperation::InspectCard,
            CardOperation::ReadIdentity,
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            },
        ];
        if let Some((key_profile, algorithm)) = sign_profile {
            operations.push(CardOperation::BrowserAuthenticate {
                origin: "rapp-demo.refineid.fi".into(),
                key_profile,
                algorithm,
                digest: demo_digest(algorithm)?,
            });
        }
        for operation in &operations {
            print!("{} ... ", operation.action());
            let _ = std::io::stdout().flush();
            match requester.execute(&mut session, operation, OPERATION_EXPIRY_MS) {
                Ok(outcome) => {
                    report(operation, &outcome);
                    flush_now();
                }
                Err(error) => {
                    println!("not admitted: {error:?}");
                    break;
                }
            }
            if requester.store().get(pair_id).is_err() {
                return Err("the pairing is gone; pair again".into());
            }
        }
        requester.disconnect(&mut session, CloseReason::UserDisconnect);
        println!("session closed; waiting for the next connection (Ctrl-C to quit)");
        flush_now();
    }
}

/// Pushes buffered output through redirected stdout, which is block
/// buffered, so progress is visible while the process waits.
fn flush_now() {
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// The both-device grant confirmation of specification Section 9.3 step 7.
fn confirm_grants(peer: &PeerIntroduction, requested: &[String]) -> Option<Vec<String>> {
    println!();
    println!(
        "pairing request from {} ({})",
        peer.display_name, peer.platform
    );
    println!("grants to confirm: {}", requested.join(", "));
    print!("confirm this exact pairing? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    if line.trim().eq_ignore_ascii_case("y") {
        Some(requested.to_vec())
    } else {
        None
    }
}

/// A fresh random digest of the algorithm's registered length.
fn demo_digest(algorithm: SignatureAlgorithm) -> Result<Vec<u8>, String> {
    let mut digest = Vec::new();
    while digest.len() < algorithm.digest_length() {
        let challenge = Challenge::random().map_err(|_| "secure random unavailable")?;
        digest.extend_from_slice(&challenge.0);
    }
    digest.truncate(algorithm.digest_length());
    Ok(digest)
}

fn report(operation: &CardOperation, outcome: &OperationOutcome) {
    match outcome {
        OperationOutcome::Completed(result) => match result {
            CardOperationResult::Inspection {
                pin1_factory,
                pin2_factory,
                pin1_attempts,
                pin2_attempts,
                puk_attempts,
            } => {
                println!(
                    "ok: pin1 factory {pin1_factory}, pin2 factory {pin2_factory}, attempts {}",
                    attempts_label(*pin1_attempts, *pin2_attempts, *puk_attempts)
                );
            }
            CardOperationResult::Identity {
                display_name,
                person_id,
            } => {
                println!("ok: {display_name} ({})", masked(person_id));
            }
            CardOperationResult::Certificate(der) => {
                println!("ok: certificate, {} bytes DER", der.len());
            }
            CardOperationResult::Signature(bytes) => {
                println!("ok: signature, {} bytes", bytes.len());
            }
        },
        OperationOutcome::Denied => println!("denied on the phone"),
        OperationOutcome::Cancelled => println!("cancelled or expired"),
        OperationOutcome::Rejected(reason) => {
            println!("rejected: {}", reason.as_deref().unwrap_or("unnamed"));
        }
        OperationOutcome::CredentialRejected => {
            println!("credential rejected; the pairing is revoked on both devices");
        }
        OperationOutcome::Ambiguous => {
            println!(
                "ambiguous: {} may or may not have executed; it will not be retried",
                operation.action()
            );
        }
    }
}

fn attempts_label(pin1: Option<u8>, pin2: Option<u8>, puk: Option<u8>) -> String {
    let label = |value: Option<u8>| value.map_or_else(|| "?".to_owned(), |count| count.to_string());
    format!(
        "pin1 {}, pin2 {}, puk {}",
        label(pin1),
        label(pin2),
        label(puk)
    )
}

fn masked(person_id: &str) -> String {
    let visible: String = person_id.chars().take(PERSON_ID_VISIBLE_CHARS).collect();
    format!("{visible}…")
}
