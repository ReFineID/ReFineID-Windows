//! Remote Authorization Proxy Protocol (RAPP) requester core.
//!
//! This crate implements the requester role of RAPP draft 26.8.17.213 for the
//! Windows port: a Windows machine asks for typed credential operations, and
//! an authorization proxy — the holder's phone — presents consent, talks to
//! the identity card, and returns only the profile-defined result.
//!
//! The implementation tracks exactly the vendored specification revision in
//! `docs/protocol/rapp-v26.8.17.213.md` and its machine-readable transition
//! model `docs/protocol/rapp-state-machine-v26.8.17.213.yaml`. Section
//! references in this crate's documentation cite that document. Per its
//! Section 1, this is an experimental implementation of a review draft, not
//! a production security claim.
//!
//! Layering follows specification Section 5: deterministic CBOR wire
//! representation, one Noise pairing channel that continues as the live
//! session, typed messages, the role-projected state machines, and a
//! requester engine. A pairing is that single live connection: its keys are
//! held only in memory and every close ends the session and the pairing
//! together. Transport profiles are supplied through a trait; nothing here
//! trusts a transport to establish RAPP identity.

pub mod base64url;
pub mod cbor;
pub mod engine;
pub mod hashes;
pub mod ids;
pub mod message;
pub mod noise;
pub mod offer;
pub mod operations;
pub mod profiles;
pub mod states;
pub mod store;
pub mod stream;
pub mod transport;

/// The two-element wire version (specification Section 6). The engine
/// accepts exactly this tuple; the conformance corpus rejects every other.
pub const WIRE_VERSION: (u64, u64) = (26, 8);

/// The mandatory handshake construction (specification Section 8.1). RAPP
/// has exactly one handshake: the authenticated pairing channel it creates
/// continues as the live session.
pub const PAIRING_SUITE: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";

/// Named resource limits from specification Section 7.4.
pub mod limits {
    /// Maximum bytes in one Noise frame (`NOISE_MAX_MESSAGE`).
    pub const NOISE_MAX_MESSAGE: usize = 65_535;

    /// Maximum plaintext bytes in one envelope (`MAX_FRAME_PLAINTEXT`).
    pub const MAX_FRAME_PLAINTEXT: usize = 65_519;

    /// Maximum container nesting depth in one message (`MAX_NESTING_DEPTH`).
    pub const MAX_NESTING_DEPTH: usize = 8;

    /// Maximum UTF-8 bytes in one text string (`MAX_TEXT_SIZE`).
    pub const MAX_TEXT_SIZE: usize = 4_096;

    /// Maximum encoded pairing-offer bytes before QR encoding
    /// (`MAX_OFFER_SIZE`).
    pub const MAX_OFFER_SIZE: usize = 1_024;

    /// Maximum transport candidates in one offer
    /// (`MAX_TRANSPORT_CANDIDATES`).
    pub const MAX_TRANSPORT_CANDIDATES: usize = 8;

    /// Maximum concurrently active operations per proxy
    /// (`MAX_ACTIVE_OPERATIONS`).
    pub const MAX_ACTIVE_OPERATIONS: usize = 1;

    /// Maximum pairing-offer lifetime in milliseconds (`OFFER_TTL_MAX`).
    pub const OFFER_TTL_MAX_MS: u64 = 180_000;
}
