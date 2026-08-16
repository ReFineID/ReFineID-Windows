//! The pairing offer and its QR text form, specification Section 9.2.
//!
//! The requester creates one offer per explicit user action and displays it
//! as a QR code. The QR encodes deterministic CBOR inside a `rapp:` URI
//! carrying unpadded base64url. The bearer secret travels only inside the QR;
//! `offer_hash` (Section 8.5) is computed over the offer with the secret
//! entry removed, which is what lets the hash be transcript-bound while the
//! secret contributes only as the handshake pre-shared key.

use sha2::{Digest, Sha256};

use crate::base64url;
use crate::cbor::Value;
use crate::ids::{OFFER_ID_LENGTH, OfferId, PAIRING_SECRET_LENGTH, PairingSecret};
use crate::limits;

/// The URI scheme and map discriminant of a pairing offer.
pub const OFFER_SCHEME: &str = "rapp";
/// The URI prefix of the QR text form.
const URI_PREFIX: &str = "rapp:";

/// Map key of the scheme discriminant.
const KEY_SCHEME: &str = "scheme";
/// Map key of the wire version.
const KEY_VERSION: &str = "version";
/// Map key of the offer identifier.
const KEY_OFFER_ID: &str = "offer_id";
/// Map key of the bearer secret.
const KEY_PAIRING_SECRET: &str = "pairing_secret";
/// Map key of the offered cryptographic suites.
const KEY_SUITES: &str = "suites";
/// Map key of the offered credential profiles.
const KEY_PROFILES: &str = "profiles";
/// Map key of the offered transport candidates.
const KEY_TRANSPORTS: &str = "transports";
/// Map key of the offer lifetime.
const KEY_OFFER_TTL_MS: &str = "offer_ttl_ms";
/// Map key of a candidate's transport profile.
const KEY_CANDIDATE_PROFILE: &str = "profile";
/// Map key of a candidate's identifier.
const KEY_CANDIDATE_ID: &str = "candidate_id";
/// Map key of a candidate's parameters.
const KEY_CANDIDATE_PARAMETERS: &str = "parameters";

/// One offered way to reach the requester, Section 9.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportCandidate {
    /// The transport profile name.
    pub profile: String,
    /// The candidate identifier echoed inside the first authenticated
    /// message of the channel (Section 8.4).
    pub candidate_id: String,
    /// Profile-defined reachability parameters.
    pub parameters: Vec<(String, Value)>,
}

impl TransportCandidate {
    /// The candidate as a wire map.
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                KEY_CANDIDATE_PROFILE.into(),
                Value::Text(self.profile.clone()),
            ),
            (
                KEY_CANDIDATE_ID.into(),
                Value::Text(self.candidate_id.clone()),
            ),
            (
                KEY_CANDIDATE_PARAMETERS.into(),
                Value::Map(self.parameters.clone()),
            ),
        ])
    }

    /// Reads one candidate from its wire map.
    fn from_value(value: &Value) -> Result<Self, OfferError> {
        let Value::Map(entries) = value else {
            return Err(OfferError::Malformed);
        };
        let mut profile = None;
        let mut candidate_id = None;
        let mut parameters = None;
        for (key, entry) in entries {
            match (key.as_str(), entry) {
                (KEY_CANDIDATE_PROFILE, Value::Text(text)) => profile = Some(text.clone()),
                (KEY_CANDIDATE_ID, Value::Text(text)) => candidate_id = Some(text.clone()),
                (KEY_CANDIDATE_PARAMETERS, Value::Map(map)) => parameters = Some(map.clone()),
                _ => return Err(OfferError::Malformed),
            }
        }
        Ok(Self {
            profile: profile.ok_or(OfferError::Malformed)?,
            candidate_id: candidate_id.ok_or(OfferError::Malformed)?,
            parameters: parameters.ok_or(OfferError::Malformed)?,
        })
    }
}

/// One pairing offer, without its bearer secret.
///
/// The secret is deliberately not a field: it has a different lifetime and a
/// zeroizing type, and `offer_hash` is defined over the secret-free map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingOffer {
    /// The two-element wire version.
    pub version: (u64, u64),
    /// The random offer identifier.
    pub offer_id: OfferId,
    /// Offered cryptographic suites, most preferred first.
    pub suites: Vec<String>,
    /// Offered credential profiles.
    pub profiles: Vec<String>,
    /// Offered transport candidates.
    pub transports: Vec<TransportCandidate>,
    /// Offer lifetime in milliseconds, bounded by
    /// [`limits::OFFER_TTL_MAX_MS`].
    pub offer_ttl_ms: u64,
}

/// Why an offer could not be built or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferError {
    /// The offer does not satisfy its schema.
    Malformed,
    /// The encoded offer exceeds [`limits::MAX_OFFER_SIZE`].
    TooLarge,
    /// More than [`limits::MAX_TRANSPORT_CANDIDATES`] candidates.
    TooManyCandidates,
    /// No suite, profile, or transport candidate was offered.
    EmptyChoice,
    /// The lifetime exceeds [`limits::OFFER_TTL_MAX_MS`].
    LifetimeTooLong,
    /// The URI prefix, base64url payload, or CBOR could not be read.
    UnreadableUri,
}

impl PairingOffer {
    /// Validates the structural rules every offer must satisfy.
    const fn validate(&self) -> Result<(), OfferError> {
        if self.suites.is_empty() || self.profiles.is_empty() || self.transports.is_empty() {
            return Err(OfferError::EmptyChoice);
        }
        if self.transports.len() > limits::MAX_TRANSPORT_CANDIDATES {
            return Err(OfferError::TooManyCandidates);
        }
        if self.offer_ttl_ms > limits::OFFER_TTL_MAX_MS {
            return Err(OfferError::LifetimeTooLong);
        }
        Ok(())
    }

    /// The offer as a wire map, with or without the bearer secret entry.
    fn to_value(&self, secret: Option<&PairingSecret>) -> Value {
        let mut entries = vec![
            (KEY_SCHEME.into(), Value::Text(OFFER_SCHEME.into())),
            (
                KEY_VERSION.into(),
                Value::Array(vec![
                    Value::Unsigned(self.version.0),
                    Value::Unsigned(self.version.1),
                ]),
            ),
            (KEY_OFFER_ID.into(), Value::Bytes(self.offer_id.0.to_vec())),
            (
                KEY_SUITES.into(),
                Value::Array(self.suites.iter().cloned().map(Value::Text).collect()),
            ),
            (
                KEY_PROFILES.into(),
                Value::Array(self.profiles.iter().cloned().map(Value::Text).collect()),
            ),
            (
                KEY_TRANSPORTS.into(),
                Value::Array(
                    self.transports
                        .iter()
                        .map(TransportCandidate::to_value)
                        .collect(),
                ),
            ),
            (KEY_OFFER_TTL_MS.into(), Value::Unsigned(self.offer_ttl_ms)),
        ];
        if let Some(secret) = secret {
            entries.push((KEY_PAIRING_SECRET.into(), Value::Bytes(secret.0.to_vec())));
        }
        Value::Map(entries)
    }

    /// The `offer_hash` of Section 8.5: SHA-256 over the deterministic
    /// encoding of the offer with the bearer-secret entry removed.
    ///
    /// # Errors
    ///
    /// Fails when the offer violates its structural rules or exceeds an
    /// encoding limit.
    pub fn offer_hash(&self) -> Result<[u8; 32], OfferError> {
        self.validate()?;
        let encoded = self
            .to_value(None)
            .encode()
            .map_err(|_| OfferError::Malformed)?;
        Ok(Sha256::digest(&encoded).into())
    }

    /// The QR text form: `rapp:` followed by unpadded base64url of the
    /// deterministic CBOR including the bearer secret.
    ///
    /// # Errors
    ///
    /// Fails when the offer violates its structural rules or the encoded
    /// form exceeds [`limits::MAX_OFFER_SIZE`].
    pub fn to_uri(&self, secret: &PairingSecret) -> Result<String, OfferError> {
        self.validate()?;
        let encoded = self
            .to_value(Some(secret))
            .encode()
            .map_err(|_| OfferError::Malformed)?;
        if encoded.len() > limits::MAX_OFFER_SIZE {
            return Err(OfferError::TooLarge);
        }
        Ok(format!("{URI_PREFIX}{}", base64url::encode(&encoded)))
    }

    /// Reads and validates an offer from its QR text form.
    ///
    /// This is the proxy-side entry point (Section 9.3 step 2); the crate
    /// carries it so loopback conformance tests exercise both directions of
    /// the format.
    ///
    /// # Errors
    ///
    /// Fails when the URI, its base64url payload, its CBOR, its schema, or a
    /// structural rule cannot be accepted.
    pub fn from_uri(uri: &str) -> Result<(Self, PairingSecret), OfferError> {
        let payload = uri
            .strip_prefix(URI_PREFIX)
            .ok_or(OfferError::UnreadableUri)?;
        let encoded = base64url::decode(payload).map_err(|_| OfferError::UnreadableUri)?;
        if encoded.len() > limits::MAX_OFFER_SIZE {
            return Err(OfferError::TooLarge);
        }
        let value = Value::decode(&encoded).map_err(|_| OfferError::UnreadableUri)?;
        let Value::Map(entries) = value else {
            return Err(OfferError::Malformed);
        };
        let mut version = None;
        let mut offer_id = None;
        let mut secret = None;
        let mut suites = None;
        let mut profiles = None;
        let mut transports = None;
        let mut offer_ttl_ms = None;
        let mut scheme_seen = false;
        for (key, entry) in &entries {
            match (key.as_str(), entry) {
                (KEY_SCHEME, Value::Text(text)) if text == OFFER_SCHEME => scheme_seen = true,
                (KEY_VERSION, Value::Array(parts)) => {
                    if let [Value::Unsigned(major), Value::Unsigned(minor)] = parts.as_slice() {
                        version = Some((*major, *minor));
                    } else {
                        return Err(OfferError::Malformed);
                    }
                }
                (KEY_OFFER_ID, Value::Bytes(bytes)) => {
                    let raw: [u8; OFFER_ID_LENGTH] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| OfferError::Malformed)?;
                    offer_id = Some(OfferId(raw));
                }
                (KEY_PAIRING_SECRET, Value::Bytes(bytes)) => {
                    let raw: [u8; PAIRING_SECRET_LENGTH] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| OfferError::Malformed)?;
                    secret = Some(PairingSecret(raw));
                }
                (KEY_SUITES, Value::Array(items)) => suites = Some(text_items(items)?),
                (KEY_PROFILES, Value::Array(items)) => profiles = Some(text_items(items)?),
                (KEY_TRANSPORTS, Value::Array(items)) => {
                    let mut candidates = Vec::with_capacity(items.len());
                    for item in items {
                        candidates.push(TransportCandidate::from_value(item)?);
                    }
                    transports = Some(candidates);
                }
                (KEY_OFFER_TTL_MS, Value::Unsigned(number)) => offer_ttl_ms = Some(*number),
                _ => return Err(OfferError::Malformed),
            }
        }
        if !scheme_seen {
            return Err(OfferError::Malformed);
        }
        let offer = Self {
            version: version.ok_or(OfferError::Malformed)?,
            offer_id: offer_id.ok_or(OfferError::Malformed)?,
            suites: suites.ok_or(OfferError::Malformed)?,
            profiles: profiles.ok_or(OfferError::Malformed)?,
            transports: transports.ok_or(OfferError::Malformed)?,
            offer_ttl_ms: offer_ttl_ms.ok_or(OfferError::Malformed)?,
        };
        offer.validate()?;
        Ok((offer, secret.ok_or(OfferError::Malformed)?))
    }
}

/// Reads an array of text items.
fn text_items(items: &[Value]) -> Result<Vec<String>, OfferError> {
    items
        .iter()
        .map(|item| match item {
            Value::Text(text) => Ok(text.clone()),
            _ => Err(OfferError::Malformed),
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::{OfferError, PairingOffer, TransportCandidate};
    use crate::cbor::Value;
    use crate::ids::{OfferId, PairingSecret};
    use crate::{PAIRING_SUITE, WIRE_VERSION, limits};

    fn sample_offer() -> PairingOffer {
        PairingOffer {
            version: WIRE_VERSION,
            offer_id: OfferId([0x11; 32]),
            suites: vec![PAIRING_SUITE.into()],
            profiles: vec!["fi.eid.card-status.v1".into()],
            transports: vec![TransportCandidate {
                profile: "fi.refineid.stream.v1".into(),
                candidate_id: "loopback-1".into(),
                parameters: vec![("address".into(), Value::Text("127.0.0.1:0".into()))],
            }],
            offer_ttl_ms: 120_000,
        }
    }

    #[test]
    fn uri_round_trips_offer_and_secret() {
        let offer = sample_offer();
        let secret = PairingSecret([0x22; 32]);
        let uri = offer.to_uri(&secret).unwrap();
        assert!(uri.starts_with("rapp:"));
        let (read, read_secret) = PairingOffer::from_uri(&uri).unwrap();
        assert_eq!(read, offer);
        assert_eq!(read_secret.0, [0x22; 32]);
    }

    #[test]
    fn offer_hash_excludes_the_secret() {
        let offer = sample_offer();
        let hash = offer.offer_hash().unwrap();
        // The hash is independent of any secret, so recomputing after a URI
        // round trip with a different secret yields the same value.
        let uri = offer.to_uri(&PairingSecret([0x33; 32])).unwrap();
        let (read, _) = PairingOffer::from_uri(&uri).unwrap();
        assert_eq!(read.offer_hash().unwrap(), hash);
    }

    #[test]
    fn structural_rules_are_enforced() {
        let mut empty = sample_offer();
        empty.profiles.clear();
        assert_eq!(empty.offer_hash(), Err(OfferError::EmptyChoice));

        let mut long_lived = sample_offer();
        long_lived.offer_ttl_ms = limits::OFFER_TTL_MAX_MS + 1;
        assert_eq!(long_lived.offer_hash(), Err(OfferError::LifetimeTooLong));

        let mut crowded = sample_offer();
        let candidate = crowded.transports[0].clone();
        crowded.transports = vec![candidate; limits::MAX_TRANSPORT_CANDIDATES + 1];
        assert_eq!(crowded.offer_hash(), Err(OfferError::TooManyCandidates));
    }

    #[test]
    fn foreign_uri_forms_are_rejected() {
        assert!(matches!(
            PairingOffer::from_uri("https://example.invalid/"),
            Err(OfferError::UnreadableUri)
        ));
        assert!(matches!(
            PairingOffer::from_uri("rapp:!!!"),
            Err(OfferError::UnreadableUri)
        ));
    }
}
