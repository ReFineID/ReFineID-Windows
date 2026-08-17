//! Device-local serialization of a pairing record.
//!
//! A durable [`PairingStore`](crate::store::PairingStore) — on Windows, the
//! platform credential store — needs the record's bytes. This module is the
//! only serialization boundary for [`PairingRecord`]: a versioned, length-framed
//! encoding with no external serde surface, so the pair-specific private key is
//! never handed to a general-purpose serializer or format.
//!
//! The encoded blob carries the private key, so [`encode_pairing_record`]
//! returns it inside [`Zeroizing`]; callers hand it straight to device-only
//! secret storage and never log it. [`decode_pairing_record`] bounds-checks
//! every field and rejects trailing bytes, so a truncated or tampered blob
//! fails closed rather than yielding a half-built record. Neither direction
//! ever prints a key.

use zeroize::Zeroizing;

use crate::ids::{PairId, RendezvousToken};
use crate::store::{PairingDisposition, PairingRecord};

/// Format tag identifying a `ReFineID` pairing-record blob.
const PAIRING_BLOB_MAGIC: &[u8] = b"RAPP-pair-record";

/// The encoding revision. A future field change increments this and the
/// decoder refuses an unknown value rather than misreading an old blob.
const PAIRING_BLOB_VERSION: u8 = 1;

/// Disposition tag for a usable pairing.
const DISPOSITION_PAIRED: u8 = 0;
/// Disposition tag for a revoked (tombstoned) pairing.
const DISPOSITION_REVOKED: u8 = 1;

/// Boolean false on the wire.
const BOOLEAN_FALSE: u8 = 0;
/// Boolean true on the wire.
const BOOLEAN_TRUE: u8 = 1;

/// Why a stored pairing blob could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingCodecError {
    /// The blob did not begin with the pairing-record format tag.
    BadMagic,
    /// The blob used an encoding revision this build does not understand.
    UnsupportedVersion {
        /// The revision found in the blob.
        found: u8,
    },
    /// The blob ended before a field was fully read.
    Truncated,
    /// Bytes remained after the last field was read.
    TrailingBytes,
    /// A disposition tag was neither paired nor revoked.
    InvalidDisposition,
    /// A boolean field was neither zero nor one.
    InvalidBoolean,
    /// A text field was not valid UTF-8.
    InvalidText,
}

impl core::fmt::Display for PairingCodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("blob is not a pairing record"),
            Self::UnsupportedVersion { found } => {
                write!(formatter, "unsupported pairing-record revision {found}")
            }
            Self::Truncated => formatter.write_str("pairing record ended mid-field"),
            Self::TrailingBytes => formatter.write_str("pairing record had trailing bytes"),
            Self::InvalidDisposition => {
                formatter.write_str("pairing record had an unknown disposition")
            }
            Self::InvalidBoolean => formatter.write_str("pairing record had a malformed flag"),
            Self::InvalidText => formatter.write_str("pairing record held invalid text"),
        }
    }
}

impl core::error::Error for PairingCodecError {}

/// Serializes a pairing record for device-only secret storage.
///
/// The returned blob contains the pair-specific private key and is therefore
/// wrapped in [`Zeroizing`]: hand it directly to the platform credential store
/// and never log it.
#[must_use]
pub fn encode_pairing_record(record: &PairingRecord) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(PAIRING_BLOB_MAGIC);
    out.push(PAIRING_BLOB_VERSION);
    out.extend_from_slice(&record.pair_id.0);
    out.extend_from_slice(&record.rendezvous_token.0);
    out.extend_from_slice(&record.grants_hash);
    out.push(disposition_tag(record.disposition));
    out.push(if record.peer_initiated_termination {
        BOOLEAN_TRUE
    } else {
        BOOLEAN_FALSE
    });
    out.extend_from_slice(&record.candidate_failures.to_be_bytes());
    put_bytes(&mut out, &record.local_private);
    put_bytes(&mut out, &record.local_public);
    put_bytes(&mut out, &record.peer_public);
    put_length(&mut out, record.granted_profiles.len());
    for profile in &record.granted_profiles {
        put_bytes(&mut out, profile.as_bytes());
    }
    put_bytes(&mut out, record.peer_display_name.as_bytes());
    put_bytes(&mut out, record.peer_platform.as_bytes());
    out
}

/// Reconstructs a pairing record from a device-only blob.
///
/// # Errors
///
/// Fails when the blob is not a pairing record, uses an unknown revision, ends
/// mid-field, carries trailing bytes, or holds a malformed field.
pub fn decode_pairing_record(blob: &[u8]) -> Result<PairingRecord, PairingCodecError> {
    let mut reader = Reader::new(blob);
    if reader.take(PAIRING_BLOB_MAGIC.len())? != PAIRING_BLOB_MAGIC {
        return Err(PairingCodecError::BadMagic);
    }
    let version = reader.take_u8()?;
    if version != PAIRING_BLOB_VERSION {
        return Err(PairingCodecError::UnsupportedVersion { found: version });
    }

    let pair_id = PairId(reader.take_array()?);
    let rendezvous_token = RendezvousToken(reader.take_array()?);
    let grants_hash = reader.take_array()?;
    let disposition = disposition_from_tag(reader.take_u8()?)?;
    let peer_initiated_termination = boolean_from_tag(reader.take_u8()?)?;
    let candidate_failures = u32::from_be_bytes(reader.take_array()?);
    let local_private = Zeroizing::new(reader.take_length_prefixed()?.to_vec());
    let local_public = reader.take_length_prefixed()?.to_vec();
    let peer_public = reader.take_length_prefixed()?.to_vec();

    let profile_count = reader.take_length()?;
    let mut granted_profiles = Vec::with_capacity(profile_count);
    for _ in 0..profile_count {
        granted_profiles.push(reader.take_text()?);
    }
    let peer_display_name = reader.take_text()?;
    let peer_platform = reader.take_text()?;

    reader.finish()?;

    Ok(PairingRecord {
        pair_id,
        rendezvous_token,
        local_private,
        local_public,
        peer_public,
        granted_profiles,
        grants_hash,
        peer_display_name,
        peer_platform,
        disposition,
        peer_initiated_termination,
        candidate_failures,
    })
}

/// Maps a disposition to its wire tag.
const fn disposition_tag(disposition: PairingDisposition) -> u8 {
    match disposition {
        PairingDisposition::Paired => DISPOSITION_PAIRED,
        PairingDisposition::Revoked => DISPOSITION_REVOKED,
    }
}

/// Maps a wire tag to a disposition.
const fn disposition_from_tag(tag: u8) -> Result<PairingDisposition, PairingCodecError> {
    match tag {
        DISPOSITION_PAIRED => Ok(PairingDisposition::Paired),
        DISPOSITION_REVOKED => Ok(PairingDisposition::Revoked),
        _ => Err(PairingCodecError::InvalidDisposition),
    }
}

/// Maps a wire tag to a boolean.
const fn boolean_from_tag(tag: u8) -> Result<bool, PairingCodecError> {
    match tag {
        BOOLEAN_FALSE => Ok(false),
        BOOLEAN_TRUE => Ok(true),
        _ => Err(PairingCodecError::InvalidBoolean),
    }
}

/// Appends a count as a big-endian `u32`.
fn put_length(out: &mut Vec<u8>, length: usize) {
    // Every length here is a key size, a bounded profile name, or a small
    // count, so it fits a u32; a saturating cast keeps the encoder infallible
    // without a silent wrap.
    let bounded = u32::try_from(length).unwrap_or(u32::MAX);
    out.extend_from_slice(&bounded.to_be_bytes());
}

/// Appends a length-prefixed byte string.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_length(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A bounds-checked forward cursor over a blob.
struct Reader<'blob> {
    remaining: &'blob [u8],
}

impl<'blob> Reader<'blob> {
    const fn new(blob: &'blob [u8]) -> Self {
        Self { remaining: blob }
    }

    /// Takes exactly `count` bytes or reports truncation.
    const fn take(&mut self, count: usize) -> Result<&'blob [u8], PairingCodecError> {
        if self.remaining.len() < count {
            return Err(PairingCodecError::Truncated);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    /// Takes one byte.
    fn take_u8(&mut self) -> Result<u8, PairingCodecError> {
        Ok(self.take(1)?[0])
    }

    /// Takes a fixed-size array.
    fn take_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], PairingCodecError> {
        let slice = self.take(LENGTH)?;
        let mut array = [0_u8; LENGTH];
        array.copy_from_slice(slice);
        Ok(array)
    }

    /// Takes a big-endian `u32` length as a `usize`.
    fn take_length(&mut self) -> Result<usize, PairingCodecError> {
        // A u32 always fits the usize this crate targets (32- and 64-bit).
        Ok(u32::from_be_bytes(self.take_array()?) as usize)
    }

    /// Takes a length-prefixed byte string.
    fn take_length_prefixed(&mut self) -> Result<&'blob [u8], PairingCodecError> {
        let length = self.take_length()?;
        self.take(length)
    }

    /// Takes a length-prefixed UTF-8 string.
    fn take_text(&mut self) -> Result<String, PairingCodecError> {
        let bytes = self.take_length_prefixed()?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_error| PairingCodecError::InvalidText)
    }

    /// Confirms the blob was consumed exactly.
    const fn finish(&self) -> Result<(), PairingCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PairingCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use zeroize::Zeroizing;

    use super::{
        PAIRING_BLOB_MAGIC, PAIRING_BLOB_VERSION, PairingCodecError, decode_pairing_record,
        encode_pairing_record,
    };
    use crate::ids::{PairId, RendezvousToken};
    use crate::store::{PairingDisposition, PairingRecord};

    fn sample() -> PairingRecord {
        PairingRecord {
            pair_id: PairId([7; 16]),
            rendezvous_token: RendezvousToken([9; 16]),
            local_private: Zeroizing::new(vec![1; 32]),
            local_public: vec![2; 32],
            peer_public: vec![3; 32],
            granted_profiles: vec![
                "fi.eid.authentication.v1".into(),
                "fi.eid.document-signing.v1".into(),
            ],
            grants_hash: [4; 32],
            peer_display_name: "Petri's iPhone".into(),
            peer_platform: "iOS".into(),
            disposition: PairingDisposition::Paired,
            peer_initiated_termination: false,
            candidate_failures: 2,
        }
    }

    fn assert_same(left: &PairingRecord, right: &PairingRecord) {
        assert_eq!(left.pair_id, right.pair_id);
        assert_eq!(left.rendezvous_token, right.rendezvous_token);
        assert_eq!(
            left.local_private.as_slice(),
            right.local_private.as_slice()
        );
        assert_eq!(left.local_public, right.local_public);
        assert_eq!(left.peer_public, right.peer_public);
        assert_eq!(left.granted_profiles, right.granted_profiles);
        assert_eq!(left.grants_hash, right.grants_hash);
        assert_eq!(left.peer_display_name, right.peer_display_name);
        assert_eq!(left.peer_platform, right.peer_platform);
        assert_eq!(left.disposition, right.disposition);
        assert_eq!(
            left.peer_initiated_termination,
            right.peer_initiated_termination
        );
        assert_eq!(left.candidate_failures, right.candidate_failures);
    }

    #[test]
    fn round_trips_every_field() {
        let record = sample();
        let blob = encode_pairing_record(&record);
        let decoded = decode_pairing_record(&blob).unwrap();
        assert_same(&record, &decoded);
    }

    #[test]
    fn round_trips_a_revoked_tombstone() {
        let mut record = sample();
        record.disposition = PairingDisposition::Revoked;
        record.peer_initiated_termination = true;
        record.local_private = Zeroizing::new(Vec::new());
        record.peer_public = Vec::new();
        let decoded = decode_pairing_record(&encode_pairing_record(&record)).unwrap();
        assert_same(&record, &decoded);
    }

    #[test]
    fn rejects_a_foreign_blob() {
        assert!(matches!(
            decode_pairing_record(b"not a pairing record at all"),
            Err(PairingCodecError::BadMagic)
        ));
    }

    #[test]
    fn rejects_a_truncated_blob() {
        let blob = encode_pairing_record(&sample());
        let cut = &blob[..blob.len() - 1];
        assert!(matches!(
            decode_pairing_record(cut),
            Err(PairingCodecError::Truncated)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut blob = encode_pairing_record(&sample()).to_vec();
        blob.push(0);
        assert!(matches!(
            decode_pairing_record(&blob),
            Err(PairingCodecError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_an_unknown_revision() {
        let bogus_version = PAIRING_BLOB_VERSION.wrapping_add(9);
        let mut blob = encode_pairing_record(&sample()).to_vec();
        blob[PAIRING_BLOB_MAGIC.len()] = bogus_version;
        assert!(matches!(
            decode_pairing_record(&blob),
            Err(PairingCodecError::UnsupportedVersion { found })
                if found == bogus_version
        ));
    }
}
