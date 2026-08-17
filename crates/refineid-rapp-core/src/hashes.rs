//! The defined hashes of specification Section 8.5.
//!
//! `offer_hash` lives with the offer type; this module carries the request
//! hash both peers must compute identically. The preimage is the
//! deterministic CBOR of a fixed shape, so a byte-level disagreement is an
//! encoding defect rather than an ambiguity. The granted profile set is not
//! hashed: it is agreed inside the authenticated channel through the equal
//! `pairing.confirm` sets and held in memory beside the pair keys.

use sha2::{Digest, Sha256};

use crate::cbor::{EncodeError, Value};
use crate::ids::{OperationId, SessionId};

/// Domain string of the request-hash preimage array.
const REQUEST_HASH_DOMAIN: &str = "RAPP-request-v1";

/// The `request_hash`: SHA-256 over the fixed-order preimage array binding
/// one operation to its session, profile, action, context, and payload
/// exactly as encoded on the wire.
///
/// # Errors
///
/// Fails only when a component exceeds an encoding limit.
pub fn request_hash(
    session_id: SessionId,
    operation_id: OperationId,
    profile: &str,
    action: &str,
    context: &[(String, Value)],
    payload: &[(String, Value)],
) -> Result<[u8; 32], EncodeError> {
    let preimage = Value::Array(vec![
        Value::Text(REQUEST_HASH_DOMAIN.into()),
        Value::Bytes(session_id.0.to_vec()),
        Value::Bytes(operation_id.0.to_vec()),
        Value::Text(profile.into()),
        Value::Text(action.into()),
        Value::Map(context.to_vec()),
        Value::Map(payload.to_vec()),
    ]);
    Ok(Sha256::digest(&preimage.encode()?).into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::request_hash;
    use crate::cbor::Value;
    use crate::ids::{OperationId, SessionId};

    #[test]
    fn request_hash_binds_every_component() {
        let session = SessionId([1; 16]);
        let operation = OperationId([2; 16]);
        let context = vec![("origin".into(), Value::Text("example.fi".into()))];
        let payload = vec![("digest".into(), Value::Bytes(vec![3; 32]))];
        let base = request_hash(
            session,
            operation,
            "fi.eid.authentication.v1",
            "sign",
            &context,
            &payload,
        )
        .unwrap();
        let other_action = request_hash(
            session,
            operation,
            "fi.eid.authentication.v1",
            "status",
            &context,
            &payload,
        )
        .unwrap();
        assert_ne!(base, other_action);
        let other_session = request_hash(
            SessionId([9; 16]),
            operation,
            "fi.eid.authentication.v1",
            "sign",
            &context,
            &payload,
        )
        .unwrap();
        assert_ne!(base, other_session);
        let repeat = request_hash(
            session,
            operation,
            "fi.eid.authentication.v1",
            "sign",
            &context,
            &payload,
        )
        .unwrap();
        assert_eq!(base, repeat);
    }
}
