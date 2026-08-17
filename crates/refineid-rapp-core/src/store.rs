//! In-memory pairing records and the operation journal.
//!
//! A pairing exists only while its live, liveness-maintained connection
//! does (Sections 9.3 and 14.2): the record is held in memory beside the
//! session and removed when the session closes, which destroys the pair
//! keys. Nothing pairing-related is written at rest, and there is no
//! tombstone or reload path. The journal is the operation record of
//! Sections 12.2 and 12.6: the requester writes its commit intent before
//! sending commit, and terminal states are permanent for the record's life.
//!
//! Both stores are traits so callers can compose them; neither ever
//! contains a credential value, a card identifier, or message plaintext.

use zeroize::Zeroizing;

use crate::ids::{OperationId, PairId};
use crate::states::OperationState;

/// One live pairing's key material and labels.
pub struct PairingRecord {
    /// The derived pair identifier.
    pub pair_id: PairId,
    /// The local pair-specific private key. Never read after establishment
    /// — the single channel needs no further handshake — and held only so
    /// its zeroizing drop is the key destruction the specification requires
    /// when the pairing ends.
    pub local_private: Zeroizing<Vec<u8>>,
    /// The local pair-specific public key.
    pub local_public: Vec<u8>,
    /// The peer's pair-specific public key.
    pub peer_public: Vec<u8>,
    /// The granted credential profiles.
    pub granted_profiles: Vec<String>,
    /// The peer's display label. A label, not an identity.
    pub peer_display_name: String,
    /// The peer's platform label.
    pub peer_platform: String,
}

impl core::fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("pair_id", &self.pair_id)
            .finish_non_exhaustive()
    }
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No record exists for the identifier.
    Unknown,
    /// The backing store refused the write.
    WriteRefused,
}

/// The in-memory holder of live pairing records.
///
/// Removal is the key destruction that ends a pairing: implementations MUST
/// hold records only in memory, never at rest.
pub trait PairingStore {
    /// Holds a new record for the life of its connection.
    ///
    /// # Errors
    ///
    /// Fails when the backing store refuses the write.
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError>;

    /// Reads one record.
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError>;

    /// Removes one record entirely, destroying its keys.
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError>;
}

/// An in-memory pairing store for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
}

impl MemoryPairingStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PairingStore for MemoryPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.records.retain(|entry| entry.pair_id != record.pair_id);
        self.records.push(record);
        Ok(())
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        let before = self.records.len();
        self.records.retain(|entry| entry.pair_id != pair_id);
        if self.records.len() == before {
            return Err(StoreError::Unknown);
        }
        Ok(())
    }
}

/// One journaled operation on the requester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    /// The operation identifier.
    pub operation_id: OperationId,
    /// The pairing the operation ran under.
    pub pair_id: PairId,
    /// The request hash of the journaled request.
    pub request_hash: [u8; 32],
    /// The credential profile name.
    pub profile: String,
    /// The profile action name.
    pub action: String,
    /// The current requester-projection state.
    pub state: OperationState,
    /// Whether automatic retry is permanently forbidden (`INV-06`).
    pub retry_prohibited: bool,
    /// The proxy's journaled state from a Section 12.6 status answer,
    /// stored as an annotation that transitions nothing.
    pub reconciled_proxy_state: Option<String>,
}

/// The requester's durable operation journal.
pub trait OperationJournal {
    /// Creates or replaces the entry for one operation.
    ///
    /// The write must be durable before the call returns: the commit intent
    /// is journaled before `operation.commit` is sent.
    ///
    /// # Errors
    ///
    /// Fails when the backing store refuses the write.
    fn record(&mut self, entry: JournalEntry) -> Result<(), StoreError>;

    /// Reads the entry for one operation.
    ///
    /// # Errors
    ///
    /// Fails when no entry exists.
    fn get(&self, operation_id: OperationId) -> Result<&JournalEntry, StoreError>;

    /// The non-terminal entries needing Section 12.6 reconciliation.
    fn open_entries(&self) -> Vec<&JournalEntry>;
}

/// An in-memory journal for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryJournal {
    entries: Vec<JournalEntry>,
}

impl MemoryJournal {
    /// Creates an empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl OperationJournal for MemoryJournal {
    fn record(&mut self, entry: JournalEntry) -> Result<(), StoreError> {
        self.entries
            .retain(|existing| existing.operation_id != entry.operation_id);
        self.entries.push(entry);
        Ok(())
    }

    fn get(&self, operation_id: OperationId) -> Result<&JournalEntry, StoreError> {
        self.entries
            .iter()
            .find(|entry| entry.operation_id == operation_id)
            .ok_or(StoreError::Unknown)
    }

    fn open_entries(&self) -> Vec<&JournalEntry> {
        self.entries
            .iter()
            .filter(|entry| !entry.state.is_terminal())
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{
        JournalEntry, MemoryJournal, MemoryPairingStore, OperationJournal, PairingRecord,
        PairingStore, StoreError,
    };
    use crate::ids::{OperationId, PairId};
    use crate::states::OperationState;
    use zeroize::Zeroizing;

    fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord {
            pair_id,
            local_private: Zeroizing::new(vec![1; 32]),
            local_public: vec![2; 32],
            peer_public: vec![3; 32],
            granted_profiles: vec!["fi.eid.card-status.v1".into()],
            peer_display_name: "Phone".into(),
            peer_platform: "iOS".into(),
        }
    }

    #[test]
    fn pairing_records_live_until_removed() {
        let mut store = MemoryPairingStore::new();
        let pair_id = PairId([7; 16]);
        store.insert(record(pair_id)).unwrap();
        assert_eq!(store.get(pair_id).unwrap().peer_display_name, "Phone");
        store.remove(pair_id).unwrap();
        assert!(matches!(store.get(pair_id), Err(StoreError::Unknown)));
    }

    #[test]
    fn journal_reports_open_entries_only() {
        let mut journal = MemoryJournal::new();
        let open = JournalEntry {
            operation_id: OperationId([1; 16]),
            pair_id: PairId([7; 16]),
            request_hash: [0; 32],
            profile: "fi.eid.authentication.v1".into(),
            action: "sign".into(),
            state: OperationState::Committed,
            retry_prohibited: false,
            reconciled_proxy_state: None,
        };
        let done = JournalEntry {
            operation_id: OperationId([2; 16]),
            state: OperationState::Completed,
            ..open.clone()
        };
        journal.record(open.clone()).unwrap();
        journal.record(done).unwrap();
        let open_entries = journal.open_entries();
        assert_eq!(open_entries.len(), 1);
        assert_eq!(open_entries[0].operation_id, open.operation_id);
    }

    #[test]
    fn pairing_record_debug_redacts_keys() {
        let text = format!("{:?}", record(PairId([7; 16])));
        assert!(!text.contains('1'));
        assert!(text.contains("pair_id"));
    }
}
