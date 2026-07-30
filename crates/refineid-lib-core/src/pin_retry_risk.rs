// Copyright 2026 Petri Koistinen <petri.koistinen@iki.fi>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Refined FINEID PIN retry-risk states and consumer safety floors.

use crate::apdu::status_word::PinRetries;
use crate::auth::{PinStatus, PukStatus};

/// Security severity derived from the FINEID five-attempt PIN counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinRetryRisk {
    /// Five attempts remain: normal operating conditions.
    NormalOperatingConditions,
    /// Four attempts remain: a disturbance was detected.
    DisturbanceDetected,
    /// Three attempts remain: a security incident is declared.
    SecurityIncidentDeclared,
    /// Two attempts remain: only an explicitly authorized expert may proceed.
    CriticalThreatLevel,
    /// One attempt remains: card credential lockout is imminent.
    LockdownImminent,
    /// No attempts remain: the card credential is locked.
    DefencesFallen,
}

impl PinRetryRisk {
    /// Classify a FINEID retry counter. Values above the DVV limit of five are
    /// rejected rather than assigned a misleading risk state.
    #[must_use]
    pub const fn from_retries(retries: PinRetries) -> Option<Self> {
        match retries.get() {
            5 => Some(Self::NormalOperatingConditions),
            4 => Some(Self::DisturbanceDetected),
            3 => Some(Self::SecurityIncidentDeclared),
            2 => Some(Self::CriticalThreatLevel),
            1 => Some(Self::LockdownImminent),
            0 => Some(Self::DefencesFallen),
            _ => None,
        }
    }

    /// PKCS #11 permits PIN1 only at five or four attempts.
    #[must_use]
    pub const fn permits_pkcs11(self) -> bool {
        matches!(
            self,
            Self::NormalOperatingConditions | Self::DisturbanceDetected
        )
    }

    /// Ordinary graphical and system interfaces permit attempts down to three.
    #[must_use]
    pub const fn permits_consumer(self) -> bool {
        matches!(
            self,
            Self::NormalOperatingConditions
                | Self::DisturbanceDetected
                | Self::SecurityIncidentDeclared
        )
    }

    /// Reusable PIN1 caching requires a pristine five-attempt state.
    #[must_use]
    pub const fn permits_reusable_cache(self) -> bool {
        matches!(self, Self::NormalOperatingConditions)
    }

    /// Counts one and two require the CLI-only expert confirmation capability.
    #[must_use]
    pub const fn requires_expert_confirmation(self) -> bool {
        matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }

    /// SCS must terminate before a PIN operation at three or fewer attempts.
    #[must_use]
    pub const fn requires_scs_shutdown(self) -> bool {
        matches!(
            self,
            Self::SecurityIncidentDeclared
                | Self::CriticalThreatLevel
                | Self::LockdownImminent
                | Self::DefencesFallen
        )
    }
}

/// Whether all three live FINEID credential retry counters permit retaining
/// or sending a cached PIN1. Unknown, verified-without-a-counter, malformed,
/// and locked states all fail closed.
#[must_use]
pub const fn pin1_cache_counters_are_pristine(
    pin1: PinStatus,
    pin2: PinStatus,
    puk: PukStatus,
) -> bool {
    matches!(
        pin1,
        PinStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(PinRetryRisk::NormalOperatingConditions)
            )
    ) && matches!(
        pin2,
        PinStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(PinRetryRisk::NormalOperatingConditions)
            )
    ) && matches!(
        puk,
        PukStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(PinRetryRisk::NormalOperatingConditions)
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(retries: u8) -> Option<PinRetryRisk> {
        PinRetries::from_nibble(retries).and_then(PinRetryRisk::from_retries)
    }

    #[test]
    fn five_attempt_risk_ladder_is_total_and_ordered() {
        assert_eq!(risk(5), Some(PinRetryRisk::NormalOperatingConditions));
        assert_eq!(risk(4), Some(PinRetryRisk::DisturbanceDetected));
        assert_eq!(risk(3), Some(PinRetryRisk::SecurityIncidentDeclared));
        assert_eq!(risk(2), Some(PinRetryRisk::CriticalThreatLevel));
        assert_eq!(risk(1), Some(PinRetryRisk::LockdownImminent));
        assert_eq!(risk(0), Some(PinRetryRisk::DefencesFallen));
        assert_eq!(risk(6), None);
    }

    #[test]
    fn consumer_floors_follow_the_risk_ladder() {
        assert!(PinRetryRisk::NormalOperatingConditions.permits_reusable_cache());
        assert!(PinRetryRisk::DisturbanceDetected.permits_pkcs11());
        assert!(!PinRetryRisk::SecurityIncidentDeclared.permits_pkcs11());
        assert!(PinRetryRisk::SecurityIncidentDeclared.permits_consumer());
        assert!(!PinRetryRisk::CriticalThreatLevel.permits_consumer());
        assert!(PinRetryRisk::LockdownImminent.requires_expert_confirmation());
        assert!(!PinRetryRisk::DefencesFallen.requires_expert_confirmation());
        assert!(!PinRetryRisk::DisturbanceDetected.requires_scs_shutdown());
        assert!(PinRetryRisk::SecurityIncidentDeclared.requires_scs_shutdown());
    }

    #[test]
    fn cached_pin1_requires_all_counters_at_five() {
        let remaining = |count| {
            PinStatus::Remaining(
                PinRetries::from_nibble(count).expect("test retry count fits one nibble"),
            )
        };
        let puk_remaining = |count| {
            PukStatus::Remaining(
                PinRetries::from_nibble(count).expect("test retry count fits one nibble"),
            )
        };
        assert!(pin1_cache_counters_are_pristine(
            remaining(5),
            remaining(5),
            puk_remaining(5)
        ));
        assert!(!pin1_cache_counters_are_pristine(
            remaining(4),
            remaining(5),
            puk_remaining(5)
        ));
        assert!(!pin1_cache_counters_are_pristine(
            remaining(5),
            remaining(4),
            puk_remaining(5)
        ));
        assert!(!pin1_cache_counters_are_pristine(
            remaining(5),
            remaining(5),
            puk_remaining(4)
        ));
        assert!(!pin1_cache_counters_are_pristine(
            PinStatus::Verified,
            remaining(5),
            puk_remaining(5)
        ));
    }
}
