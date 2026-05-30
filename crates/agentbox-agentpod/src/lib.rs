use serde::{Deserialize, Serialize};
use std::fmt;

pub const PROVIDER_LINUX: &str = "agentpod-linux";
pub const PROVIDER_MACOS: &str = "agentpod-macos";
pub const PROVIDER_WINDOWS: &str = "agentpod-windows";
pub const PROVIDER_REMOTE: &str = "remote-agentpod";

pub const ENFORCEMENT_DESCRIPTOR_ONLY_OR_UNOBSERVED: &str = "descriptor-only-or-unobserved";
pub const ENFORCEMENT_PROTOTYPE_NATIVE_RUNNER_EVIDENCE: &str = "prototype-native-runner-evidence";
pub const ENFORCEMENT_REMOTE_WORKER_CONTRACT_EVIDENCE: &str = "remote-worker-contract-evidence";

pub const RUNNER_PHASE_STATUS_ACTIVE: &str = "active";
pub const RUNNER_PHASE_STATUS_DESCRIPTOR: &str = "descriptor";
pub const RUNNER_PHASE_STATUS_INACTIVE: &str = "inactive";
pub const RUNNER_PHASE_STATUS_PLANNED: &str = "planned";
pub const RUNNER_PHASE_STATUS_PROTOTYPE: &str = "prototype";
pub const RUNNER_PHASE_STATUS_SHIPPED: &str = "shipped";

pub const LINUX_SKIPPED_PRIMITIVES: &[&str] = &[
    "complete libseccomp compatibility beyond the supported import subset",
    "complete Landlock ABI coverage",
    "nftables packet/domain enforcement",
    "cross-host overlayfs live proof",
];

pub const WINDOWS_SKIPPED_PRIMITIVES: &[&str] = &[
    "live Windows Job Object apply proof",
    "live AppContainer profile/ACL proof",
    "live WFP packet/domain enforcement",
    "live ETW capture/export",
    "live VM lifecycle",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentPodProviderId {
    Linux,
    MacOs,
    Windows,
    Remote,
}

impl AgentPodProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => PROVIDER_LINUX,
            Self::MacOs => PROVIDER_MACOS,
            Self::Windows => PROVIDER_WINDOWS,
            Self::Remote => PROVIDER_REMOTE,
        }
    }

    pub fn is_native(self) -> bool {
        !matches!(self, Self::Remote)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            PROVIDER_LINUX => Some(Self::Linux),
            PROVIDER_MACOS => Some(Self::MacOs),
            PROVIDER_WINDOWS => Some(Self::Windows),
            PROVIDER_REMOTE => Some(Self::Remote),
            _ => None,
        }
    }
}

impl fmt::Display for AgentPodProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentPodEnforcementStatus {
    DescriptorOnlyOrUnobserved,
    PrototypeNativeRunnerEvidence,
    RemoteWorkerContractEvidence,
}

impl AgentPodEnforcementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DescriptorOnlyOrUnobserved => ENFORCEMENT_DESCRIPTOR_ONLY_OR_UNOBSERVED,
            Self::PrototypeNativeRunnerEvidence => ENFORCEMENT_PROTOTYPE_NATIVE_RUNNER_EVIDENCE,
            Self::RemoteWorkerContractEvidence => ENFORCEMENT_REMOTE_WORKER_CONTRACT_EVIDENCE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPodNativeReceiptSummary {
    pub schema_version: i64,
    pub provider: String,
    pub enforcement_status: String,
    pub runner_phases: Vec<AgentPodRunnerPhaseReceipt>,
    pub enforced_phases: Vec<String>,
    pub skipped_planned_primitives: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPodRunnerPhaseReceipt {
    pub phase: String,
    pub status: String,
    pub event_name: String,
    pub evidence_ref: Option<String>,
}

pub fn is_agentpod_provider(provider: &str) -> bool {
    AgentPodProviderId::parse(provider).is_some()
}

pub fn is_native_agentpod_provider(provider: &str) -> bool {
    AgentPodProviderId::parse(provider).is_some_and(AgentPodProviderId::is_native)
}

pub fn runner_phase_status_counts_as_enforced(status: &str) -> bool {
    matches!(
        status,
        RUNNER_PHASE_STATUS_PROTOTYPE | RUNNER_PHASE_STATUS_SHIPPED | RUNNER_PHASE_STATUS_ACTIVE
    )
}

pub fn runner_phase_status_counts_as_skipped(status: &str) -> bool {
    matches!(
        status,
        RUNNER_PHASE_STATUS_INACTIVE | RUNNER_PHASE_STATUS_PLANNED | RUNNER_PHASE_STATUS_DESCRIPTOR
    )
}

pub fn skipped_primitives_for_provider(provider: &str) -> Vec<String> {
    match provider {
        PROVIDER_LINUX => LINUX_SKIPPED_PRIMITIVES
            .iter()
            .map(|primitive| (*primitive).to_string())
            .collect(),
        PROVIDER_WINDOWS => WINDOWS_SKIPPED_PRIMITIVES
            .iter()
            .map(|primitive| (*primitive).to_string())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_roundtrip_as_stable_product_vocabulary() {
        assert_eq!(AgentPodProviderId::Linux.as_str(), PROVIDER_LINUX);
        assert_eq!(AgentPodProviderId::MacOs.as_str(), PROVIDER_MACOS);
        assert_eq!(AgentPodProviderId::Windows.as_str(), PROVIDER_WINDOWS);
        assert_eq!(AgentPodProviderId::Remote.as_str(), PROVIDER_REMOTE);
        assert_eq!(
            AgentPodProviderId::parse(PROVIDER_LINUX),
            Some(AgentPodProviderId::Linux)
        );
        assert!(AgentPodProviderId::parse("podman-compat").is_none());
        assert!(is_agentpod_provider(PROVIDER_REMOTE));
        assert!(is_native_agentpod_provider(PROVIDER_LINUX));
        assert!(!is_native_agentpod_provider(PROVIDER_REMOTE));
    }

    #[test]
    fn enforcement_statuses_stay_string_backwards_compatible() {
        assert_eq!(
            AgentPodEnforcementStatus::DescriptorOnlyOrUnobserved.as_str(),
            ENFORCEMENT_DESCRIPTOR_ONLY_OR_UNOBSERVED
        );
        assert_eq!(
            AgentPodEnforcementStatus::PrototypeNativeRunnerEvidence.as_str(),
            ENFORCEMENT_PROTOTYPE_NATIVE_RUNNER_EVIDENCE
        );
        assert_eq!(
            AgentPodEnforcementStatus::RemoteWorkerContractEvidence.as_str(),
            ENFORCEMENT_REMOTE_WORKER_CONTRACT_EVIDENCE
        );
    }

    #[test]
    fn runner_phase_statuses_classify_enforced_and_skipped_boundaries() {
        assert!(runner_phase_status_counts_as_enforced(
            RUNNER_PHASE_STATUS_PROTOTYPE
        ));
        assert!(runner_phase_status_counts_as_enforced(
            RUNNER_PHASE_STATUS_SHIPPED
        ));
        assert!(runner_phase_status_counts_as_skipped(
            RUNNER_PHASE_STATUS_INACTIVE
        ));
        assert!(runner_phase_status_counts_as_skipped(
            RUNNER_PHASE_STATUS_DESCRIPTOR
        ));
        assert!(!runner_phase_status_counts_as_enforced(
            RUNNER_PHASE_STATUS_PLANNED
        ));
    }

    #[test]
    fn skipped_primitives_are_provider_scoped() {
        let linux = skipped_primitives_for_provider(PROVIDER_LINUX);
        assert!(linux.contains(&"nftables packet/domain enforcement".to_string()));
        let windows = skipped_primitives_for_provider(PROVIDER_WINDOWS);
        assert!(windows.contains(&"live WFP packet/domain enforcement".to_string()));
        assert!(skipped_primitives_for_provider(PROVIDER_MACOS).is_empty());
    }

    #[test]
    fn native_receipt_summary_remains_plain_json_shape() {
        let receipt = AgentPodNativeReceiptSummary {
            schema_version: 1,
            provider: PROVIDER_LINUX.into(),
            enforcement_status: ENFORCEMENT_DESCRIPTOR_ONLY_OR_UNOBSERVED.into(),
            runner_phases: vec![AgentPodRunnerPhaseReceipt {
                phase: "apply-seccomp".into(),
                status: RUNNER_PHASE_STATUS_PROTOTYPE.into(),
                event_name: "agentpod.linux.runner.seccomp.applied".into(),
                evidence_ref: Some("event-hash".into()),
            }],
            enforced_phases: vec!["apply-seccomp".into()],
            skipped_planned_primitives: skipped_primitives_for_provider(PROVIDER_LINUX),
            evidence_refs: vec!["event-hash".into()],
        };
        assert_eq!(receipt.provider, PROVIDER_LINUX);
        assert_eq!(
            receipt.enforcement_status,
            ENFORCEMENT_DESCRIPTOR_ONLY_OR_UNOBSERVED
        );
        assert_eq!(receipt.runner_phases[0].phase, "apply-seccomp");
    }
}
