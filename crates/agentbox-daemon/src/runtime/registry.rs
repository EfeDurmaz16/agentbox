use std::collections::BTreeMap;
use std::sync::Arc;

use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::providers::agentpod::{AgentPodProvider, AgentPodProviderKind};
use crate::runtime::providers::direct_host::DirectHostRuntimeProvider;
use crate::runtime::providers::podman::PodmanRuntimeProvider;
use crate::runtime::providers::remote::RemoteAgentPodProvider;
use crate::runtime::types::AgentPodRiskLevel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSelectionRequest {
    pub preferred_provider: Option<String>,
    pub risk: AgentPodRiskLevel,
}

impl Default for ProviderSelectionRequest {
    fn default() -> Self {
        Self {
            preferred_provider: None,
            risk: AgentPodRiskLevel::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSelectionCandidate {
    pub name: String,
    pub family: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSelectionExplanation {
    pub selected_provider: String,
    pub reason: String,
    pub candidates: Vec<ProviderSelectionCandidate>,
}

#[derive(Default)]
pub struct RuntimeProviderRegistry {
    providers: BTreeMap<String, Arc<dyn RuntimeProvider>>,
    default_provider: Option<String>,
}

impl RuntimeProviderRegistry {
    pub fn new() -> Self {
        <Self as Default>::default()
    }

    pub fn register(&mut self, provider: Arc<dyn RuntimeProvider>) {
        let name = provider.name().to_string();
        if self.default_provider.is_none() {
            self.default_provider = Some(name.clone());
        }
        self.providers.insert(name, provider);
    }

    pub fn set_default(&mut self, name: impl Into<String>) -> Result<(), RuntimeError> {
        let name = name.into();
        if !self.providers.contains_key(&name) {
            return Err(RuntimeError::Unavailable(format!(
                "provider not registered: {name}"
            )));
        }
        self.default_provider = Some(name);
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.providers.keys().map(String::as_str).collect()
    }

    pub fn get(&self, name: &str) -> Result<Arc<dyn RuntimeProvider>, RuntimeError> {
        self.providers
            .get(name)
            .cloned()
            .ok_or_else(|| RuntimeError::Unavailable(format!("provider not registered: {name}")))
    }

    pub fn default_provider(&self) -> Result<Arc<dyn RuntimeProvider>, RuntimeError> {
        let name = self
            .default_provider
            .as_deref()
            .ok_or_else(|| RuntimeError::Unavailable("no runtime provider registered".into()))?;
        self.get(name)
    }

    pub fn explain_selection(
        &self,
        request: &ProviderSelectionRequest,
    ) -> Result<ProviderSelectionExplanation, RuntimeError> {
        if let Some(preferred) = request.preferred_provider.as_deref() {
            self.get(preferred)?;
            return Ok(ProviderSelectionExplanation {
                selected_provider: preferred.to_string(),
                reason: "explicit provider requested".to_string(),
                candidates: self.selection_candidates(),
            });
        }

        let selected_provider = self.auto_provider_for_risk(&request.risk)?;

        self.get(&selected_provider)?;

        Ok(ProviderSelectionExplanation {
            reason: auto_provider_reason(&request.risk, &selected_provider),
            selected_provider,
            candidates: self.selection_candidates(),
        })
    }

    fn auto_provider_for_risk(&self, risk: &AgentPodRiskLevel) -> Result<String, RuntimeError> {
        let platform_agentpod = platform_agentpod_provider_name();

        match risk {
            AgentPodRiskLevel::Low => {
                if self.providers.contains_key("direct-host") {
                    Ok("direct-host".to_string())
                } else {
                    self.default_provider
                        .clone()
                        .ok_or_else(|| {
                            RuntimeError::Unavailable("no runtime provider registered".into())
                        })
                }
            }
            AgentPodRiskLevel::Medium => self
                .providers
                .contains_key("podman")
                .then(|| "podman".to_string())
                .ok_or_else(|| {
                    RuntimeError::Unavailable(
                        "no medium-risk runtime provider registered: podman is required for automatic medium-risk selection; request an explicit provider to override".into(),
                    )
                }),
            AgentPodRiskLevel::High | AgentPodRiskLevel::VeryHigh => self
                .providers
                .contains_key(platform_agentpod)
                .then(|| platform_agentpod.to_string())
                .ok_or_else(|| {
                    RuntimeError::Unavailable(format!(
                        "no platform AgentPod provider registered for {} risk: {platform_agentpod} is required for automatic high-risk selection; request an explicit provider to override",
                        risk.label()
                    ))
                }),
        }
    }

    fn selection_candidates(&self) -> Vec<ProviderSelectionCandidate> {
        self.providers
            .values()
            .map(|provider| ProviderSelectionCandidate {
                name: provider.name().to_string(),
                family: format!("{:?}", provider.family()),
                status: format!("{:?}", provider.implementation_status()),
            })
            .collect()
    }

    pub fn with_agentpod_descriptors() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::MacOs)));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::Linux)));
        registry.register(Arc::new(AgentPodProvider::new(
            AgentPodProviderKind::Windows,
        )));
        registry.register(Arc::new(RemoteAgentPodProvider::default()));
        registry
    }

    pub fn with_local_providers(agentbox_socket: String, shim_binary: String) -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(DirectHostRuntimeProvider::new()));
        registry.register(Arc::new(PodmanRuntimeProvider::new(
            agentbox_socket,
            shim_binary,
        )));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::MacOs)));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::Linux)));
        registry.register(Arc::new(AgentPodProvider::new(
            AgentPodProviderKind::Windows,
        )));
        registry.register(Arc::new(RemoteAgentPodProvider::default()));
        registry
    }
}

fn platform_agentpod_provider_name() -> &'static str {
    match AgentPodProviderKind::current_platform_candidate() {
        AgentPodProviderKind::MacOs => "agentpod-macos",
        AgentPodProviderKind::Linux => "agentpod-linux",
        AgentPodProviderKind::Windows => "agentpod-windows",
    }
}

fn auto_provider_reason(risk: &AgentPodRiskLevel, provider: &str) -> String {
    match risk {
        AgentPodRiskLevel::Low => {
            format!("{provider} selected as the lowest available local execution provider")
        }
        AgentPodRiskLevel::Medium => {
            format!("{provider} selected for governed local execution with reviewable boundaries")
        }
        AgentPodRiskLevel::High => {
            format!("{provider} selected because high-risk work should prefer native or VM-backed AgentPod isolation")
        }
        AgentPodRiskLevel::VeryHigh => {
            format!("{provider} selected because very-high-risk work should prefer disposable, VM-backed, or remote AgentPod isolation")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    use crate::runtime::types::{
        CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
    };

    struct NamedProvider(&'static str);

    #[async_trait]
    impl RuntimeProvider for NamedProvider {
        fn name(&self) -> &str {
            self.0
        }

        fn platform(&self) -> &str {
            "test"
        }

        fn capabilities(&self) -> &[RuntimeCapability] {
            &[]
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
            Ok(RuntimeSession::new(
                spec.name.clone(),
                self.name().to_string(),
                self.platform().to_string(),
                spec.clone(),
            ))
        }

        async fn exec(
            &self,
            _session_id: &str,
            _command: &ExecCommand,
        ) -> Result<CommandResult, RuntimeError> {
            Err(RuntimeError::ExecFailed("not implemented".into()))
        }

        async fn status(&self, _session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
            Ok(RuntimeStatus::Running)
        }

        async fn destroy(&self, _session_id: &str) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
            Ok(vec![])
        }
    }

    #[test]
    fn first_registered_provider_becomes_default() {
        let mut registry = RuntimeProviderRegistry::new();

        registry.register(Arc::new(NamedProvider("agentpod-macos")));
        registry.register(Arc::new(NamedProvider("podman")));

        assert_eq!(
            registry.default_provider().unwrap().name(),
            "agentpod-macos"
        );
        assert_eq!(registry.names(), vec!["agentpod-macos", "podman"]);
    }

    #[test]
    fn explicit_default_must_exist() {
        let mut registry = RuntimeProviderRegistry::new();
        registry.register(Arc::new(NamedProvider("podman")));

        registry.set_default("podman").unwrap();
        assert_eq!(registry.default_provider().unwrap().name(), "podman");

        let err = registry.set_default("agentpod-linux").unwrap_err();
        assert!(err.to_string().contains("not registered"));
    }

    #[test]
    fn unknown_provider_returns_unavailable() {
        let registry = RuntimeProviderRegistry::new();

        let err = match registry.default_provider() {
            Ok(provider) => panic!("expected unavailable provider, got {}", provider.name()),
            Err(err) => err,
        };

        assert!(matches!(err, RuntimeError::Unavailable(_)));
    }

    #[test]
    fn agentpod_descriptors_are_registered_without_claiming_availability() {
        let registry = RuntimeProviderRegistry::with_agentpod_descriptors();

        assert_eq!(
            registry.names(),
            vec![
                "agentpod-linux",
                "agentpod-macos",
                "agentpod-windows",
                "remote-agentpod"
            ]
        );
        assert_eq!(registry.get("agentpod-macos").unwrap().platform(), "macos");
        assert_eq!(
            registry.get("remote-agentpod").unwrap().platform(),
            "remote"
        );
    }

    #[test]
    fn local_provider_set_includes_podman_adapter_and_agentpod_candidates() {
        let registry = RuntimeProviderRegistry::with_local_providers(
            "/tmp/agentbox.sock".into(),
            "/tmp/agentbox-shim".into(),
        );

        assert_eq!(registry.default_provider().unwrap().name(), "direct-host");
        assert_eq!(
            registry.names(),
            vec![
                "agentpod-linux",
                "agentpod-macos",
                "agentpod-windows",
                "direct-host",
                "podman",
                "remote-agentpod"
            ]
        );
    }

    #[test]
    fn explicit_provider_selection_returns_requested_provider() {
        let registry = RuntimeProviderRegistry::with_agentpod_descriptors();
        let explanation = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: Some("agentpod-linux".into()),
                risk: AgentPodRiskLevel::Low,
            })
            .unwrap();

        assert_eq!(explanation.selected_provider, "agentpod-linux");
        assert_eq!(explanation.reason, "explicit provider requested");
        assert_eq!(explanation.candidates.len(), 4);
    }

    #[test]
    fn explicit_remote_provider_selection_is_visible_as_a_candidate() {
        let registry = RuntimeProviderRegistry::with_agentpod_descriptors();
        let explanation = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: Some("remote-agentpod".into()),
                risk: AgentPodRiskLevel::VeryHigh,
            })
            .unwrap();

        assert_eq!(explanation.selected_provider, "remote-agentpod");
        assert_eq!(explanation.reason, "explicit provider requested");
        assert!(explanation
            .candidates
            .iter()
            .any(|candidate| candidate.name == "remote-agentpod"));
    }

    #[test]
    fn high_risk_selection_prefers_platform_agentpod_candidate() {
        let registry = RuntimeProviderRegistry::with_local_providers(
            "/tmp/agentbox.sock".into(),
            "/tmp/agentbox-shim".into(),
        );
        let explanation = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: None,
                risk: AgentPodRiskLevel::High,
            })
            .unwrap();

        assert!(explanation.selected_provider.starts_with("agentpod-"));
        assert!(explanation.reason.contains("high-risk"));
    }

    #[test]
    fn high_risk_selection_refuses_fallback_when_platform_agentpod_missing() {
        let mut registry = RuntimeProviderRegistry::new();
        registry.register(Arc::new(NamedProvider("direct-host")));
        registry.register(Arc::new(NamedProvider("podman")));

        let err = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: None,
                risk: AgentPodRiskLevel::High,
            })
            .unwrap_err();

        assert!(matches!(err, RuntimeError::Unavailable(_)));
        assert!(err.to_string().contains("platform AgentPod provider"));
        assert!(err.to_string().contains("high"));
    }

    #[test]
    fn very_high_risk_selection_refuses_fallback_when_platform_agentpod_missing() {
        let mut registry = RuntimeProviderRegistry::new();
        registry.register(Arc::new(NamedProvider("direct-host")));
        registry.register(Arc::new(NamedProvider("podman")));

        let err = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: None,
                risk: AgentPodRiskLevel::VeryHigh,
            })
            .unwrap_err();

        assert!(matches!(err, RuntimeError::Unavailable(_)));
        assert!(err.to_string().contains("platform AgentPod provider"));
        assert!(err.to_string().contains("very-high"));
    }

    #[test]
    fn medium_risk_selection_uses_available_compat_provider_until_native_ships() {
        let registry = RuntimeProviderRegistry::with_local_providers(
            "/tmp/agentbox.sock".into(),
            "/tmp/agentbox-shim".into(),
        );
        let explanation = registry
            .explain_selection(&ProviderSelectionRequest::default())
            .unwrap();

        assert_eq!(explanation.selected_provider, "podman");
        assert!(explanation.reason.contains("governed local execution"));
    }

    #[test]
    fn medium_risk_selection_refuses_direct_host_fallback() {
        let mut registry = RuntimeProviderRegistry::new();
        registry.register(Arc::new(NamedProvider("direct-host")));

        let err = registry
            .explain_selection(&ProviderSelectionRequest::default())
            .unwrap_err();

        assert!(matches!(err, RuntimeError::Unavailable(_)));
        assert!(err.to_string().contains("medium"));
        assert!(err.to_string().contains("podman"));
    }

    #[test]
    fn low_risk_selection_uses_direct_host_provider() {
        let registry = RuntimeProviderRegistry::with_local_providers(
            "/tmp/agentbox.sock".into(),
            "/tmp/agentbox-shim".into(),
        );
        let explanation = registry
            .explain_selection(&ProviderSelectionRequest {
                preferred_provider: None,
                risk: AgentPodRiskLevel::Low,
            })
            .unwrap();

        assert_eq!(explanation.selected_provider, "direct-host");
        assert!(explanation.reason.contains("lowest available"));
    }
}
