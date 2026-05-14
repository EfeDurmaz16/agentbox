use std::collections::BTreeMap;
use std::sync::Arc;

use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::providers::agentpod::{AgentPodProvider, AgentPodProviderKind};
use crate::runtime::providers::podman::PodmanRuntimeProvider;

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

    pub fn with_agentpod_descriptors() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::MacOs)));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::Linux)));
        registry.register(Arc::new(AgentPodProvider::new(
            AgentPodProviderKind::Windows,
        )));
        registry
    }

    pub fn with_local_providers(agentbox_socket: String, shim_binary: String) -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(PodmanRuntimeProvider::new(
            agentbox_socket,
            shim_binary,
        )));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::MacOs)));
        registry.register(Arc::new(AgentPodProvider::new(AgentPodProviderKind::Linux)));
        registry.register(Arc::new(AgentPodProvider::new(
            AgentPodProviderKind::Windows,
        )));
        registry
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
            vec!["agentpod-linux", "agentpod-macos", "agentpod-windows"]
        );
        assert_eq!(registry.get("agentpod-macos").unwrap().platform(), "macos");
    }

    #[test]
    fn local_provider_set_includes_podman_adapter_and_agentpod_candidates() {
        let registry = RuntimeProviderRegistry::with_local_providers(
            "/tmp/agentbox.sock".into(),
            "/tmp/agentbox-shim".into(),
        );

        assert_eq!(registry.default_provider().unwrap().name(), "podman");
        assert_eq!(
            registry.names(),
            vec![
                "agentpod-linux",
                "agentpod-macos",
                "agentpod-windows",
                "podman"
            ]
        );
    }
}
