use std::collections::BTreeSet;

use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::types::{
    ExecCommand, MinipodSpec, NetworkEnforcementCapability, RuntimeCapability,
};

pub(crate) fn assert_provider_metadata(
    provider: &dyn RuntimeProvider,
    expected_name: &str,
    expected_platform: &str,
    required_capabilities: &[RuntimeCapability],
) {
    assert_eq!(provider.name(), expected_name);
    assert_eq!(provider.platform(), expected_platform);
    assert!(!provider.capabilities().is_empty());

    let unique: BTreeSet<String> = provider
        .capabilities()
        .iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    assert_eq!(
        unique.len(),
        provider.capabilities().len(),
        "{} declares duplicate runtime capabilities",
        provider.name()
    );

    for capability in required_capabilities {
        assert!(
            provider.capabilities().contains(capability),
            "{} must declare {capability:?}",
            provider.name()
        );
    }

    let unique_network: BTreeSet<String> = provider
        .network_enforcement_capabilities()
        .iter()
        .map(|capability| format!("{capability:?}"))
        .collect();
    assert_eq!(
        unique_network.len(),
        provider.network_enforcement_capabilities().len(),
        "{} declares duplicate network enforcement capabilities",
        provider.name()
    );
}

pub(crate) fn assert_network_enforcement_metadata(
    provider: &dyn RuntimeProvider,
    required_capabilities: &[NetworkEnforcementCapability],
) {
    for capability in required_capabilities {
        assert!(
            provider
                .network_enforcement_capabilities()
                .contains(capability),
            "{} must declare network enforcement {capability:?}",
            provider.name()
        );
    }
}

pub(crate) async fn assert_unavailable_provider_contract(provider: &dyn RuntimeProvider) {
    let spec = MinipodSpec::for_agent_task("conformance-agent", "/tmp/agentbox-work");
    let command = ExecCommand {
        argv: vec!["true".to_string()],
        working_dir: Some("/workspace".to_string()),
        env: Default::default(),
        timeout_seconds: Some(1),
    };

    assert!(!provider.is_available().await);
    assert_unavailable(provider.create(&spec).await, provider.name());
    assert_unavailable(provider.exec(&spec.id, &command).await, provider.name());
    assert_unavailable(provider.status(&spec.id).await, provider.name());
    assert_unavailable(provider.destroy(&spec.id).await, provider.name());
    assert_unavailable(provider.list().await, provider.name());
}

fn assert_unavailable<T>(result: Result<T, RuntimeError>, provider_name: &str) {
    let error = match result {
        Ok(_) => panic!("descriptor provider should not execute runtime operations"),
        Err(error) => error,
    };
    assert!(
        matches!(error, RuntimeError::Unavailable(_)),
        "{provider_name} should return RuntimeError::Unavailable, got {error:?}"
    );
    assert!(
        error.to_string().contains(provider_name),
        "{provider_name} unavailable error should name the provider"
    );
}
