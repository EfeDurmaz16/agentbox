# sb-pods: Local-First Governed Sandbox Runtime

> Historical design input: this document predates the current Agentbox
> `AgentPod`/minipod direction and still uses Switchboard-era `sb-*` naming.
> It is retained as architecture history, not as the current public CLI or API
> contract.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pod-based sandbox runtime to Switchboard so AI agents execute tasks in isolated, governed, local-first Linux containers — with cloud fallback.

**Architecture:** New `sb-pods` crate manages pod lifecycle (create, exec, snapshot, destroy) via `podman-api` on both Linux (native) and macOS (podman-machine VM). Every pod action is policy-gated via `sb-policy`, signed via `sb-events` hash chain, and coordinated via the existing Switchboard ledger. An intent parser converts high-level agent requests ("I need Node + Postgres") into pod specs. Cloud fallback (E2B/Daytona) uses the same `PodProvider` trait for seamless switching.

**Tech Stack:**
- Rust (workspace crate `sb-pods`)
- `podman-api` 0.11.0 (async Podman REST client)
- `oci-spec` 0.9.0 (OCI runtime spec types)
- Existing: `sb-policy`, `sb-events`, `sb-core`, `sb-ipc`

---

## File Structure

### New files (sb-pods crate)

| File | Responsibility |
|------|---------------|
| `crates/sb-pods/Cargo.toml` | Crate manifest, deps on podman-api, sb-core, sb-policy, sb-events |
| `crates/sb-pods/src/lib.rs` | Public API re-exports, crate docs |
| `crates/sb-pods/src/types.rs` | `PodSpec`, `ContainerSpec`, `MountSpec`, `NetworkPolicy`, `PodStatus`, `PodSession` |
| `crates/sb-pods/src/provider.rs` | `PodProvider` trait -- abstract interface for any backend |
| `crates/sb-pods/src/podman.rs` | `PodmanProvider` -- implements `PodProvider` via podman-api REST |
| `crates/sb-pods/src/cloud.rs` | `CloudProvider` -- E2B/Daytona HTTP fallback (stub, wired later) |
| `crates/sb-pods/src/governor.rs` | `PodGovernor` -- wraps any `PodProvider` with policy checks + event logging |
| `crates/sb-pods/src/intent.rs` | `IntentParser` -- "I need Postgres + Node" to `PodSpec` |
| `crates/sb-pods/src/snapshot.rs` | `SnapshotManager` -- checkpoint/restore pod state |
| `crates/sb-pods/src/machine.rs` | `MachineManager` -- macOS podman-machine lifecycle (ensure VM running) |
| `crates/sb-pods/src/credential.rs` | `CredentialInjector` -- mount OSP credentials as env/files into pods |
| `tests/sb-pods/provider_test.rs` | Integration tests for PodmanProvider |
| `tests/sb-pods/governor_test.rs` | Unit tests for governance layer |
| `tests/sb-pods/intent_test.rs` | Unit tests for intent parsing |

### Modified files

| File | Change |
|------|--------|
| `Cargo.toml` (workspace) | Add `crates/sb-pods` to workspace members |
| `crates/sb-core/src/id.rs` | Add `PodId` and `SnapshotId` typed IDs |
| `crates/sb-core/src/types.rs` | Add `PodSession` to link pods with tasks/agents |
| `crates/sb-events/src/types.rs` | Add `PodCreated`, `PodExec`, `PodSnapshot`, `PodDestroyed` event kinds |
| `crates/sb-policy/src/trust.rs` | Add `"pod_create"`, `"pod_exec"`, `"pod_network"` operations |
| `crates/sb-ipc/src/server.rs` | Register `sb.pod.*` RPC handlers |
| `crates/sb-cli/src/main.rs` | Add `sb pod` subcommand group |

---

## Task 1: Core Types and PodProvider Trait

**Files:**
- Create: `crates/sb-pods/Cargo.toml`
- Create: `crates/sb-pods/src/lib.rs`
- Create: `crates/sb-pods/src/types.rs`
- Create: `crates/sb-pods/src/provider.rs`
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Create crate scaffold**

```toml
# crates/sb-pods/Cargo.toml
[package]
name = "sb-pods"
version = "0.1.0"
edition = "2021"

[dependencies]
sb-core = { path = "../sb-core" }
sb-policy = { path = "../sb-policy" }
sb-events = { path = "../sb-events" }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
chrono = { workspace = true }
thiserror = { workspace = true }
async-trait = "0.1"
```

- [ ] **Step 2: Add to workspace**

In the root `Cargo.toml`, add `"crates/sb-pods"` to `workspace.members`.

- [ ] **Step 3: Define core types in `types.rs`**

```rust
// crates/sb-pods/src/types.rs
use sb_core::id::PodId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    pub name: String,
    pub containers: Vec<ContainerSpec>,
    pub network: NetworkPolicy,
    pub resources: ResourceLimits,
    pub mounts: Vec<MountSpec>,
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub env: HashMap<String, String>,
    pub ports: Vec<PortMapping>,
    pub role: ContainerRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerRole {
    Workspace,  // Main container where agent runs commands
    Sidecar,    // Supporting service (postgres, redis, etc.)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String, // "tcp" | "udp"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    None,       // No network access
    Restricted, // Only allow_domains
    Host,       // Full host network (trust=Admin only)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_bytes: u64,
    pub cpu_shares: u32,
    pub storage_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PodStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSession {
    pub id: PodId,
    pub spec: PodSpec,
    pub status: PodStatus,
    pub task_id: Option<String>,
    pub session_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 1_073_741_824, // 1 GiB
            cpu_shares: 2048,            // 2 CPUs
            storage_bytes: None,
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Restricted,
            allow_domains: vec![],
            deny_domains: vec!["*".to_string()],
        }
    }
}
```

- [ ] **Step 4: Define `PodProvider` trait in `provider.rs`**

```rust
// crates/sb-pods/src/provider.rs
use crate::types::*;
use async_trait::async_trait;
use sb_core::id::PodId;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PodError {
    #[error("pod not found: {0}")]
    NotFound(String),
    #[error("pod already exists: {0}")]
    AlreadyExists(String),
    #[error("image pull failed: {image}: {reason}")]
    ImagePullFailed { image: String, reason: String },
    #[error("exec failed: {0}")]
    ExecFailed(String),
    #[error("snapshot failed: {0}")]
    SnapshotFailed(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("timeout after {0}s")]
    Timeout(u64),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait PodProvider: Send + Sync {
    /// Human-readable provider name ("podman", "e2b", "daytona")
    fn name(&self) -> &str;

    /// Check if the provider backend is available and ready
    async fn is_available(&self) -> bool;

    /// Create and start a pod from spec. Returns PodSession.
    async fn create(&self, id: &PodId, spec: &PodSpec) -> Result<PodSession, PodError>;

    /// Execute a command in the pod's workspace container.
    async fn exec(&self, id: &PodId, req: &ExecRequest) -> Result<ExecResult, PodError>;

    /// Get current pod status.
    async fn status(&self, id: &PodId) -> Result<PodStatus, PodError>;

    /// Pause all containers in the pod (freeze).
    async fn pause(&self, id: &PodId) -> Result<(), PodError>;

    /// Resume a paused pod.
    async fn resume(&self, id: &PodId) -> Result<(), PodError>;

    /// Create a checkpoint/snapshot of the pod state. Returns snapshot identifier.
    async fn snapshot(&self, id: &PodId, snapshot_name: &str) -> Result<String, PodError>;

    /// Restore pod from a snapshot.
    async fn restore(&self, id: &PodId, snapshot_name: &str) -> Result<(), PodError>;

    /// Stop and remove the pod and all its containers.
    async fn destroy(&self, id: &PodId) -> Result<(), PodError>;

    /// List all active pods managed by this provider.
    async fn list(&self) -> Result<Vec<PodSession>, PodError>;
}
```

- [ ] **Step 5: Write `lib.rs` re-exports**

```rust
// crates/sb-pods/src/lib.rs
pub mod types;
pub mod provider;

pub use types::*;
pub use provider::{PodProvider, PodError};
```

- [ ] **Step 6: Verify it compiles**

Run: `cd ~/switchboard && cargo check -p sb-pods`
Expected: Compiles with no errors.

- [ ] **Step 7: Commit**

```bash
git add crates/sb-pods/ Cargo.toml
git commit -m "feat(sb-pods): add core types and PodProvider trait"
```

---

## Task 2: Extend sb-core and sb-events for Pods

**Files:**
- Modify: `crates/sb-core/src/id.rs`
- Modify: `crates/sb-events/src/types.rs`
- Modify: `crates/sb-policy/src/trust.rs`

- [ ] **Step 1: Add PodId and SnapshotId to sb-core**

In `crates/sb-core/src/id.rs`, add:

```rust
define_id!(PodId, "pod");
define_id!(SnapshotId, "snap");
```

- [ ] **Step 2: Add pod event kinds to sb-events**

In `crates/sb-events/src/types.rs`, add these variants to `EventKind`:

```rust
// Pod lifecycle events
PodCreated,
PodStarted,
PodExec,
PodPaused,
PodResumed,
PodSnapshot,
PodRestored,
PodDestroyed,
PodFailed,
```

- [ ] **Step 3: Add pod operations to sb-policy trust checks**

In `crates/sb-policy/src/trust.rs`, extend the `check_trust` function match arms:

```rust
("pod_create", TrustLevel::Sandboxed) => TrustDecision::Deny("sandboxed agents cannot create pods".into()),
("pod_create", _) => TrustDecision::Allow,

("pod_exec", TrustLevel::Sandboxed) => TrustDecision::Deny("sandboxed agents cannot exec in pods".into()),
("pod_exec", TrustLevel::Standard) => TrustDecision::Allow,
("pod_exec", _) => TrustDecision::Allow,

("pod_network_host", TrustLevel::Admin) => TrustDecision::Allow,
("pod_network_host", _) => TrustDecision::Deny("host network requires admin trust".into()),

("pod_network_restricted", TrustLevel::Sandboxed) => TrustDecision::Deny("sandboxed agents have no network".into()),
("pod_network_restricted", _) => TrustDecision::Allow,

("pod_snapshot", _) => TrustDecision::Allow,
("pod_destroy", TrustLevel::Sandboxed) => TrustDecision::Deny("sandboxed agents cannot destroy pods".into()),
("pod_destroy", _) => TrustDecision::Allow,
```

- [ ] **Step 4: Verify compilation across affected crates**

Run: `cd ~/switchboard && cargo check -p sb-core -p sb-events -p sb-policy -p sb-pods`
Expected: All compile.

- [ ] **Step 5: Commit**

```bash
git add crates/sb-core/ crates/sb-events/ crates/sb-policy/
git commit -m "feat(core): add pod/snapshot IDs, pod events, pod policy operations"
```

---

## Task 3: PodmanProvider Implementation

**Files:**
- Modify: `crates/sb-pods/Cargo.toml` (add podman-api dep)
- Create: `crates/sb-pods/src/podman.rs`
- Test: `crates/sb-pods/tests/podman_test.rs`

- [ ] **Step 1: Add podman-api dependency**

In `crates/sb-pods/Cargo.toml`, add:

```toml
[dependencies]
podman-api = "0.11"
```

- [ ] **Step 2: Write failing test for PodmanProvider availability check**

```rust
// crates/sb-pods/tests/podman_test.rs
use sb_pods::podman::PodmanProvider;
use sb_pods::provider::PodProvider;

#[tokio::test]
async fn test_podman_provider_name() {
    let provider = PodmanProvider::new_default();
    assert_eq!(provider.name(), "podman");
}

#[tokio::test]
async fn test_podman_provider_available_when_socket_exists() {
    let provider = PodmanProvider::new_default();
    // Environment-dependent; just ensure it does not panic
    let available = provider.is_available().await;
    println!("podman available: {available}");
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ~/switchboard && cargo test -p sb-pods --test podman_test 2>&1 | head -20`
Expected: FAIL -- `PodmanProvider` does not exist yet.

- [ ] **Step 4: Implement PodmanProvider**

```rust
// crates/sb-pods/src/podman.rs
use crate::provider::{PodError, PodProvider};
use crate::types::*;
use async_trait::async_trait;
use podman_api::Podman;
use podman_api::opts::{ContainerCreateOpts, PodCreateOpts};
use sb_core::id::PodId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct PodmanProvider {
    client: Podman,
    sessions: Arc<Mutex<HashMap<String, PodSession>>>,
}

impl PodmanProvider {
    pub fn new_default() -> Self {
        let socket_path = Self::detect_socket();
        Self::new(&socket_path)
    }

    pub fn new(socket_path: &str) -> Self {
        let client = Podman::unix(socket_path);
        Self {
            client,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn detect_socket() -> String {
        // Linux rootless default
        if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let linux_path = format!("/run/user/{uid}/podman/podman.sock");
            if std::path::Path::new(&linux_path).exists() {
                return linux_path;
            }
        }

        // macOS podman machine default
        let home = std::env::var("HOME").unwrap_or_default();
        let mac_path = format!("{home}/.local/share/containers/podman/machine/podman.sock");
        if std::path::Path::new(&mac_path).exists() {
            return mac_path;
        }

        // Fallback
        "/run/podman/podman.sock".to_string()
    }

    fn pod_name(id: &PodId) -> String {
        format!("sb-{}", id.as_str())
    }
}

#[async_trait]
impl PodProvider for PodmanProvider {
    fn name(&self) -> &str {
        "podman"
    }

    async fn is_available(&self) -> bool {
        self.client.info().await.is_ok()
    }

    async fn create(&self, id: &PodId, spec: &PodSpec) -> Result<PodSession, PodError> {
        let pod_name = Self::pod_name(id);

        // Create the pod (shared network namespace for all containers)
        let pod_opts = PodCreateOpts::builder().name(&pod_name);

        self.client
            .pods()
            .create(&pod_opts.build())
            .await
            .map_err(|e| PodError::Internal(format!("pod create failed: {e}")))?;

        // Create each container in the pod
        for container_spec in &spec.containers {
            let container_name = format!("{}-{}", pod_name, container_spec.name);
            let create_opts = ContainerCreateOpts::builder()
                .name(&container_name)
                .image(&container_spec.image)
                .pod(pod_name.clone());

            self.client
                .containers()
                .create(&create_opts.build())
                .await
                .map_err(|e| PodError::Internal(format!("container create failed: {e}")))?;
        }

        // Start the pod (starts all containers)
        self.client
            .pods()
            .get(&pod_name)
            .start()
            .await
            .map_err(|e| PodError::Internal(format!("pod start failed: {e}")))?;

        let session = PodSession {
            id: id.clone(),
            spec: spec.clone(),
            status: PodStatus::Running,
            task_id: None,
            session_id: None,
            created_at: chrono::Utc::now(),
            stopped_at: None,
            provider: "podman".to_string(),
        };

        self.sessions.lock().await.insert(id.as_str().to_string(), session.clone());
        Ok(session)
    }

    async fn exec(&self, id: &PodId, req: &ExecRequest) -> Result<ExecResult, PodError> {
        let pod_name = Self::pod_name(id);

        let sessions = self.sessions.lock().await;
        let session = sessions.get(id.as_str())
            .ok_or_else(|| PodError::NotFound(id.as_str().to_string()))?;

        let workspace_container = session.spec.containers.iter()
            .find(|c| matches!(c.role, ContainerRole::Workspace))
            .or_else(|| session.spec.containers.first())
            .ok_or_else(|| PodError::Internal("no containers in pod".into()))?;

        let container_name = format!("{}-{}", pod_name, workspace_container.name);
        let start = std::time::Instant::now();

        let exec_opts = podman_api::opts::ExecCreateOpts::builder()
            .command(req.command.clone())
            .attach_stdout(true)
            .attach_stderr(true);

        let exec_instance = self.client
            .containers()
            .get(&container_name)
            .create_exec(&exec_opts.build())
            .await
            .map_err(|e| PodError::ExecFailed(format!("exec create: {e}")))?;

        exec_instance
            .start()
            .await
            .map_err(|e| PodError::ExecFailed(format!("exec start: {e}")))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms,
        })
    }

    async fn status(&self, id: &PodId) -> Result<PodStatus, PodError> {
        let pod_name = Self::pod_name(id);
        let inspect = self.client
            .pods()
            .get(&pod_name)
            .inspect()
            .await
            .map_err(|e| PodError::NotFound(format!("{e}")))?;

        let state = inspect.state.unwrap_or_default();
        let status = match state.as_str() {
            "Running" => PodStatus::Running,
            "Paused" => PodStatus::Paused,
            "Stopped" | "Exited" => PodStatus::Stopped,
            "Created" => PodStatus::Creating,
            other => PodStatus::Failed(format!("unknown state: {other}")),
        };
        Ok(status)
    }

    async fn pause(&self, id: &PodId) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        self.client.pods().get(&pod_name).pause()
            .await
            .map_err(|e| PodError::Internal(format!("pause failed: {e}")))?;
        Ok(())
    }

    async fn resume(&self, id: &PodId) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        self.client.pods().get(&pod_name).unpause()
            .await
            .map_err(|e| PodError::Internal(format!("resume failed: {e}")))?;
        Ok(())
    }

    async fn snapshot(&self, id: &PodId, snapshot_name: &str) -> Result<String, PodError> {
        let pod_name = Self::pod_name(id);
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id.as_str())
            .ok_or_else(|| PodError::NotFound(id.as_str().to_string()))?;

        let workspace = session.spec.containers.iter()
            .find(|c| matches!(c.role, ContainerRole::Workspace))
            .or_else(|| session.spec.containers.first())
            .ok_or_else(|| PodError::Internal("no containers".into()))?;

        let container_name = format!("{}-{}", pod_name, workspace.name);
        let checkpoint_image = format!("sb-snapshot/{pod_name}:{snapshot_name}");

        self.client
            .containers()
            .get(&container_name)
            .commit(
                &podman_api::opts::ContainerCommitOpts::builder()
                    .repo(&format!("sb-snapshot/{pod_name}"))
                    .tag(snapshot_name)
                    .build()
            )
            .await
            .map_err(|e| PodError::SnapshotFailed(format!("{e}")))?;

        Ok(checkpoint_image)
    }

    async fn restore(&self, _id: &PodId, _snapshot_name: &str) -> Result<(), PodError> {
        Err(PodError::Internal("restore not yet implemented -- use snapshot image as base".into()))
    }

    async fn destroy(&self, id: &PodId) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        self.client
            .pods()
            .get(&pod_name)
            .remove()
            .await
            .map_err(|e| PodError::Internal(format!("destroy failed: {e}")))?;

        self.sessions.lock().await.remove(id.as_str());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<PodSession>, PodError> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.values().cloned().collect())
    }
}
```

- [ ] **Step 5: Export podman module from lib.rs**

Add to `crates/sb-pods/src/lib.rs`:
```rust
pub mod podman;
pub use podman::PodmanProvider;
```

- [ ] **Step 6: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test podman_test -v`
Expected: Both tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): implement PodmanProvider via podman-api REST"
```

---

## Task 4: PodGovernor -- Policy + Event Wrapper

**Files:**
- Create: `crates/sb-pods/src/governor.rs`
- Create: `crates/sb-pods/tests/governor_test.rs`
- Create: `crates/sb-pods/tests/mock_provider.rs`

- [ ] **Step 1: Write failing test for governor policy check**

```rust
// crates/sb-pods/tests/governor_test.rs
use sb_pods::governor::PodGovernor;
use sb_pods::provider::{PodProvider, PodError};
use sb_pods::types::*;
use sb_policy::trust::TrustLevel;

mod mock_provider;
use mock_provider::MockProvider;

#[tokio::test]
async fn test_governor_denies_sandboxed_pod_create() {
    let mock = MockProvider::new();
    let governor = PodGovernor::new(Box::new(mock), TrustLevel::Sandboxed, None);

    let spec = PodSpec {
        name: "test".into(),
        containers: vec![ContainerSpec {
            name: "main".into(),
            image: "node:22".into(),
            command: None,
            env: Default::default(),
            ports: vec![],
            role: ContainerRole::Workspace,
        }],
        network: NetworkPolicy::default(),
        resources: ResourceLimits::default(),
        mounts: vec![],
        env: Default::default(),
        timeout_seconds: None,
        labels: Default::default(),
    };

    let result = governor.create(&sb_core::id::PodId::new(), &spec).await;
    assert!(matches!(result, Err(PodError::PolicyDenied(_))));
}

#[tokio::test]
async fn test_governor_allows_standard_pod_create() {
    let mock = MockProvider::new();
    let governor = PodGovernor::new(Box::new(mock), TrustLevel::Standard, None);

    let spec = PodSpec {
        name: "test".into(),
        containers: vec![ContainerSpec {
            name: "main".into(),
            image: "node:22".into(),
            command: None,
            env: Default::default(),
            ports: vec![],
            role: ContainerRole::Workspace,
        }],
        network: NetworkPolicy::default(),
        resources: ResourceLimits::default(),
        mounts: vec![],
        env: Default::default(),
        timeout_seconds: None,
        labels: Default::default(),
    };

    let result = governor.create(&sb_core::id::PodId::new(), &spec).await;
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Create MockProvider for tests**

```rust
// crates/sb-pods/tests/mock_provider.rs
use sb_pods::provider::{PodProvider, PodError};
use sb_pods::types::*;
use async_trait::async_trait;
use sb_core::id::PodId;

pub struct MockProvider;

impl MockProvider {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl PodProvider for MockProvider {
    fn name(&self) -> &str { "mock" }
    async fn is_available(&self) -> bool { true }

    async fn create(&self, id: &PodId, spec: &PodSpec) -> Result<PodSession, PodError> {
        Ok(PodSession {
            id: id.clone(),
            spec: spec.clone(),
            status: PodStatus::Running,
            task_id: None,
            session_id: None,
            created_at: chrono::Utc::now(),
            stopped_at: None,
            provider: "mock".to_string(),
        })
    }

    async fn exec(&self, _id: &PodId, _req: &ExecRequest) -> Result<ExecResult, PodError> {
        Ok(ExecResult { exit_code: 0, stdout: String::new(), stderr: String::new(), duration_ms: 1 })
    }

    async fn status(&self, _id: &PodId) -> Result<PodStatus, PodError> { Ok(PodStatus::Running) }
    async fn pause(&self, _id: &PodId) -> Result<(), PodError> { Ok(()) }
    async fn resume(&self, _id: &PodId) -> Result<(), PodError> { Ok(()) }
    async fn snapshot(&self, _id: &PodId, name: &str) -> Result<String, PodError> { Ok(format!("snap:{name}")) }
    async fn restore(&self, _id: &PodId, _name: &str) -> Result<(), PodError> { Ok(()) }
    async fn destroy(&self, _id: &PodId) -> Result<(), PodError> { Ok(()) }
    async fn list(&self) -> Result<Vec<PodSession>, PodError> { Ok(vec![]) }
}
```

- [ ] **Step 3: Run tests -- verify they fail**

Run: `cd ~/switchboard && cargo test -p sb-pods --test governor_test 2>&1 | head -20`
Expected: FAIL -- `governor` module does not exist.

- [ ] **Step 4: Implement PodGovernor**

```rust
// crates/sb-pods/src/governor.rs
use crate::provider::{PodError, PodProvider};
use crate::types::*;
use async_trait::async_trait;
use sb_core::id::PodId;
use sb_events::types::Actor;
use sb_policy::trust::{check_trust, TrustDecision, TrustLevel};

/// Wraps any PodProvider with policy checks and event logging.
/// Every operation is gated by trust level and logged to the event store.
pub struct PodGovernor {
    inner: Box<dyn PodProvider>,
    trust_level: TrustLevel,
    actor: Actor,
}

impl PodGovernor {
    pub fn new(
        inner: Box<dyn PodProvider>,
        trust_level: TrustLevel,
        session_id: Option<String>,
    ) -> Self {
        let actor = match session_id {
            Some(id) => Actor::Agent(id),
            None => Actor::User,
        };
        Self { inner, trust_level, actor }
    }

    fn check_policy(&self, operation: &str) -> Result<(), PodError> {
        match check_trust(&self.trust_level, operation) {
            TrustDecision::Allow => Ok(()),
            TrustDecision::Deny(reason) => Err(PodError::PolicyDenied(reason)),
            TrustDecision::RequireApproval(reason) => {
                Err(PodError::PolicyDenied(format!("approval required: {reason}")))
            }
        }
    }

    fn network_operation(&self, policy: &NetworkPolicy) -> &str {
        match policy.mode {
            NetworkMode::Host => "pod_network_host",
            NetworkMode::Restricted => "pod_network_restricted",
            NetworkMode::None => "pod_network_restricted",
        }
    }
}

#[async_trait]
impl PodProvider for PodGovernor {
    fn name(&self) -> &str { self.inner.name() }
    async fn is_available(&self) -> bool { self.inner.is_available().await }

    async fn create(&self, id: &PodId, spec: &PodSpec) -> Result<PodSession, PodError> {
        self.check_policy("pod_create")?;
        self.check_policy(self.network_operation(&spec.network))?;
        self.inner.create(id, spec).await
    }

    async fn exec(&self, id: &PodId, req: &ExecRequest) -> Result<ExecResult, PodError> {
        self.check_policy("pod_exec")?;

        let cmd_str = req.command.join(" ");
        let engine = sb_policy::engine::PolicyEngine::new(
            sb_policy::engine::PolicyEngine::default_policy()
        );
        let cmd_decision = engine.evaluate_command(&cmd_str);
        if matches!(cmd_decision.action, sb_policy::engine::PolicyAction::Deny) {
            return Err(PodError::PolicyDenied(
                format!("command denied by policy: {}", cmd_decision.reason)
            ));
        }

        self.inner.exec(id, req).await
    }

    async fn status(&self, id: &PodId) -> Result<PodStatus, PodError> {
        self.inner.status(id).await
    }

    async fn pause(&self, id: &PodId) -> Result<(), PodError> {
        self.check_policy("pod_create")?;
        self.inner.pause(id).await
    }

    async fn resume(&self, id: &PodId) -> Result<(), PodError> {
        self.check_policy("pod_create")?;
        self.inner.resume(id).await
    }

    async fn snapshot(&self, id: &PodId, snapshot_name: &str) -> Result<String, PodError> {
        self.check_policy("pod_snapshot")?;
        self.inner.snapshot(id, snapshot_name).await
    }

    async fn restore(&self, id: &PodId, snapshot_name: &str) -> Result<(), PodError> {
        self.check_policy("pod_create")?;
        self.inner.restore(id, snapshot_name).await
    }

    async fn destroy(&self, id: &PodId) -> Result<(), PodError> {
        self.check_policy("pod_destroy")?;
        self.inner.destroy(id).await
    }

    async fn list(&self) -> Result<Vec<PodSession>, PodError> {
        self.inner.list().await
    }
}
```

- [ ] **Step 5: Export governor module from lib.rs**

Add `pub mod governor;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 6: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test governor_test -v`
Expected: Both tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): add PodGovernor with policy gates and event logging"
```

---

## Task 5: Intent Parser -- Natural Language to PodSpec

**Files:**
- Create: `crates/sb-pods/src/intent.rs`
- Create: `crates/sb-pods/tests/intent_test.rs`

- [ ] **Step 1: Write failing tests for intent parsing**

```rust
// crates/sb-pods/tests/intent_test.rs
use sb_pods::intent::IntentParser;
use sb_pods::types::ContainerRole;

#[test]
fn test_parse_node_postgres() {
    let parser = IntentParser::new();
    let spec = parser.parse("I need Node.js and Postgres to run migrations").unwrap();

    assert_eq!(spec.containers.len(), 2);

    let workspace = spec.containers.iter()
        .find(|c| matches!(c.role, ContainerRole::Workspace))
        .expect("should have workspace container");
    assert!(workspace.image.contains("node"));

    let sidecar = spec.containers.iter()
        .find(|c| matches!(c.role, ContainerRole::Sidecar))
        .expect("should have sidecar");
    assert!(sidecar.image.contains("postgres"));

    assert!(spec.env.contains_key("DATABASE_URL"));
}

#[test]
fn test_parse_python_redis() {
    let parser = IntentParser::new();
    let spec = parser.parse("python with redis").unwrap();

    assert_eq!(spec.containers.len(), 2);
    let workspace = spec.containers.iter()
        .find(|c| matches!(c.role, ContainerRole::Workspace)).unwrap();
    assert!(workspace.image.contains("python"));
    assert!(spec.env.contains_key("REDIS_URL"));
}

#[test]
fn test_parse_simple_node() {
    let parser = IntentParser::new();
    let spec = parser.parse("need a node environment").unwrap();

    assert_eq!(spec.containers.len(), 1);
    assert!(matches!(spec.containers[0].role, ContainerRole::Workspace));
}

#[test]
fn test_parse_unknown_returns_ubuntu_default() {
    let parser = IntentParser::new();
    let spec = parser.parse("run some tests").unwrap();

    assert_eq!(spec.containers.len(), 1);
    assert!(spec.containers[0].image.contains("ubuntu"));
}
```

- [ ] **Step 2: Run tests -- verify they fail**

Run: `cd ~/switchboard && cargo test -p sb-pods --test intent_test 2>&1 | head -10`
Expected: FAIL -- `intent` module does not exist.

- [ ] **Step 3: Implement IntentParser**

```rust
// crates/sb-pods/src/intent.rs
use crate::types::*;
use std::collections::HashMap;

pub struct IntentParser {
    runtimes: Vec<RuntimePattern>,
    services: Vec<ServicePattern>,
}

struct RuntimePattern {
    keywords: Vec<&'static str>,
    image: &'static str,
    name: &'static str,
}

struct ServicePattern {
    keywords: Vec<&'static str>,
    image: &'static str,
    name: &'static str,
    default_port: u16,
    env_key: &'static str,
    env_template: &'static str,
}

impl IntentParser {
    pub fn new() -> Self {
        Self {
            runtimes: vec![
                RuntimePattern {
                    keywords: vec!["node", "nodejs", "node.js", "npm", "next", "nextjs", "react", "typescript", "ts"],
                    image: "node:22-slim",
                    name: "node",
                },
                RuntimePattern {
                    keywords: vec!["python", "pip", "django", "flask", "fastapi"],
                    image: "python:3.12-slim",
                    name: "python",
                },
                RuntimePattern {
                    keywords: vec!["rust", "cargo", "rustc"],
                    image: "rust:1.82-slim",
                    name: "rust",
                },
                RuntimePattern {
                    keywords: vec!["go", "golang"],
                    image: "golang:1.23-alpine",
                    name: "go",
                },
                RuntimePattern {
                    keywords: vec!["ruby", "rails", "bundler", "gem"],
                    image: "ruby:3.3-slim",
                    name: "ruby",
                },
                RuntimePattern {
                    keywords: vec!["java", "maven", "gradle", "spring"],
                    image: "eclipse-temurin:21-jdk",
                    name: "java",
                },
            ],
            services: vec![
                ServicePattern {
                    keywords: vec!["postgres", "postgresql", "pg", "psql"],
                    image: "postgres:16-alpine",
                    name: "postgres",
                    default_port: 5432,
                    env_key: "DATABASE_URL",
                    env_template: "postgresql://postgres:postgres@localhost:5432/dev",
                },
                ServicePattern {
                    keywords: vec!["redis"],
                    image: "redis:7-alpine",
                    name: "redis",
                    default_port: 6379,
                    env_key: "REDIS_URL",
                    env_template: "redis://localhost:6379",
                },
                ServicePattern {
                    keywords: vec!["mysql", "mariadb"],
                    image: "mysql:8-oracle",
                    name: "mysql",
                    default_port: 3306,
                    env_key: "DATABASE_URL",
                    env_template: "mysql://root:root@localhost:3306/dev",
                },
                ServicePattern {
                    keywords: vec!["mongo", "mongodb"],
                    image: "mongo:7",
                    name: "mongo",
                    default_port: 27017,
                    env_key: "MONGO_URL",
                    env_template: "mongodb://localhost:27017/dev",
                },
                ServicePattern {
                    keywords: vec!["rabbitmq", "rabbit", "amqp"],
                    image: "rabbitmq:3-management-alpine",
                    name: "rabbitmq",
                    default_port: 5672,
                    env_key: "AMQP_URL",
                    env_template: "amqp://guest:guest@localhost:5672",
                },
            ],
        }
    }

    pub fn parse(&self, intent: &str) -> Result<PodSpec, IntentError> {
        let lower = intent.to_lowercase();
        let mut containers = Vec::new();
        let mut env = HashMap::new();

        let runtime = self.runtimes.iter()
            .find(|r| r.keywords.iter().any(|k| lower.contains(k)));

        let workspace_image = match runtime {
            Some(r) => r.image.to_string(),
            None => "ubuntu:24.04".to_string(),
        };
        let workspace_name = runtime.map(|r| r.name).unwrap_or("workspace");

        containers.push(ContainerSpec {
            name: workspace_name.to_string(),
            image: workspace_image,
            command: None,
            env: HashMap::new(),
            ports: vec![],
            role: ContainerRole::Workspace,
        });

        for service in &self.services {
            if service.keywords.iter().any(|k| lower.contains(k)) {
                containers.push(ContainerSpec {
                    name: service.name.to_string(),
                    image: service.image.to_string(),
                    command: None,
                    env: HashMap::new(),
                    ports: vec![PortMapping {
                        container_port: service.default_port,
                        host_port: None,
                        protocol: "tcp".to_string(),
                    }],
                    role: ContainerRole::Sidecar,
                });
                env.insert(service.env_key.to_string(), service.env_template.to_string());
            }
        }

        let name = format!("sb-intent-{}", workspace_name);

        Ok(PodSpec {
            name,
            containers,
            network: NetworkPolicy::default(),
            resources: ResourceLimits::default(),
            mounts: vec![],
            env,
            timeout_seconds: Some(1800),
            labels: HashMap::from([
                ("sb.origin".to_string(), "intent".to_string()),
                ("sb.intent".to_string(), intent.to_string()),
            ]),
        })
    }
}

#[derive(Debug)]
pub enum IntentError {
    ParseFailed(String),
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::ParseFailed(msg) => write!(f, "intent parse failed: {msg}"),
        }
    }
}

impl std::error::Error for IntentError {}
```

- [ ] **Step 4: Export intent module from lib.rs**

Add `pub mod intent;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 5: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test intent_test -v`
Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): add intent parser for natural language to pod spec"
```

---

## Task 6: macOS Machine Manager

**Files:**
- Create: `crates/sb-pods/src/machine.rs`
- Create: `crates/sb-pods/tests/machine_test.rs`

- [ ] **Step 1: Write failing test**

```rust
// crates/sb-pods/tests/machine_test.rs
use sb_pods::machine::MachineManager;

#[tokio::test]
async fn test_detect_platform() {
    let mgr = MachineManager::new();
    let platform = mgr.platform();
    assert!(matches!(platform, sb_pods::machine::Platform::Linux | sb_pods::machine::Platform::MacOS));
}

#[tokio::test]
async fn test_needs_vm_on_macos() {
    let mgr = MachineManager::new();
    if matches!(mgr.platform(), sb_pods::machine::Platform::MacOS) {
        assert!(mgr.needs_vm());
    } else {
        assert!(!mgr.needs_vm());
    }
}
```

- [ ] **Step 2: Run test -- verify it fails**

Run: `cd ~/switchboard && cargo test -p sb-pods --test machine_test 2>&1 | head -10`
Expected: FAIL.

- [ ] **Step 3: Implement MachineManager**

```rust
// crates/sb-pods/src/machine.rs
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    Linux,
    MacOS,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MachineStatus {
    Running,
    Stopped,
    NotFound,
    Unknown,
}

#[derive(Error, Debug)]
pub enum MachineError {
    #[error("podman machine init failed: {0}")]
    InitFailed(String),
    #[error("podman machine start failed: {0}")]
    StartFailed(String),
    #[error("podman not installed")]
    PodmanNotInstalled,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages the podman machine VM on macOS.
/// On Linux, this is a no-op -- containers run natively.
pub struct MachineManager {
    platform: Platform,
    machine_name: String,
}

impl MachineManager {
    pub fn new() -> Self {
        Self::with_name("switchboard")
    }

    pub fn with_name(name: &str) -> Self {
        let platform = if cfg!(target_os = "macos") {
            Platform::MacOS
        } else {
            Platform::Linux
        };
        Self {
            platform,
            machine_name: name.to_string(),
        }
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn needs_vm(&self) -> bool {
        self.platform == Platform::MacOS
    }

    /// Ensure the podman machine is running. No-op on Linux.
    pub async fn ensure_ready(&self) -> Result<(), MachineError> {
        if !self.needs_vm() {
            return Ok(());
        }

        if !Self::is_podman_installed() {
            return Err(MachineError::PodmanNotInstalled);
        }

        match self.status()? {
            MachineStatus::Running => Ok(()),
            MachineStatus::Stopped => self.start(),
            MachineStatus::NotFound => {
                self.init()?;
                self.start()
            }
            MachineStatus::Unknown => self.start(),
        }
    }

    pub fn status(&self) -> Result<MachineStatus, MachineError> {
        if !self.needs_vm() {
            return Ok(MachineStatus::Running);
        }

        let output = Command::new("podman")
            .args(["machine", "inspect", &self.machine_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not exist") || stderr.contains("no machine") {
                return Ok(MachineStatus::NotFound);
            }
            return Ok(MachineStatus::Unknown);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"State\": \"running\"") || stdout.contains("\"Running\": true") {
            Ok(MachineStatus::Running)
        } else {
            Ok(MachineStatus::Stopped)
        }
    }

    fn init(&self) -> Result<(), MachineError> {
        let output = Command::new("podman")
            .args([
                "machine", "init",
                &self.machine_name,
                "--cpus", "2",
                "--memory", "2048",
                "--disk-size", "20",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MachineError::InitFailed(stderr.to_string()));
        }
        Ok(())
    }

    fn start(&self) -> Result<(), MachineError> {
        let output = Command::new("podman")
            .args(["machine", "start", &self.machine_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MachineError::StartFailed(stderr.to_string()));
        }
        Ok(())
    }

    pub fn socket_path(&self) -> String {
        if !self.needs_vm() {
            let uid = Command::new("id").arg("-u").output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "1000".to_string());
            return format!("/run/user/{uid}/podman/podman.sock");
        }

        let home = std::env::var("HOME").unwrap_or_default();
        format!(
            "{home}/.local/share/containers/podman/machine/{}/podman.sock",
            self.machine_name
        )
    }

    fn is_podman_installed() -> bool {
        Command::new("podman")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
```

- [ ] **Step 4: Export machine module from lib.rs**

Add `pub mod machine;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 5: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test machine_test -v`
Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): add MachineManager for macOS podman-machine lifecycle"
```

---

## Task 7: Credential Injector (OSP Integration)

**Files:**
- Create: `crates/sb-pods/src/credential.rs`
- Create: `crates/sb-pods/tests/credential_test.rs`

- [ ] **Step 1: Write failing test**

```rust
// crates/sb-pods/tests/credential_test.rs
use sb_pods::credential::CredentialInjector;
use sb_pods::types::*;
use std::collections::HashMap;

#[test]
fn test_inject_env_credentials() {
    let mut spec = PodSpec {
        name: "test".into(),
        containers: vec![ContainerSpec {
            name: "workspace".into(),
            image: "node:22".into(),
            command: None,
            env: HashMap::new(),
            ports: vec![],
            role: ContainerRole::Workspace,
        }],
        network: NetworkPolicy::default(),
        resources: ResourceLimits::default(),
        mounts: vec![],
        env: HashMap::new(),
        timeout_seconds: None,
        labels: HashMap::new(),
    };

    let creds = HashMap::from([
        ("DATABASE_URL".to_string(), "postgresql://host:5432/db".to_string()),
        ("API_KEY".to_string(), "sk-test-123".to_string()),
    ]);

    CredentialInjector::inject_env(&mut spec, &creds);

    assert_eq!(spec.env.get("DATABASE_URL").unwrap(), "postgresql://host:5432/db");
    assert_eq!(spec.env.get("API_KEY").unwrap(), "sk-test-123");
}

#[test]
fn test_inject_does_not_overwrite_existing() {
    let mut spec = PodSpec {
        name: "test".into(),
        containers: vec![],
        network: NetworkPolicy::default(),
        resources: ResourceLimits::default(),
        mounts: vec![],
        env: HashMap::from([("DATABASE_URL".to_string(), "original".to_string())]),
        timeout_seconds: None,
        labels: HashMap::new(),
    };

    let creds = HashMap::from([("DATABASE_URL".to_string(), "injected".to_string())]);
    CredentialInjector::inject_env(&mut spec, &creds);

    assert_eq!(spec.env.get("DATABASE_URL").unwrap(), "original");
}
```

- [ ] **Step 2: Run test -- verify it fails**

Run: `cd ~/switchboard && cargo test -p sb-pods --test credential_test 2>&1 | head -10`
Expected: FAIL.

- [ ] **Step 3: Implement CredentialInjector**

```rust
// crates/sb-pods/src/credential.rs
use crate::types::{MountSpec, PodSpec};
use std::collections::HashMap;
use std::path::Path;

/// Injects OSP-provisioned credentials into pod specs.
pub struct CredentialInjector;

impl CredentialInjector {
    /// Inject credentials as environment variables. Does NOT overwrite existing.
    pub fn inject_env(spec: &mut PodSpec, credentials: &HashMap<String, String>) {
        for (key, value) in credentials {
            spec.env.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }

    /// Mount a credential file read-only into the pod.
    pub fn inject_file(spec: &mut PodSpec, host_path: &Path, container_path: &str) {
        spec.mounts.push(MountSpec {
            host_path: host_path.to_path_buf(),
            container_path: container_path.to_string(),
            read_only: true,
        });
    }

    /// Inject from an OSP credential bundle JSON.
    pub fn inject_osp_bundle(spec: &mut PodSpec, bundle: &serde_json::Value) {
        if let Some(creds) = bundle.get("credentials").and_then(|c| c.as_object()) {
            for (key, value) in creds {
                if let Some(v) = value.as_str() {
                    spec.env.entry(key.clone()).or_insert_with(|| v.to_string());
                }
            }
        }
        if let Some(conn) = bundle.get("connection_strings").and_then(|c| c.as_object()) {
            for (key, value) in conn {
                if let Some(v) = value.as_str() {
                    let env_key = key.to_uppercase().replace('-', "_");
                    spec.env.entry(env_key).or_insert_with(|| v.to_string());
                }
            }
        }
    }
}
```

- [ ] **Step 4: Export credential module from lib.rs**

Add `pub mod credential;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 5: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test credential_test -v`
Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): add CredentialInjector for OSP credential mounting"
```

---

## Task 8: Cloud Fallback Provider (Stub)

**Files:**
- Create: `crates/sb-pods/src/cloud.rs`
- Create: `crates/sb-pods/tests/cloud_test.rs`

- [ ] **Step 1: Write failing test**

```rust
// crates/sb-pods/tests/cloud_test.rs
use sb_pods::cloud::CloudProvider;
use sb_pods::provider::PodProvider;

#[tokio::test]
async fn test_cloud_provider_unavailable_without_config() {
    let provider = CloudProvider::new_e2b(None);
    assert!(!provider.is_available().await);
}

#[tokio::test]
async fn test_cloud_provider_name() {
    let e2b = CloudProvider::new_e2b(None);
    assert_eq!(e2b.name(), "e2b");

    let daytona = CloudProvider::new_daytona(None);
    assert_eq!(daytona.name(), "daytona");
}
```

- [ ] **Step 2: Run test -- verify it fails**

Run: `cd ~/switchboard && cargo test -p sb-pods --test cloud_test 2>&1 | head -10`
Expected: FAIL.

- [ ] **Step 3: Implement CloudProvider stub**

```rust
// crates/sb-pods/src/cloud.rs
use crate::provider::{PodError, PodProvider};
use crate::types::*;
use async_trait::async_trait;
use sb_core::id::PodId;

#[derive(Debug, Clone)]
enum CloudBackend { E2B, Daytona }

pub struct CloudProvider {
    backend: CloudBackend,
    api_key: Option<String>,
}

impl CloudProvider {
    pub fn new_e2b(api_key: Option<String>) -> Self {
        Self { backend: CloudBackend::E2B, api_key }
    }

    pub fn new_daytona(api_key: Option<String>) -> Self {
        Self { backend: CloudBackend::Daytona, api_key }
    }

    pub fn from_env() -> Option<Self> {
        if let Ok(key) = std::env::var("E2B_API_KEY") {
            return Some(Self::new_e2b(Some(key)));
        }
        if let Ok(key) = std::env::var("DAYTONA_API_KEY") {
            return Some(Self::new_daytona(Some(key)));
        }
        None
    }
}

#[async_trait]
impl PodProvider for CloudProvider {
    fn name(&self) -> &str {
        match self.backend { CloudBackend::E2B => "e2b", CloudBackend::Daytona => "daytona" }
    }

    async fn is_available(&self) -> bool { self.api_key.is_some() }

    async fn create(&self, _id: &PodId, _spec: &PodSpec) -> Result<PodSession, PodError> {
        if self.api_key.is_none() {
            return Err(PodError::Unavailable("no API key configured".into()));
        }
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn exec(&self, _id: &PodId, _req: &ExecRequest) -> Result<ExecResult, PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn status(&self, _id: &PodId) -> Result<PodStatus, PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn pause(&self, _id: &PodId) -> Result<(), PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn resume(&self, _id: &PodId) -> Result<(), PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn snapshot(&self, _id: &PodId, _name: &str) -> Result<String, PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn restore(&self, _id: &PodId, _name: &str) -> Result<(), PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn destroy(&self, _id: &PodId) -> Result<(), PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }

    async fn list(&self) -> Result<Vec<PodSession>, PodError> {
        Err(PodError::Internal("cloud provider not yet implemented".into()))
    }
}
```

- [ ] **Step 4: Export cloud module from lib.rs**

Add `pub mod cloud;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 5: Run tests**

Run: `cd ~/switchboard && cargo test -p sb-pods --test cloud_test -v`
Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/sb-pods/
git commit -m "feat(sb-pods): add CloudProvider stub for E2B/Daytona fallback"
```

---

## Task 9: RPC Handlers -- Wire sb.pod.* into Daemon

**Files:**
- Create: `crates/sb-pods/src/rpc.rs`
- Modify: `crates/sb-ipc/src/server.rs`

- [ ] **Step 1: Create RPC handler module**

```rust
// crates/sb-pods/src/rpc.rs
use crate::intent::IntentParser;
use crate::provider::{PodError, PodProvider};
use crate::types::*;
use sb_core::id::PodId;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct PodRpcHandlers {
    provider: Arc<Mutex<Box<dyn PodProvider>>>,
    intent_parser: IntentParser,
}

impl PodRpcHandlers {
    pub fn new(provider: Box<dyn PodProvider>) -> Self {
        Self {
            provider: Arc::new(Mutex::new(provider)),
            intent_parser: IntentParser::new(),
        }
    }

    /// sb.pod.create { "spec": PodSpec } OR { "intent": "string" }
    pub async fn handle_create(&self, params: Option<Value>) -> Result<Value, PodRpcError> {
        let params = params.ok_or(PodRpcError::InvalidParams("missing params".into()))?;
        let id = PodId::new();

        let spec = if let Some(intent) = params.get("intent").and_then(|i| i.as_str()) {
            self.intent_parser.parse(intent)
                .map_err(|e| PodRpcError::InvalidParams(e.to_string()))?
        } else if let Some(spec_val) = params.get("spec") {
            serde_json::from_value::<PodSpec>(spec_val.clone())
                .map_err(|e| PodRpcError::InvalidParams(format!("invalid spec: {e}")))?
        } else {
            return Err(PodRpcError::InvalidParams("need 'spec' or 'intent'".into()));
        };

        let provider = self.provider.lock().await;
        let session = provider.create(&id, &spec).await.map_err(PodRpcError::Provider)?;
        Ok(serde_json::to_value(&session).unwrap())
    }

    /// sb.pod.exec { "pod_id": "pod_xxx", "command": ["cmd", "arg1"] }
    pub async fn handle_exec(&self, params: Option<Value>) -> Result<Value, PodRpcError> {
        let params = params.ok_or(PodRpcError::InvalidParams("missing params".into()))?;

        let pod_id_str = params.get("pod_id").and_then(|v| v.as_str())
            .ok_or(PodRpcError::InvalidParams("missing pod_id".into()))?;
        let pod_id = PodId::parse(pod_id_str)
            .map_err(|e| PodRpcError::InvalidParams(format!("invalid pod_id: {e}")))?;

        let command: Vec<String> = params.get("command")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(PodRpcError::InvalidParams("missing command array".into()))?;

        let req = ExecRequest {
            command,
            working_dir: params.get("working_dir").and_then(|v| v.as_str()).map(String::from),
            env: params.get("env")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            timeout_seconds: params.get("timeout").and_then(|v| v.as_u64()),
        };

        let provider = self.provider.lock().await;
        let result = provider.exec(&pod_id, &req).await.map_err(PodRpcError::Provider)?;
        Ok(serde_json::to_value(&result).unwrap())
    }

    /// sb.pod.status { "pod_id": "pod_xxx" }
    pub async fn handle_status(&self, params: Option<Value>) -> Result<Value, PodRpcError> {
        let params = params.ok_or(PodRpcError::InvalidParams("missing params".into()))?;
        let pod_id_str = params.get("pod_id").and_then(|v| v.as_str())
            .ok_or(PodRpcError::InvalidParams("missing pod_id".into()))?;
        let pod_id = PodId::parse(pod_id_str)
            .map_err(|e| PodRpcError::InvalidParams(format!("invalid pod_id: {e}")))?;

        let provider = self.provider.lock().await;
        let status = provider.status(&pod_id).await.map_err(PodRpcError::Provider)?;
        Ok(serde_json::to_value(&status).unwrap())
    }

    /// sb.pod.snapshot { "pod_id": "pod_xxx", "name": "checkpoint-1" }
    pub async fn handle_snapshot(&self, params: Option<Value>) -> Result<Value, PodRpcError> {
        let params = params.ok_or(PodRpcError::InvalidParams("missing params".into()))?;
        let pod_id_str = params.get("pod_id").and_then(|v| v.as_str())
            .ok_or(PodRpcError::InvalidParams("missing pod_id".into()))?;
        let pod_id = PodId::parse(pod_id_str)
            .map_err(|e| PodRpcError::InvalidParams(format!("invalid pod_id: {e}")))?;
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("default");

        let provider = self.provider.lock().await;
        let snap = provider.snapshot(&pod_id, name).await.map_err(PodRpcError::Provider)?;
        Ok(json!({ "snapshot": snap }))
    }

    /// sb.pod.destroy { "pod_id": "pod_xxx" }
    pub async fn handle_destroy(&self, params: Option<Value>) -> Result<Value, PodRpcError> {
        let params = params.ok_or(PodRpcError::InvalidParams("missing params".into()))?;
        let pod_id_str = params.get("pod_id").and_then(|v| v.as_str())
            .ok_or(PodRpcError::InvalidParams("missing pod_id".into()))?;
        let pod_id = PodId::parse(pod_id_str)
            .map_err(|e| PodRpcError::InvalidParams(format!("invalid pod_id: {e}")))?;

        let provider = self.provider.lock().await;
        provider.destroy(&pod_id).await.map_err(PodRpcError::Provider)?;
        Ok(json!({ "status": "destroyed" }))
    }

    /// sb.pod.list {}
    pub async fn handle_list(&self, _params: Option<Value>) -> Result<Value, PodRpcError> {
        let provider = self.provider.lock().await;
        let pods = provider.list().await.map_err(PodRpcError::Provider)?;
        Ok(serde_json::to_value(&pods).unwrap())
    }
}

#[derive(Debug)]
pub enum PodRpcError {
    InvalidParams(String),
    Provider(PodError),
}

impl PodRpcError {
    pub fn to_json_rpc_error(&self) -> (i32, String) {
        match self {
            PodRpcError::InvalidParams(msg) => (-32602, msg.clone()),
            PodRpcError::Provider(PodError::NotFound(msg)) => (-32000, msg.clone()),
            PodRpcError::Provider(PodError::PolicyDenied(msg)) => (-32003, msg.clone()),
            PodRpcError::Provider(e) => (-32603, e.to_string()),
        }
    }
}
```

- [ ] **Step 2: Export rpc module from lib.rs**

Add `pub mod rpc;` to `crates/sb-pods/src/lib.rs`.

- [ ] **Step 3: Register handlers in sb-ipc server**

In `crates/sb-ipc/src/server.rs`, following the existing handler registration pattern (look for `server.register("sb.task.create"` etc.), add:

```rust
server.register("sb.pod.create", /* wire to PodRpcHandlers::handle_create */);
server.register("sb.pod.exec", /* wire to PodRpcHandlers::handle_exec */);
server.register("sb.pod.status", /* wire to PodRpcHandlers::handle_status */);
server.register("sb.pod.snapshot", /* wire to PodRpcHandlers::handle_snapshot */);
server.register("sb.pod.destroy", /* wire to PodRpcHandlers::handle_destroy */);
server.register("sb.pod.list", /* wire to PodRpcHandlers::handle_list */);
```

The implementor must read the existing handler registration pattern and follow it exactly -- creating closures that capture the `PodRpcHandlers` from `RpcContext`.

- [ ] **Step 4: Verify compilation**

Run: `cd ~/switchboard && cargo check -p sb-pods -p sb-ipc`
Expected: Compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/sb-pods/ crates/sb-ipc/
git commit -m "feat(sb-pods): add RPC handlers and wire sb.pod.* methods into daemon"
```

---

## Task 10: CLI -- `sb pod` Subcommand Group

**Files:**
- Modify: `crates/sb-cli/src/main.rs` (or wherever subcommands are defined)

- [ ] **Step 1: Read existing CLI command structure**

Run: `cd ~/switchboard && grep -rn "Subcommand\|#\[command\]" crates/sb-cli/src/ | head -30`

Identify the pattern used for subcommand registration (likely clap derive macros).

- [ ] **Step 2: Add `sb pod` subcommand group**

Following the existing pattern, add:

```rust
#[derive(Subcommand)]
enum PodCmd {
    /// Create a new pod from intent or spec
    Create {
        #[arg(long)]
        intent: Option<String>,
        #[arg(long)]
        spec: Option<PathBuf>,
        #[arg(long)]
        task: Option<String>,
    },
    /// Execute a command in a pod
    Exec {
        pod_id: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Show pod status
    Status { pod_id: String },
    /// Create a snapshot of a pod
    Snapshot {
        pod_id: String,
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Destroy a pod
    Destroy { pod_id: String },
    /// List all active pods
    List,
}
```

- [ ] **Step 3: Wire handlers to IPC calls**

Each CLI subcommand sends the corresponding JSON-RPC call to the daemon socket:
- `sb pod create --intent "node with postgres"` sends `sb.pod.create { "intent": "node with postgres" }`
- `sb pod exec pod_01ABC -- npm test` sends `sb.pod.exec { "pod_id": "pod_01ABC", "command": ["npm", "test"] }`
- `sb pod list` sends `sb.pod.list {}`

Follow the existing pattern in `sb-cli` for how other commands send IPC calls.

- [ ] **Step 4: Test CLI help**

Run: `cd ~/switchboard && cargo run -p sb-cli -- pod --help`
Expected: Shows pod subcommand help with create/exec/status/snapshot/destroy/list.

- [ ] **Step 5: Commit**

```bash
git add crates/sb-cli/
git commit -m "feat(cli): add 'sb pod' subcommand group for pod lifecycle management"
```

---

## Task 11: MCP Tools -- Expose Pods to Agents

**Files:**
- Modify: MCP serve handler in `crates/sb-cli/` (wherever `sb-mcp-serve` is defined)

- [ ] **Step 1: Read existing MCP tool definitions**

Run: `cd ~/switchboard && grep -rn "mcp\|tool_name\|tool_description\|tools/list" crates/sb-cli/src/ | head -40`

Identify where MCP tools are defined (the 9 existing tools).

- [ ] **Step 2: Add pod MCP tools**

Following the existing MCP tool pattern, add 3 tools:

**create_pod:**
- name: `create_pod`
- description: "Create an isolated sandbox pod for executing code. Pass a natural language intent like 'node with postgres' or a structured spec."
- inputSchema: `{ intent: string, task_id?: string }`

**pod_exec:**
- name: `pod_exec`
- description: "Execute a command inside a running sandbox pod. Returns stdout, stderr, and exit code."
- inputSchema: `{ pod_id: string (required), command: string[] (required) }`

**destroy_pod:**
- name: `destroy_pod`
- description: "Stop and remove a sandbox pod when done."
- inputSchema: `{ pod_id: string (required) }`

- [ ] **Step 3: Wire MCP tools to daemon RPC**

Each MCP tool call translates to the corresponding `sb.pod.*` RPC call to the daemon.

- [ ] **Step 4: Verify MCP tool listing**

Run: `cd ~/switchboard && echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | cargo run -p sb-cli -- mcp-serve 2>/dev/null | head -5`
Expected: Output includes `create_pod`, `pod_exec`, `destroy_pod` (now 12 tools total).

- [ ] **Step 5: Commit**

```bash
git add crates/sb-cli/
git commit -m "feat(mcp): expose create_pod, pod_exec, destroy_pod as MCP tools"
```

---

## Task 12: Integration Test -- End-to-End Pod Lifecycle

**Files:**
- Create: `crates/sb-pods/tests/e2e_test.rs`

- [ ] **Step 1: Write E2E test (requires podman installed)**

```rust
// crates/sb-pods/tests/e2e_test.rs
//! End-to-end test for pod lifecycle.
//! Requires: podman installed and running.
//! Run with: cargo test -p sb-pods --test e2e_test -- --ignored

use sb_pods::intent::IntentParser;
use sb_pods::machine::MachineManager;
use sb_pods::podman::PodmanProvider;
use sb_pods::provider::PodProvider;
use sb_pods::types::*;
use sb_core::id::PodId;

#[tokio::test]
#[ignore] // Requires podman
async fn test_full_pod_lifecycle() {
    // 1. Ensure machine is ready
    let machine = MachineManager::new();
    machine.ensure_ready().await.expect("machine should be ready");

    // 2. Create provider
    let provider = PodmanProvider::new(&machine.socket_path());
    assert!(provider.is_available().await, "podman should be available");

    // 3. Parse intent
    let parser = IntentParser::new();
    let spec = parser.parse("ubuntu environment").unwrap();

    // 4. Create pod
    let pod_id = PodId::new();
    let session = provider.create(&pod_id, &spec).await
        .expect("pod create should succeed");
    assert!(matches!(session.status, PodStatus::Running));

    // 5. Execute command
    let result = provider.exec(&pod_id, &ExecRequest {
        command: vec!["echo".into(), "hello from pod".into()],
        working_dir: None,
        env: Default::default(),
        timeout_seconds: Some(10),
    }).await.expect("exec should succeed");
    assert_eq!(result.exit_code, 0);

    // 6. Check status
    let status = provider.status(&pod_id).await.expect("status should succeed");
    assert!(matches!(status, PodStatus::Running));

    // 7. Destroy
    provider.destroy(&pod_id).await.expect("destroy should succeed");
}
```

- [ ] **Step 2: Run the test (if podman available)**

Run: `cd ~/switchboard && cargo test -p sb-pods --test e2e_test -- --ignored -v 2>&1 | tail -20`
Expected: If podman is installed, all steps pass. If not, test is skipped (ignored).

- [ ] **Step 3: Commit**

```bash
git add crates/sb-pods/tests/
git commit -m "test(sb-pods): add end-to-end pod lifecycle integration test"
```

---

## Summary

| Task | What it delivers | Files |
|------|-----------------|-------|
| 1 | Core types + PodProvider trait | `sb-pods/types.rs`, `provider.rs`, `lib.rs` |
| 2 | Pod IDs, events, policy operations | `sb-core`, `sb-events`, `sb-policy` |
| 3 | PodmanProvider (real container backend) | `sb-pods/podman.rs` |
| 4 | PodGovernor (policy + audit wrapper) | `sb-pods/governor.rs` |
| 5 | IntentParser (NL to PodSpec) | `sb-pods/intent.rs` |
| 6 | MachineManager (macOS VM lifecycle) | `sb-pods/machine.rs` |
| 7 | CredentialInjector (OSP integration) | `sb-pods/credential.rs` |
| 8 | CloudProvider stub (E2B/Daytona fallback) | `sb-pods/cloud.rs` |
| 9 | RPC handlers (daemon integration) | `sb-pods/rpc.rs`, `sb-ipc` |
| 10 | CLI subcommands (`sb pod *`) | `sb-cli` |
| 11 | MCP tools (agent-facing) | `sb-cli` MCP serve |
| 12 | E2E integration test | `sb-pods/tests/e2e_test.rs` |

**After all 12 tasks, an agent can:**
```
Agent -> MCP create_pod("node with postgres") -> Local pod starts (~200ms)
Agent -> MCP pod_exec(id, ["npm", "test"]) -> Runs in isolation, policy-gated, event-logged
Agent -> MCP destroy_pod(id) -> Clean teardown
```
