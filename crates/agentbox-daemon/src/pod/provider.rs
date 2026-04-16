use crate::pod::types::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PodError {
    #[error("pod not found: {0}")]
    NotFound(String),
    #[error("pod already exists: {0}")]
    AlreadyExists(String),
    #[error("image pull failed: {0}")]
    ImagePullFailed(String),
    #[error("exec failed: {0}")]
    ExecFailed(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("timeout after {0}s")]
    Timeout(u64),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[async_trait::async_trait]
pub trait PodProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn is_available(&self) -> bool;
    async fn create(&self, id: &str, spec: &PodSpec) -> Result<PodSession, PodError>;
    async fn exec(&self, id: &str, req: &ExecRequest) -> Result<ExecResult, PodError>;
    async fn status(&self, id: &str) -> Result<PodStatus, PodError>;
    async fn destroy(&self, id: &str) -> Result<(), PodError>;
    async fn list(&self) -> Result<Vec<PodSession>, PodError>;
}
