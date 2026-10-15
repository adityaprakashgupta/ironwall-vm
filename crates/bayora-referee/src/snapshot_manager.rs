//! The Resettable pillar.
//!
//! Every evaluation begins from a known-clean state. Two tiers exist in the
//! shipped design and both are expressed here as [`ResetManager`]s:
//!
//! * **`SNAPSHOT`** — restore the LLM MicroVM from a golden Firecracker
//!   snapshot (`PUT /snapshot/load`). This rolls back guest RAM, so no text
//!   from a previous evaluation can survive in memory. Strongest isolation;
//!   ~330 ms per evaluation.
//! * **`LOGICAL_KV`** — erase the llama.cpp KV cache slot for the evaluation
//!   in place. No VM reload; cheap, but only an application-tier guarantee.
//!
//! The mode is declared in `policy.yaml`, recorded in the manifest, and
//! re-checked by the Independent Verifier — so the auditor can tell whether a
//! given run used the strong or the cheap reset.

use crate::mini_http;
use bayora_common::policy::ResetPolicy;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ResetError {
    #[error("reset endpoint unavailable: {0}")]
    Unavailable(String),
    #[error("reset endpoint returned HTTP {status}: {message}")]
    Rejected { status: u16, message: String },
    #[error("reset transport failure: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResetReport {
    pub policy: ResetPolicy,
    pub duration_us: u64,
    pub detail: String,
    /// `true` when no real reset ran (demo stub / test fixture).
    pub simulated: bool,
}

impl ResetReport {
    pub fn mode(&self) -> &'static str {
        self.policy.as_str()
    }
}

#[async_trait::async_trait]
pub trait ResetManager: Send + Sync {
    async fn reset(&self) -> Result<ResetReport, ResetError>;
    fn policy(&self) -> ResetPolicy;
    fn describe(&self) -> String;
}

/// Golden-snapshot restore via the Firecracker API socket.
///
/// `api_sock`/`http_timeout` are only read on unix; on other platforms
/// [`FirecrackerSnapshotManager`] fails closed with
/// [`ResetError::Unavailable`], so silence the dead-code lint there.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct FirecrackerSnapshotManager {
    api_sock: std::path::PathBuf,
    snapshot_path: std::path::PathBuf,
    http_timeout: Duration,
}

impl FirecrackerSnapshotManager {
    pub fn new(
        api_sock: impl Into<std::path::PathBuf>,
        snapshot_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        FirecrackerSnapshotManager {
            api_sock: api_sock.into(),
            snapshot_path: snapshot_path.into(),
            http_timeout: Duration::from_secs(5),
        }
    }

    /// Create the golden snapshot the manager will restore on every reset.
    /// Run once at image-build time (`microvm/build_immutable_images.sh`).
    pub async fn create_golden_snapshot(&self) -> Result<ResetReport, ResetError> {
        let body = json!({
            "snapshot_type": "Full",
            "snapshot_path": self.snapshot_path.display().to_string(),
        });
        let started = Instant::now();
        self.fc_put("/snapshot/create", &body).await?;
        Ok(ResetReport {
            policy: ResetPolicy::Snapshot,
            duration_us: started.elapsed().as_micros() as u64,
            detail: format!("golden snapshot written to {}", self.snapshot_path.display()),
            simulated: false,
        })
    }
}

impl FirecrackerSnapshotManager {
    async fn fc_put(&self, path: &str, body: &serde_json::Value) -> Result<(), ResetError> {
        #[cfg(unix)]
        {
            // Bind the serialized body: the request future borrows it, so it
            // must outlive the `timeout(...).await` below.
            let body_bytes = serde_json::to_vec(body).unwrap_or_default();
            let fut = mini_http::unix_request(
                &self.api_sock,
                "localhost",
                "PUT",
                path,
                Some(&body_bytes),
            );
            let response = tokio::time::timeout(self.http_timeout, fut)
                .await
                .map_err(|_| ResetError::Unavailable(format!(
                    "firecracker api {} did not answer within {:?}",
                    self.api_sock.display(),
                    self.http_timeout
                )))?
                .map_err(|e| ResetError::Io(format!("{}: {e}", self.api_sock.display())))?;
            if response.is_success() {
                return Ok(());
            }
            return Err(ResetError::Rejected {
                status: response.status,
                message: response
                    .body_str()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = (path, body);
            Err(ResetError::Unavailable(
                "firecracker requires unix sockets; this Referee is not on unix".into(),
            ))
        }
    }
}

#[async_trait::async_trait]
impl ResetManager for FirecrackerSnapshotManager {
    async fn reset(&self) -> Result<ResetReport, ResetError> {
        let started = Instant::now();
        // resume_vm: the restored MicroVM comes back running the workload.
        let body = json!({
            "snapshot_path": self.snapshot_path.display().to_string(),
            "resume_vm": true,
        });
        self.fc_put("/snapshot/load", &body).await?;
        Ok(ResetReport {
            policy: ResetPolicy::Snapshot,
            duration_us: started.elapsed().as_micros() as u64,
            detail: format!("restored golden snapshot {}", self.snapshot_path.display()),
            simulated: false,
        })
    }

    fn policy(&self) -> ResetPolicy {
        ResetPolicy::Snapshot
    }

    fn describe(&self) -> String {
        format!("firecracker snapshot {}", self.snapshot_path.display())
    }
}

/// llama.cpp logical KV-slot erase.
pub struct LogicalKvResetManager {
    endpoint: String,
    slot: u32,
    http_timeout: Duration,
}

impl LogicalKvResetManager {
    pub fn new(endpoint: impl Into<String>, slot: u32) -> Self {
        LogicalKvResetManager {
            endpoint: endpoint.into(),
            slot,
            http_timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait::async_trait]
impl ResetManager for LogicalKvResetManager {
    async fn reset(&self) -> Result<ResetReport, ResetError> {
        let addr = mini_http::parse_http_endpoint(&self.endpoint)
            .map_err(ResetError::Unavailable)?;
        let path = format!("/slots/{}?action=erase", self.slot);
        let started = Instant::now();
        let fut = mini_http::tcp_request(addr, "POST", &path, Some(b"{}"));
        let response = tokio::time::timeout(self.http_timeout, fut)
            .await
            .map_err(|_| ResetError::Unavailable(format!(
                "llama server {} did not answer within {:?}",
                self.endpoint, self.http_timeout
            )))?
            .map_err(|e| ResetError::Io(format!("{}: {e}", self.endpoint)))?;
        if !response.is_success() {
            return Err(ResetError::Rejected {
                status: response.status,
                message: response
                    .body_str()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            });
        }
        Ok(ResetReport {
            policy: ResetPolicy::LogicalKv,
            duration_us: started.elapsed().as_micros() as u64,
            detail: format!("erased llama.cpp KV slot {}", self.slot),
            simulated: false,
        })
    }

    fn policy(&self) -> ResetPolicy {
        ResetPolicy::LogicalKv
    }

    fn describe(&self) -> String {
        format!("llama.cpp KV erase via {} slot {}", self.endpoint, self.slot)
    }
}

/// Simulated reset for demos and tests (no VM present).
///
/// The *reported* policy is whatever the caller declared, so evidence records
/// still carry the intended reset mode; `simulated: true` marks it as such.
pub struct NoopResetManager {
    policy: ResetPolicy,
    delay: Duration,
}

impl NoopResetManager {
    pub fn new(policy: ResetPolicy) -> Self {
        NoopResetManager {
            policy,
            delay: Duration::from_millis(1),
        }
    }

    pub fn with_delay(policy: ResetPolicy, delay: Duration) -> Self {
        NoopResetManager { policy, delay }
    }
}

#[async_trait::async_trait]
impl ResetManager for NoopResetManager {
    async fn reset(&self) -> Result<ResetReport, ResetError> {
        let started = Instant::now();
        tokio::time::sleep(self.delay).await;
        Ok(ResetReport {
            policy: self.policy,
            duration_us: started.elapsed().as_micros() as u64,
            detail: format!("simulated {} reset", self.policy.as_str()),
            simulated: true,
        })
    }

    fn policy(&self) -> ResetPolicy {
        self.policy
    }

    fn describe(&self) -> String {
        format!("simulated {} reset", self.policy.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn noop_reset_reports_the_declared_policy() {
        let manager = NoopResetManager::new(ResetPolicy::Snapshot);
        let report = manager.reset().await.unwrap();
        assert_eq!(report.policy, ResetPolicy::Snapshot);
        assert_eq!(report.mode(), "SNAPSHOT");
        assert!(report.simulated);
        assert!(report.duration_us > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn logical_kv_manager_reports_app_tier() {
        let manager = LogicalKvResetManager::new("http://127.0.0.1:8081", 0);
        assert_eq!(manager.policy(), ResetPolicy::LogicalKv);
        assert!(manager.describe().contains("KV"));
        // No llama server listening here, so the reset must fail closed.
        let err = manager.reset().await.unwrap_err();
        assert!(matches!(err, ResetError::Io(_) | ResetError::Unavailable(_)));
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn firecracker_manager_uses_snapshot_load_over_api_sock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("fc.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen_clone = seen.clone();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                *seen_clone.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = socket.shutdown().await;
            }
        });

        let manager = FirecrackerSnapshotManager::new(&sock, "/var/lib/bayora/llm.snap");
        let report = manager.reset().await.unwrap();
        assert_eq!(report.policy, ResetPolicy::Snapshot);
        assert!(!report.simulated);
        let request = seen.lock().unwrap().clone();
        assert!(request.starts_with("PUT /snapshot/load HTTP/1.1"), "{request}");
        assert!(request.contains("resume_vm"), "{request}");
        assert!(request.contains("/var/lib/bayora/llm.snap"), "{request}");
    }

    #[cfg(not(unix))]
    #[tokio::test(start_paused = true)]
    async fn firecracker_manager_fails_closed_off_unix() {
        let manager =
            FirecrackerSnapshotManager::new("/run/fc.sock", "/var/lib/bayora/llm.snap");
        let err = manager.reset().await.unwrap_err();
        assert!(matches!(err, ResetError::Unavailable(_)));
    }

    #[cfg(not(unix))]
    #[tokio::test(start_paused = true)]
    async fn firecracker_manager_reports_declared_policy() {
        let manager =
            FirecrackerSnapshotManager::new("/run/fc.sock", "/var/lib/bayora/llm.snap");
        assert_eq!(manager.policy(), ResetPolicy::Snapshot);
        assert!(manager.describe().contains("firecracker"));
    }
}
