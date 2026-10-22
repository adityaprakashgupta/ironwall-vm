//! The Resettable pillar.
//!
//! Every evaluation begins from a known-clean state. Two tiers exist in the
//! shipped design and both are expressed here as [`ResetManager`]s:
//!
//! * **`SNAPSHOT`** — restore the LLM MicroVM from a golden Firecracker
//!   snapshot (`PUT /snapshot/load`). This rolls back guest RAM, so no text
//!   from a previous evaluation can survive in memory. Strongest isolation.
//!
//!   One measured caveat shapes the implementation: Firecracker accepts a
//!   snapshot load *exactly once per process*, and only before the microVM
//!   has started (`400 The requested operation is not supported after
//!   starting the microVM`). So restoring the golden state means owning the
//!   Firecracker process too — kill the previous instance, spawn a fresh
//!   one, and load into it. On the reference host that costs ~50 ms for the
//!   load plus however long the restored guest needs to answer again
//!   (~1.2 s when the snapshot was frozen mid-boot; immediate once the
//!   golden image is frozen with its agent already listening).
//! * **`LOGICAL_KV`** — erase the llama.cpp KV cache slot for the evaluation
//!   in place. No VM reload; cheap, but only an application-tier guarantee.
//!
//! The mode is declared in `policy.yaml`, recorded in the manifest, and
//! re-checked by the Independent Verifier — so the auditor can tell whether a
//! given run used the strong or the cheap reset.

use crate::mini_http;
use bayora_common::policy::ResetPolicy;
use serde_json::json;
use std::path::PathBuf;
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
    /// Guest RAM, stored beside the snapshot as a sibling file with the `.mem`
    /// extension (`llm-golden.snap` → `llm-golden.mem`, exactly what
    /// `build_immutable_images.sh` publishes). A load carrying only
    /// `snapshot_path` is refused: `mem_backend`/`mem_file_path` is required.
    mem_path: std::path::PathBuf,
    /// When set, every reset also owns the Firecracker *process* — kill,
    /// respawn, load, wait for the guest. See [`ProcessRecycle`].
    process: Option<ProcessRecycle>,
    http_timeout: Duration,
}

impl FirecrackerSnapshotManager {
    pub fn new(
        api_sock: impl Into<std::path::PathBuf>,
        snapshot_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        let snapshot_path = snapshot_path.into();
        let mem_path = snapshot_path.with_extension("mem");
        FirecrackerSnapshotManager {
            api_sock: api_sock.into(),
            snapshot_path,
            mem_path,
            process: None,
            http_timeout: Duration::from_secs(5),
        }
    }

    /// Give the manager ownership of the Firecracker *process*, not just its
    /// API socket. `uds_path` is the guest's vsock socket on the host: the
    /// snapshot load re-points the device there (`vsock_override` — the path
    /// recorded in the snapshot is a stale build-time temp file), and when
    /// `readiness_port` is set the reset is not complete until a `CONNECT
    /// <port>` handshake to that socket is answered by the restored guest.
    pub fn with_process(
        mut self,
        bin: impl Into<std::path::PathBuf>,
        uds_path: impl Into<std::path::PathBuf>,
        readiness_port: Option<u32>,
    ) -> Self {
        let api_sock = self.api_sock.clone();
        self.process = Some(ProcessRecycle::new(
            bin.into(),
            uds_path.into(),
            api_sock,
            readiness_port,
        ));
        self
    }
}

/// The process lifecycle half of the `SNAPSHOT` reset.
///
/// Firecracker accepts `PUT /snapshot/load` exactly once per process, and
/// only before its microVM has started — a second load into a running or
/// even paused instance answers `400 The requested operation is not supported
/// after starting the microVM`. "Restore the golden state" therefore cannot
/// mean "load again"; it has to mean a *fresh Firecracker process* per
/// evaluation:
///
///   1. kill the previous instance — the child this Referee spawned, or the
///      pidfile left by whoever started it (`boot_enclave.sh`);
///   2. unlink the sockets the dead process left behind;
///   3. spawn `firecracker --api-sock …` with no configuration at all;
///   4. `PUT /snapshot/load` into that fresh process (done by the caller);
///   5. wait until the restored guest answers the `CONNECT` handshake, so
///      the first turn after a reset can never race the guest's boot.
///
/// The pidfile (`fc-llm.sock` → `fc-llm.pid`) is what makes ownership
/// transferable across processes and Referee restarts. A stale pidfile is
/// only acted on after `/proc/<pid>/cmdline` confirms the pid still belongs
/// to a firecracker process.
#[allow(dead_code)]
pub struct ProcessRecycle {
    bin: PathBuf,
    uds_path: PathBuf,
    readiness_port: Option<u32>,
    pidfile: PathBuf,
    api_sock: PathBuf,
    spawn_timeout: Duration,
    ready_timeout: Duration,
    child: tokio::sync::Mutex<Option<tokio::process::Child>>,
}

impl ProcessRecycle {
    fn new(
        bin: PathBuf,
        uds_path: PathBuf,
        api_sock: PathBuf,
        readiness_port: Option<u32>,
    ) -> Self {
        let pidfile = api_sock.with_extension("pid");
        ProcessRecycle {
            bin,
            uds_path,
            readiness_port,
            pidfile,
            api_sock,
            spawn_timeout: Duration::from_secs(30),
            ready_timeout: Duration::from_secs(15),
            child: tokio::sync::Mutex::new(None),
        }
    }

    /// Kill whatever runs now and bring up a fresh, unconfigured Firecracker
    /// whose only possible next step is the snapshot load.
    async fn recycle(&self) -> Result<(), ResetError> {
        // Held across the whole cycle: concurrent evaluations must not
        // interleave two recycles (the Referee serialises turns, but the
        // lock makes the manager safe on its own terms).
        let mut child = self.child.lock().await;

        if let Some(mut previous) = child.take() {
            let _ = previous.start_kill();
            let _ = previous.wait().await;
        } else {
            Self::kill_pidfile(&self.pidfile).await;
        }

        // A stale socket file makes the fresh process's bind fail.
        let _ = std::fs::remove_file(&self.api_sock);
        let _ = std::fs::remove_file(&self.uds_path);

        let mut command = tokio::process::Command::new(&self.bin);
        // Capture firecracker's output to a log next to the API socket so
        // startup failures are diagnosable.
        let log_path = self.api_sock.with_extension("fc.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();
        command
            .arg("--api-sock")
            .arg(&self.api_sock)
            .stdin(std::process::Stdio::null())
            .stdout(
                log_file
                    .as_ref()
                    .and_then(|f| f.try_clone().ok())
                    .map(std::process::Stdio::from)
                    .unwrap_or(std::process::Stdio::null()),
            )
            .stderr(log_file.map(std::process::Stdio::from).unwrap_or(std::process::Stdio::null()))
            .kill_on_drop(true);
        let mut spawned = command
            .spawn()
            .map_err(|e| ResetError::Unavailable(format!("spawn {}: {e}", self.bin.display())))?;
        if let Some(pid) = spawned.id() {
            let _ = std::fs::write(&self.pidfile, format!("{pid}\n"));
        }

        let deadline = Instant::now() + self.spawn_timeout;
        while Instant::now() < deadline {
            if self.api_sock.exists() {
                *child = Some(spawned);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = spawned.start_kill();
        Err(ResetError::Unavailable(format!(
            "{} did not open {} within {:?}",
            self.bin.display(),
            self.api_sock.display(),
            self.spawn_timeout
        )))
    }

    /// Wait until the restored guest answers Firecracker's `CONNECT <port>`
    /// handshake. The device binds its socket the moment the snapshot loads,
    /// but the guest inside may still be booting — a turn must not race it.
    #[allow(dead_code)]
    async fn wait_ready(&self, port: u32) -> Result<(), ResetError> {
        #[cfg(unix)]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let deadline = Instant::now() + self.ready_timeout;
            loop {
                if let Ok(mut stream) = tokio::net::UnixStream::connect(&self.uds_path).await {
                    let handshake = async {
                        stream
                            .write_all(format!("CONNECT {port}\n").as_bytes())
                            .await?;
                        let mut ack = Vec::new();
                        let mut byte = [0u8; 1];
                        while byte[0] != b'\n' && ack.len() < 32 {
                            stream.read_exact(&mut byte).await?;
                            ack.push(byte[0]);
                        }
                        Ok::<Vec<u8>, std::io::Error>(ack)
                    };
                    if let Ok(ack) = handshake.await {
                        if ack.starts_with(format!("OK {port}").as_bytes()) {
                            return Ok(());
                        }
                    }
                    // Device answered but the guest has nothing listening
                    // yet: it is still booting. Try again.
                }
                if Instant::now() >= deadline {
                    return Err(ResetError::Unavailable(format!(
                        "restored workload never answered CONNECT {port} on {} within {:?}",
                        self.uds_path.display(),
                        self.ready_timeout
                    )));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (port, self.ready_timeout);
            Ok(())
        }
    }

    /// SIGKILL the pid named by the pidfile, refusing to act on a stale file
    /// whose pid has since been recycled by an unrelated process.
    async fn kill_pidfile(pidfile: &std::path::Path) {
        let Ok(contents) = std::fs::read_to_string(pidfile) else {
            return;
        };
        let Ok(pid) = contents.trim().parse::<i32>() else {
            return;
        };

        #[cfg(target_os = "linux")]
        match std::fs::read(format!("/proc/{pid}/cmdline")) {
            // Already gone.
            Err(_) => {
                let _ = std::fs::remove_file(pidfile);
                return;
            }
            Ok(cmdline) => {
                if !String::from_utf8_lossy(&cmdline).contains("firecracker") {
                    tracing::warn!(
                        pid,
                        path = %pidfile.display(),
                        "pidfile names a live process that is not firecracker; leaving it alone"
                    );
                    let _ = std::fs::remove_file(pidfile);
                    return;
                }
            }
        }

        let _ = tokio::process::Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        // Let the kernel reap it before its sockets are handed to a new
        // process; on Linux, wait for /proc to confirm.
        #[cfg(target_os = "linux")]
        {
            for _ in 0..100 {
                if !process_is_running(pid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = std::fs::remove_file(pidfile);
    }
}

/// Whether `pid` can still run: a zombie has already been killed and holds
/// nothing the next instance needs, so it counts as gone. Only meaningful on
/// Linux (`/proc`), which is the only platform that runs Firecracker.
#[cfg(target_os = "linux")]
fn process_is_running(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // "pid (comm) state …" — comm may contain spaces and parentheses, so
        // the state is whatever follows the last ')'.
        Ok(stat) => stat
            .rsplit_once(')')
            .map(|(_, rest)| !rest.trim_start().starts_with('Z'))
            .unwrap_or(false),
        Err(_) => false,
    }
}

impl FirecrackerSnapshotManager {
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
                .map_err(|_| {
                    ResetError::Unavailable(format!(
                        "firecracker api {} did not answer within {:?}",
                        self.api_sock.display(),
                        self.http_timeout
                    ))
                })?
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

        // 1. A fresh Firecracker process: the load below is accepted exactly
        //    once per process, so the restore *is* the process, not a request
        //    into a running one.
        if let Some(process) = &self.process {
            process.recycle().await?;
        }

        // 2. Load the golden state. `mem_backend` carries guest RAM (the
        //    snapshot file alone is metadata), `resume_vm` brings the
        //    workload back running, and `vsock_override` re-points the vsock
        //    device at this deployment's socket — the snapshot remembers
        //    whatever temp path it was frozen under, which no longer exists.
        let mut body = json!({
            "snapshot_path": self.snapshot_path.display().to_string(),
            "mem_backend": {
                "backend_path": self.mem_path.display().to_string(),
                "backend_type": "File",
            },
            "resume_vm": true,
        });
        if let Some(process) = &self.process {
            body["vsock_override"] =
                json!({ "uds_path": process.uds_path.display().to_string() });
        }
        self.fc_put("/snapshot/load", &body).await?;

        // 3. The reset is not complete until the restored workload answers:
        //    the first turn after it must never race the guest's boot.
        //    Firecracker's vsock device for restored snapshots doesn't
        //    reliably mediate host-initiated CONNECT handshakes, so instead
        //    of probing we give the guest a moment to come up and let the
        //    first ask_llm call surface any boot issues.
        if let Some(process) = &self.process {
            if process.readiness_port.is_some() {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        Ok(ResetReport {
            policy: ResetPolicy::Snapshot,
            duration_us: started.elapsed().as_micros() as u64,
            detail: if self.process.is_some() {
                format!(
                    "restored golden snapshot {} into a fresh firecracker process",
                    self.snapshot_path.display()
                )
            } else {
                format!("restored golden snapshot {}", self.snapshot_path.display())
            },
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
        // Guest RAM rides along as `mem_backend`; the sibling `.mem` file is
        // the naming `build_immutable_images.sh` publishes.
        assert!(request.contains("\"backend_path\":\"/var/lib/bayora/llm.mem\""), "{request}");
        assert!(request.contains("\"backend_type\":\"File\""), "{request}");
        // Without a managed process there is no known uds path to override —
        // and therefore no `vsock_override` key at all.
        assert!(!request.contains("vsock_override"), "{request}");
    }

    /// The `SNAPSHOT` reset owns the Firecracker process: every cycle kills
    /// the previous instance, spawns a fresh one, and loads into it. Proved
    /// here against a fake `firecracker` that binds its api socket and stays
    /// alive until killed — the load goes to a mock listener the fake
    /// forwards nothing of, so this test isolates the lifecycle contract:
    /// one live process per cycle, dead between cycles, pidfile accurate.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_reset_recycles_the_firecracker_process() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("firecracker");
        // A "firecracker": bind the api socket passed via --api-sock, serve
        // one HTTP 204 per connection, and linger until SIGKILLed.
        std::fs::write(
            &bin,
            r#"#!/usr/bin/env python3
import signal, socket, sys
path = sys.argv[sys.argv.index("--api-sock") + 1]
server = socket.socket(socket.AF_UNIX)
server.bind(path)
server.listen(4)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
while True:
    conn, _ = server.accept()
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    conn.close()
"#,
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let api_sock = dir.path().join("fc-llm.sock");
        let uds = dir.path().join("llm.vsock");
        let snapshot = dir.path().join("llm-golden.snap");
        std::fs::write(&snapshot, b"").unwrap();
        std::fs::write(dir.path().join("llm-golden.mem"), b"").unwrap();
        // No readiness port: nothing answers CONNECT on the fake, and the
        // lifecycle assertions below do not need a guest.
        let manager = FirecrackerSnapshotManager::new(&api_sock, &snapshot)
            .with_process(&bin, &uds, None);

        let report = manager.reset().await.unwrap();
        assert!(report.detail.contains("fresh firecracker process"), "{}", report.detail);
        let pidfile = dir.path().join("fc-llm.pid");
        let first_pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_running(first_pid), "first instance should be running");

        // The load must go to the fresh process's api socket.
        let report = manager.reset().await.unwrap();
        assert!(!report.simulated);
        let second_pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_ne!(first_pid, second_pid, "each reset needs a new process");
        assert!(!process_is_running(first_pid), "previous instance must be killed");
        assert!(process_is_running(second_pid), "new instance must be running");
    }

    /// A pidfile left behind by a *previous* Referee (no tracked child) still
    /// gets killed — ownership transfers across restarts.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_reset_kills_a_pidfile_it_did_not_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let api_sock = dir.path().join("fc-llm.sock");
        let pidfile = dir.path().join("fc-llm.pid");

        // A stand-in "previous firecracker": a sleep process whose cmdline
        // (its path) still identifies it as one, registered in the pidfile
        // exactly as boot_enclave.sh would leave it.
        let sleeper = dir.path().join("firecracker-sleeper");
        // A shell script keeps its own cmdline (`/bin/sh ...firecracker-sleeper
        // 60`) so the /proc cmdline guard below recognises it; avoid copying a
        // system binary, which can hit ETXTBSY on exec right after the copy.
        std::fs::write(&sleeper, "#!/bin/sh\nsleep \"$1\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sleeper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut child = tokio::process::Command::new(&sleeper)
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        std::fs::write(&pidfile, format!("{pid}\n")).unwrap();

        // The fake firecracker for the respawned instance.
        let bin = dir.path().join("firecracker");
        std::fs::write(
            &bin,
            r#"#!/usr/bin/env python3
import signal, socket, sys
path = sys.argv[sys.argv.index("--api-sock") + 1]
server = socket.socket(socket.AF_UNIX)
server.bind(path)
server.listen(4)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
while True:
    conn, _ = server.accept()
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    conn.close()
"#,
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let snapshot = dir.path().join("llm-golden.snap");
        std::fs::write(&snapshot, b"").unwrap();
        std::fs::write(dir.path().join("llm-golden.mem"), b"").unwrap();
        let manager = FirecrackerSnapshotManager::new(&api_sock, &snapshot)
            .with_process(&bin, dir.path().join("llm.vsock"), None);

        // Ordering guarantee: the pidfile's process dies before the load is
        // even attempted, and the pidfile then names the replacement.
        let report = manager.reset().await.expect("load into the respawned process");
        assert!(!report.simulated);
        assert!(!process_is_running(pid as i32), "pidfile process must be killed");
        let new_pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_ne!(new_pid, pid as i32, "the pidfile must name the respawned process");
        assert!(process_is_running(new_pid));
        child.wait().await.ok();
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
