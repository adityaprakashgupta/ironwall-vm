//! Firecracker MicroVM management.
//! Directly manages Firecracker processes instead of shelling out to
//! boot_enclave.sh, giving full control over the boot lifecycle.

use crate::trace::{Trace, TraceStage};
use anyhow::{anyhow, Result};
use serde_json::json;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Boot the Firecracker MicroVMs (red, blue, llm).
///
/// Directly starts Firecracker processes for blue and red VMs. The llm VM
/// is owned by the Referee (via --reset snapshot) and is not booted here.
pub fn boot_enclave(
    trace: &Trace,
    root: &Path,
    kernel: &Path,
    firecracker_bin: &Path,
    images_dir: &Path,
    runtime_dir: &Path,
    task_file: &Path,
    mem_mib: u32,
    vcpus: u32,
) -> Result<BootResult> {
    trace.info(
        TraceStage::MicroVMBoot,
        "booting Firecracker MicroVMs directly",
        Default::default(),
    );

    fs::create_dir_all(runtime_dir)?;

    // Clean stale sockets
    for entry in fs::read_dir(runtime_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.ends_with(".sock") || name_str.ends_with(".vsock") || name_str.ends_with(".pid") {
            let _ = fs::remove_file(entry.path());
        }
    }

    // Get model digest from images.json
    let model_sha = get_model_digest(root)?;

    // Boot blue VM (CID 4)
    boot_single_vm(
        trace,
        "blue",
        4,
        9001,
        kernel,
        &images_dir.join("blue.ext4"),
        runtime_dir,
        firecracker_bin,
        mem_mib,
        vcpus,
        None,
        &model_sha,
    )?;

    // Wait for blue to be ready
    wait_for_vsock(trace, runtime_dir.join("blue.vsock"), "blue")?;

    // Boot red VM (CID 3) with task disk
    boot_single_vm(
        trace,
        "red",
        3,
        9000,
        kernel,
        &images_dir.join("red.ext4"),
        runtime_dir,
        firecracker_bin,
        mem_mib,
        vcpus,
        Some(task_file),
        &model_sha,
    )?;

    // Wait for red to be ready
    wait_for_vsock(trace, runtime_dir.join("red.vsock"), "red")?;

    let result = BootResult {
        blue_vsock: runtime_dir.join("blue.vsock"),
        red_vsock: runtime_dir.join("red.vsock"),
        llm_vsock: runtime_dir.join("llm.vsock"), // owned by Referee
        runtime_dir: runtime_dir.to_path_buf(),
    };

    trace.success(
        TraceStage::MicroVMBoot,
        "enclave booted",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("blue_vsock".into(), result.blue_vsock.display().to_string().into());
            m.insert("red_vsock".into(), result.red_vsock.display().to_string().into());
            m.insert("llm_vsock".into(), result.llm_vsock.display().to_string().into());
            m
        },
    );

    Ok(result)
}

/// Boot a single Firecracker MicroVM.
fn boot_single_vm(
    trace: &Trace,
    role: &str,
    cid: u32,
    port: u32,
    kernel: &Path,
    image: &Path,
    runtime_dir: &Path,
    firecracker_bin: &Path,
    mem_mib: u32,
    vcpus: u32,
    extra_drive: Option<&Path>,
    model_sha: &str,
) -> Result<()> {
    let api_sock = runtime_dir.join(format!("fc-{role}.sock"));
    let vsock_uds = runtime_dir.join(format!("{role}.vsock"));
    let config_path = runtime_dir.join(format!("fc-{role}.json"));

    // Remove stale sockets
    let _ = fs::remove_file(&api_sock);
    let _ = fs::remove_file(&vsock_uds);

    // Build drives JSON
    let mut drives = vec![json!({
        "drive_id": "rootfs",
        "path_on_host": image.display().to_string(),
        "is_root_device": true,
        "is_read_only": true
    })];

    if let Some(extra) = extra_drive {
        drives.push(json!({
            "drive_id": format!("{role}-task"),
            "path_on_host": extra.display().to_string(),
            "is_root_device": false,
            "is_read_only": true
        }));
    }

    // Build boot args
    let mut boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role={role} bayora.port={port}"
    );
    if role == "llm" && !model_sha.is_empty() {
        boot_args.push_str(&format!(" bayora.model_sha256={model_sha}"));
    }

    let config = json!({
        "boot-source": {
            "kernel_image_path": kernel.display().to_string(),
            "boot_args": boot_args
        },
        "drives": drives,
        "machine-config": { "vcpu_count": vcpus, "mem_size_mib": mem_mib, "smt": false },
        "vsock": { "guest_cid": cid, "uds_path": vsock_uds.display().to_string() },
        "serial": { "path": runtime_dir.join(format!("{role}.serial")).display().to_string() },
        "logger": { "log_path": runtime_dir.join(format!("{role}.log")).display().to_string(), "level": "Warning" }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    // Start Firecracker
    let mut fc = Command::new(firecracker_bin)
        .arg("--api-sock").arg(&api_sock)
        .arg("--config-file").arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for API socket
    for _ in 0..100 {
        if api_sock.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Start the instance via Firecracker API
    let client = reqwest::blocking::Client::new();
    client
        .put(format!("http://localhost/actions"))
        .header("Content-Type", "application/json")
        .body(json!({"action_type": "InstanceStart"}).to_string())
        .send()?;

    // Wait for vsock socket
    for _ in 0..100 {
        if vsock_uds.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Keep the Firecracker process running (don't kill it)
    // We intentionally don't call fc.wait() - the process runs in background

    trace.info(
        TraceStage::MicroVMBoot,
        &format!("VM booted: {role} (CID {cid})"),
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("role".into(), role.into());
            m.insert("cid".into(), cid.into());
            m.insert("port".into(), port.into());
            m.insert("vsock_uds".into(), vsock_uds.display().to_string().into());
            m
        },
    );

    Ok(())
}

/// Wait for a vsock socket to appear.
fn wait_for_vsock(trace: &Trace, sock_path: PathBuf, role: &str) -> Result<()> {
    for _ in 0..200 {
        if sock_path.exists() {
            trace.success(
                TraceStage::MicroVMBoot,
                &format!("{role} vsock ready"),
                {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("role".into(), role.into());
                    m.insert("socket".into(), sock_path.display().to_string().into());
                    m
                },
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(anyhow!("{role} vsock socket never appeared at {}", sock_path.display()))
}

/// Result of booting the enclave.
pub struct BootResult {
    pub blue_vsock: PathBuf,
    pub red_vsock: PathBuf,
    pub llm_vsock: PathBuf,
    pub runtime_dir: PathBuf,
}

/// Get the model digest from config/images.json.
fn get_model_digest(root: &Path) -> Result<String> {
    let images_json_path = root.join("config/images.json");
    let contents = fs::read_to_string(&images_json_path)?;
    let images: serde_json::Value = serde_json::from_str(&contents)?;
    let model_digest = images["model_digest"]
        .as_str()
        .ok_or_else(|| anyhow!("model_digest not found in images.json"))?;
    Ok(model_digest.strip_prefix("sha256:").unwrap_or(model_digest).to_string())
}

/// Kill all Firecracker processes.
pub fn kill_all_firecrackers() -> Result<()> {
    let _ = Command::new("sudo").arg("pkill").arg("-9").arg("firecracker").status();
    Ok(())
}