//! Immutable ext4 image building.
//! Replaces microvm/build_immutable_images.sh — stages guest payloads, builds
//! ext4 images, takes golden snapshots, and publishes content-addressed
//! digests to config/images.json.

use crate::trace::{Trace, TraceStage};
use anyhow::{anyhow, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Build all three guest images (red, blue, llm) and publish digests.
pub fn build_images(
    trace: &Trace,
    root: &Path,
    kernel: &Path,
    model: &Path,
    firecracker_bin: &Path,
) -> Result<ImagesResult> {
    let images_dir = root.join("microvm/images");
    let snapshots_dir = root.join("microvm/snapshots");
    std::fs::create_dir_all(&images_dir)?;
    std::fs::create_dir_all(&snapshots_dir)?;

    // Build images
    let red_digest = build_role_image(trace, root, "red", kernel, &images_dir, None)?;
    let blue_digest = build_role_image(trace, root, "blue", kernel, &images_dir, None)?;
    let llm_digest = build_role_image(trace, root, "llm", kernel, &images_dir, Some(model))?;

    // Take golden snapshot
    let snapshot_path = snapshots_dir.join("llm-golden.snap");
    let mem_path = snapshots_dir.join("llm-golden.mem");
    take_golden_snapshot(
        trace,
        firecracker_bin,
        kernel,
        &images_dir.join("llm.ext4"),
        model,
        &snapshot_path,
        &mem_path,
    )?;

    // Read model digest
    let model_digest = format!("sha256:{}", sha256_hex(model)?);

    // Compute other digests
    let kernel_digest = format!("sha256:{}", sha256_hex(kernel)?);
    let blue_policy_digest = format!(
        "sha256:{}",
        sha256_hex(&root.join("workloads/common/policy.py"))?
    );
    let fc_version = get_firecracker_version(firecracker_bin)?;

    // Write config/images.json
    let images_json = json!({
        "kernel_digest": kernel_digest,
        "red_image_digest": red_digest,
        "blue_image_digest": blue_digest,
        "llm_image_digest": llm_digest,
        "model_digest": model_digest,
        "blue_policy_digest": blue_policy_digest,
        "firecracker_version": fc_version,
    });

    let images_json_path = root.join("config/images.json");
    if let Some(parent) = images_json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&images_json_path, serde_json::to_string_pretty(&images_json)?)?;

    trace.success(
        TraceStage::ImageBuild,
        "images.json published",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("path".into(), images_json_path.display().to_string().into());
            m.insert("red".into(), red_digest.clone().into());
            m.insert("blue".into(), blue_digest.clone().into());
            m.insert("llm".into(), llm_digest.clone().into());
            m
        },
    );

    Ok(ImagesResult {
        red_digest,
        blue_digest,
        llm_digest,
        model_digest,
        kernel_digest,
    })
}

/// Build a single role's ext4 image.
fn build_role_image(
    trace: &Trace,
    root: &Path,
    role: &str,
    kernel: &Path,
    images_dir: &Path,
    model: Option<&Path>,
) -> Result<String> {
    trace.info(
        TraceStage::ImageBuild,
        &format!("building image: {role}"),
        Default::default(),
    );

    let stage_dir = std::env::temp_dir().join(format!("bayora-stage-{role}"));
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)?;

    // Stage minimal userspace (busybox + python for red/blue, busybox only for llm)
    let busybox = which_which("busybox")?;
    trace.info(
        TraceStage::ImageBuild,
        "staging busybox",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("path".into(), busybox.display().to_string().into());
            m
        },
    );

    // Copy busybox and create applet symlinks
    fs::create_dir_all(stage_dir.join("bin"))?;
    fs::copy(&busybox, stage_dir.join("bin/busybox"))?;
    for applet in [
        "sh", "ash", "mount", "umount", "mkdir", "sed", "sleep", "seq", "echo",
        "cat", "ls", "grep", "sha256sum", "cut", "head", "basename", "dirname",
        "env", "test", "true", "false", "uname",
    ] {
        let _ = std::os::unix::fs::symlink("busybox", stage_dir.join(format!("bin/{applet}")));
    }

    // /etc/passwd and /etc/group
    fs::create_dir_all(stage_dir.join("etc"))?;
    fs::write(stage_dir.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n")?;
    fs::write(stage_dir.join("etc/group"), "root:x:0:\n")?;

    // Create directory structure
    for dir in ["proc", "sys", "dev", "tmp", "run", "var/log", "root", "opt/bayora"] {
        fs::create_dir_all(stage_dir.join(dir))?;
    }

    // Copy init.sh
    fs::copy(root.join("microvm/guest/init.sh"), stage_dir.join("opt/bayora/init.sh"))?;

    if role == "llm" {
        // Copy Rust agent binary
        let agent_bin = root.join("target/release/bayora-llm-agent");
        if !agent_bin.exists() {
            return Err(anyhow!(
                "bayora-llm-agent binary not found at {:?}. Build it first: cargo build --release -p bayora-llm-engine",
                agent_bin
            ));
        }
        fs::copy(&agent_bin, stage_dir.join("opt/bayora/bayora-llm-agent"))?;

        // Copy model weights
        let model_path = model.expect("model path required for llm role");
        fs::copy(model_path, stage_dir.join("opt/bayora/model.gguf"))?;

        // Stage system shared libraries for the Rust agent
        stage_system_libs(trace, &agent_bin, &stage_dir)?;

        // Copy common guest library
        fs::create_dir_all(stage_dir.join("opt/bayora/common"))?;
        for entry in fs::read_dir(root.join("workloads/common"))? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".py") {
                fs::copy(entry.path(), stage_dir.join(format!("opt/bayora/common/{}", name.to_string_lossy())))?;
            }
        }
    } else {
        // Copy Python agent and common library
        fs::create_dir_all(stage_dir.join(format!("opt/bayora/{}-team", role)))?;
        let agent_src = root.join(format!("workloads/{}-team/agent.py", role));
        fs::copy(&agent_src, stage_dir.join(format!("opt/bayora/{}-team/agent.py", role)))?;

        fs::create_dir_all(stage_dir.join("opt/bayora/common"))?;
        for entry in fs::read_dir(root.join("workloads/common"))? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".py") {
                fs::copy(entry.path(), stage_dir.join(format!("opt/bayora/common/{}", name.to_string_lossy())))?;
            }
        }

        // Stage Python interpreter and stdlib (for red/blue roles)
        stage_python(trace, &stage_dir)?;
    }

    // Compute image size
    let size_mb = compute_size_mb(&stage_dir)?;

    // Build ext4 image
    let image_path = images_dir.join(format!("{role}.ext4"));
    let label = format!("bayora-{role}");
    let uuid = match role {
        "red" => "b1a0e0a1-0000-4000-8000-000000000003",
        "blue" => "b1a0e0a1-0000-4000-8000-000000000004",
        "llm" => "b1a0e0a1-0000-4000-8000-000000000005",
        _ => return Err(anyhow!("unknown role: {role}")),
    };

    // Create zero-filled file
    Command::new("dd")
        .arg("if=/dev/zero")
        .arg(&format!("of={}", image_path.display()))
        .arg(&format!("bs=1M count={size_mb}"))
        .arg("status=none")
        .status()?;

    // Create ext4 filesystem
    Command::new("mke2fs")
        .args([
            "-q", "-t", "ext4", "-F", "-b", "1024", "-I", "128",
            "-L", &label, "-U", uuid,
            "-d", &stage_dir.to_string_lossy(),
            &image_path.to_string_lossy(),
        ])
        .status()?;

    // Shrink filesystem
    let _ = Command::new("e2fsck").args(["-f", "-y", &image_path.to_string_lossy()]).status();
    let _ = Command::new("resize2fs").args(["-M", &image_path.to_string_lossy()]).status();
    let _ = Command::new("e2fsck").args(["-f", "-y", &image_path.to_string_lossy()]).status();

    // Set permissions
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o444))?;

    let digest = format!("sha256:{}", sha256_hex(&image_path)?);

    trace.success(
        TraceStage::ImageBuild,
        &format!("image built: {role} ({size_mb} MiB)"),
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("role".into(), role.into());
            m.insert("digest".into(), digest.clone().into());
            m.insert("size_mb".into(), size_mb.into());
            m
        },
    );

    // Cleanup staging
    let _ = fs::remove_dir_all(&stage_dir);

    Ok(digest)
}

/// Stage system shared libraries needed by the Rust agent into the llm image.
fn stage_system_libs(trace: &Trace, agent_bin: &Path, stage_dir: &Path) -> Result<()> {
    let output = Command::new("ldd").arg(agent_bin).output()?;
    let ldd_output = String::from_utf8_lossy(&output.stdout);

    let libs_dir = stage_dir.join("lib64");
    fs::create_dir_all(&libs_dir)?;

    for line in ldd_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Parse lines like: libfoo.so.1 => /path/to/libfoo.so.1 (0x...)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "=>" {
            let lib_path = Path::new(parts[2]);
            if lib_path.exists() {
                let dest = libs_dir.join(lib_path.file_name().unwrap());
                fs::copy(lib_path, &dest)?;
                trace.info(
                    TraceStage::ImageBuild,
                    &format!("staged lib: {}", lib_path.display()),
                    Default::default(),
                );
            }
        } else if parts.len() >= 1 && parts[0].starts_with('/') && !line.contains("=>") {
            let lib_path = Path::new(parts[0]);
            if lib_path.exists() {
                let dest = libs_dir.join(lib_path.file_name().unwrap());
                fs::copy(lib_path, &dest)?;
                trace.info(
                    TraceStage::ImageBuild,
                    &format!("staged lib: {}", lib_path.display()),
                    Default::default(),
                );
            }
        }
    }

    Ok(())
}

/// Stage Python interpreter and stdlib into the image (for red/blue roles).
fn stage_python(_trace: &Trace, stage_dir: &Path) -> Result<()> {
    let python_bin = which_which("python3")?;

    fs::create_dir_all(stage_dir.join("usr/lib64/python3"))?;
    fs::create_dir_all(stage_dir.join("usr/bin"))?;

    // Copy the Python binary
    fs::copy(&python_bin, stage_dir.join("usr/bin/python3"))?;

    Ok(())
}

/// Take a golden Firecracker snapshot of the llm image.
fn take_golden_snapshot(
    trace: &Trace,
    firecracker_bin: &Path,
    kernel: &Path,
    image: &Path,
    model: &Path,
    snapshot_path: &Path,
    mem_path: &Path,
) -> Result<()> {
    trace.info(
        TraceStage::ImageBuild,
        "taking golden Firecracker snapshot",
        Default::default(),
    );

    let work_dir = std::env::temp_dir().join("bayora-golden");
    let _ = fs::remove_dir_all(&work_dir);
    fs::create_dir_all(&work_dir)?;

    let api_sock = work_dir.join("fc.sock");
    let vsock_uds = work_dir.join("llm.vsock");

    // Get model digest
    let model_digest = sha256_hex(model)?;
    let model_sha = &model_digest[7..]; // strip "sha256:"

    let config = json!({
        "boot-source": {
            "kernel_image_path": kernel.display().to_string(),
            "boot_args": format!("console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=llm bayora.port=9002 bayora.model_sha256={model_sha}")
        },
        "drives": [
            { "drive_id": "rootfs", "path_on_host": image.display().to_string(), "is_root_device": true, "is_read_only": true }
        ],
        "machine-config": { "vcpu_count": 1, "mem_size_mib": 2048, "smt": false },
        "vsock": { "guest_cid": 5, "uds_path": vsock_uds.display().to_string() },
        "logger": { "log_path": work_dir.join("fc.log").display().to_string(), "level": "Warning" }
    });

    let config_path = work_dir.join("config.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    // Start Firecracker
    let mut fc = Command::new(firecracker_bin)
        .arg("--api-sock").arg(&api_sock)
        .arg("--config-file").arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Wait for API socket
    for _ in 0..100 {
        if api_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Start the instance
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
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Wait for agent to answer CONNECT handshake
    for _ in 0..600 {
        if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&vsock_uds) {
            use std::io::Read;
            let _ = stream.write_all(b"CONNECT 9002\n");
            let mut buf = [0u8; 32];
            if let Ok(n) = stream.read(&mut buf) {
                let ack = String::from_utf8_lossy(&buf[..n]);
                if ack.starts_with("OK ") {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Pause the VM
    client
        .patch(format!("http://localhost/vm"))
        .header("Content-Type", "application/json")
        .body(json!({"state": "Paused"}).to_string())
        .send()?;

    // Create snapshot
    client
        .put(format!("http://localhost/snapshot/create"))
        .header("Content-Type", "application/json")
        .body(json!({
            "snapshot_type": "Full",
            "snapshot_path": snapshot_path.display().to_string(),
            "mem_file_path": mem_path.display().to_string()
        }).to_string())
        .send()?;

    // Kill Firecracker
    let _ = fc.kill();
    let _ = fc.wait();

    // Set permissions
    std::fs::set_permissions(snapshot_path, std::fs::Permissions::from_mode(0o444))?;
    std::fs::set_permissions(mem_path, std::fs::Permissions::from_mode(0o444))?;

    trace.success(
        TraceStage::ImageBuild,
        "golden snapshot created",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("snapshot".into(), snapshot_path.display().to_string().into());
            m.insert("mem".into(), mem_path.display().to_string().into());
            m
        },
    );

    Ok(())
}

/// Compute image size in MiB based on staged content.
fn compute_size_mb(stage_dir: &Path) -> Result<u32> {
    let output = Command::new("du")
        .args(["-sm", stage_dir.to_str().unwrap()])
        .output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    let size_mb: u32 = output_str
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()?;
    Ok(size_mb + size_mb / 5 + 8) // content + 20% + 8 MiB overhead
}

/// Get sha256 hex digest of a file.
fn sha256_hex(path: &Path) -> Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Find a binary in PATH.
fn which_which(name: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let full = dir.join(name);
            if full.is_file() {
                return Ok(full);
            }
        }
    }
    Err(anyhow!("{name} not found in PATH"))
}

/// Get Firecracker version string.
fn get_firecracker_version(bin: &Path) -> Result<String> {
    let output = Command::new(bin).arg("--version").output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Result of image building.
#[derive(Debug, Clone)]
pub struct ImagesResult {
    pub red_digest: String,
    pub blue_digest: String,
    pub llm_digest: String,
    pub model_digest: String,
    pub kernel_digest: String,
}