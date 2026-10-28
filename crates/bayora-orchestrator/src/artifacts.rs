//! Artifact download and verification.
//! Replaces microvm/fetch_artifacts.sh — downloads firecracker, vmlinux kernel,
//! and model.gguf with sha256 verification.

use crate::trace::{Trace, TraceStage};
use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Download an artifact with URL and expected sha256.
pub fn download_artifact(
    trace: &Trace,
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<()> {
    trace.info(
        TraceStage::ArtifactDownload,
        &format!("downloading {}", dest.display()),
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("url".into(), url.into());
            m.insert("dest".into(), dest.display().to_string().into());
            m
        },
    );

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let client = Client::builder().timeout(std::time::Duration::from_secs(300)).build()?;
    let mut resp = client.get(url).send()?;

    if !resp.status().is_success() {
        return Err(anyhow!("download failed: HTTP {} for {}", resp.status(), url));
    }

    let mut file = File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;

    loop {
        let mut buf = [0u8; 8192];
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    file.flush()?;
    drop(file);

    let computed = format!("{:x}", hasher.finalize());

    if let Some(expected) = expected_sha256 {
        if computed != expected {
            return Err(anyhow!(
                "sha256 mismatch for {}: expected {}, got {}",
                dest.display(),
                expected,
                computed
            ));
        }
    }

    trace.success(
        TraceStage::ArtifactDownload,
        &format!("downloaded {} ({} bytes, sha256={})", dest.display(), total, &computed[..16]),
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("url".into(), url.into());
            m.insert("dest".into(), dest.display().to_string().into());
            m.insert("bytes".into(), total.into());
            m.insert("sha256".into(), computed.into());
            m
        },
    );

    Ok(())
}

/// Verify that firecracker binary is executable and returns a version.
pub fn verify_firecracker(trace: &Trace, bin: &Path) -> Result<String> {
    let output = Command::new(bin).arg("--version").output()?;
    if !output.status.success() {
        return Err(anyhow!("firecracker --version failed"));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    trace.success(
        TraceStage::ArtifactDownload,
        &format!("firecracker verified: {version}"),
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("path".into(), bin.display().to_string().into());
            m.insert("version".into(), version.clone().into());
            m
        },
    );
    Ok(version)
}

/// Verify kernel is a valid ELF.
pub fn verify_kernel(trace: &Trace, path: &Path) -> Result<()> {
    let data = std::fs::read(path)?;
    if &data[..4] != b"\x7fELF" {
        return Err(anyhow!("kernel is not a valid ELF: {}", path.display()));
    }
    trace.success(
        TraceStage::ArtifactDownload,
        "kernel verified (ELF)",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("path".into(), path.display().to_string().into());
            m.insert("bytes".into(), data.len().into());
            m
        },
    );
    Ok(())
}

/// Verify model file starts with GGUF magic.
pub fn verify_model(trace: &Trace, path: &Path) -> Result<()> {
    let data = std::fs::read(path)?;
    if &data[..4] != b"GGUF" {
        return Err(anyhow!("model is not a valid GGUF: {}", path.display()));
    }
    trace.success(
        TraceStage::ArtifactDownload,
        "model verified (GGUF)",
        {
            let mut m = std::collections::BTreeMap::new();
            m.insert("path".into(), path.display().to_string().into());
            m.insert("bytes".into(), data.len().into());
            m
        },
    );
    Ok(())
}

/// Ensure all artifacts are present and valid. Downloads missing ones.
pub fn ensure_artifacts(
    trace: &Trace,
    root: &std::path::Path,
) -> Result<ArtifactPaths> {
    let artifacts_dir = root.join("microvm/artifacts");
    std::fs::create_dir_all(&artifacts_dir)?;

    let firecracker_bin = artifacts_dir.join("firecracker");
    let kernel_path = artifacts_dir.join("vmlinux");
    let model_path = artifacts_dir.join("model.gguf");

    // Firecracker
    if !firecracker_bin.exists() {
        let version = std::env::var("FIRECRACKER_VERSION").unwrap_or_else(|_| "v1.17.0".to_string());
        let arch = std::env::consts::ARCH;
        let url = format!(
            "https://github.com/firecracker-microvm/firecracker/releases/download/{version}/firecracker-{version}-{arch}.tgz",
        );
        // Download tarball, extract, verify
        let tarball = artifacts_dir.join(format!("firecracker-{version}-{arch}.tgz"));
        let expected_sha256 = std::env::var("BAYORA_FIRECRACKER_SHA256").ok();
        download_artifact(trace, &url, &tarball, expected_sha256.as_deref())?;

        // Extract
        let output = Command::new("tar")
            .arg("-xzf")
            .arg(&tarball)
            .arg("-C")
            .arg(&artifacts_dir)
            .output()?;
        if !output.status.success() {
            return Err(anyhow!("failed to extract firecracker tarball"));
        }

        // Find the binary in extracted dir
        for entry in std::fs::read_dir(&artifacts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().unwrap_or_default().to_string_lossy().contains("firecracker-") {
                std::fs::rename(&path, &firecracker_bin)?;
                break;
            }
        }
        std::fs::set_permissions(&firecracker_bin, std::fs::Permissions::from_mode(0o755))?;
    }
    verify_firecracker(trace, &firecracker_bin)?;

    // Kernel
    if !kernel_path.exists() {
        // Discover newest kernel from Firecracker CI S3
        let key = discover_kernel(std::env::consts::ARCH)?;
        let url = format!("https://s3.amazonaws.com/spec.ccfc.min/{key}");
        let expected_sha256 = std::env::var("BAYORA_KERNEL_SHA256").ok();
        download_artifact(trace, &url, &kernel_path, expected_sha256.as_deref())?;
    }
    verify_kernel(trace, &kernel_path)?;

    // Model
    if !model_path.exists() {
        let model_url = std::env::var("BAYORA_MODEL_URL")
            .unwrap_or_else(|_| "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf".to_string());
        let expected_sha256 = std::env::var("BAYORA_MODEL_SHA256").ok();
        download_artifact(trace, &model_url, &model_path, expected_sha256.as_deref())?;
    }
    verify_model(trace, &model_path)?;

    Ok(ArtifactPaths {
        firecracker_bin,
        kernel_path,
        model_path,
    })
}

/// Discover the newest vmlinux kernel key from Firecracker CI S3 bucket.
fn discover_kernel(arch: &str) -> Result<String> {
    let client = Client::new();
    let listing: String = client
        .get("https://s3.amazonaws.com/spec.ccfc.min?list-type=2&prefix=firecracker-ci/&delimiter=/")
        .send()?
        .text()?;

    // Find prefixes (dates)
    let prefixes: Vec<&str> = listing
        .lines()
        .filter_map(|l| {
            if let Some(start) = l.find("<Prefix>firecracker-ci/") {
                let end = l[start..].find("</Prefix>")?;
                Some(&l[start + 10..start + end])
            } else {
                None
            }
        })
        .collect();

    for prefix in prefixes.iter().rev() {
        let page: String = client
            .get(format!(
                "https://s3.amazonaws.com/spec.ccfc.min?list-type=2&prefix={prefix}/{arch}/vmlinux-"
            ))
            .send()?
            .text()?;

        // Find vmlinux keys
        let versions: Vec<&str> = page
            .lines()
            .filter_map(|l| {
                if let Some(start) = l.find(format!("{arch}/vmlinux-").as_str()) {
                    let after = &l[start + format!("{arch}/").len()..];
                    let end = after.find("</Key>")?;
                    Some(&after[..end])
                } else {
                    None
                }
            })
            .collect();

        if let Some(newest) = versions.iter().max() {
            return Ok(format!("{prefix}/{arch}/{newest}"));
        }
    }

    Err(anyhow!("no vmlinux kernel found for architecture {arch}"))
}

/// Paths to all verified artifacts.
#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    pub firecracker_bin: std::path::PathBuf,
    pub kernel_path: std::path::PathBuf,
    pub model_path: std::path::PathBuf,
}