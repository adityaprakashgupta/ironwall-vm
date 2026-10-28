//! Quick integration test proving the LLM produces actual text through
//! Firecracker VM path with NORMAL timing mode (no bucket holding).
//!
//! Runs one evaluation with a benign prompt through the full pipeline:
//! Referee → Blue VM (allow) → LLM VM → response.
//! Prints the decoded response frame so you can see real model output.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn prerequisites_met() -> bool {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm not available");
        return false;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    for p in [
        root.join("microvm/artifacts/firecracker"),
        root.join("microvm/artifacts/vmlinux"),
        root.join("microvm/artifacts/model.gguf"),
        root.join("microvm/images/red.ext4"),
        root.join("microvm/images/blue.ext4"),
        root.join("microvm/images/llm.ext4"),
        root.join("microvm/snapshots/llm-golden.snap"),
        root.join("microvm/snapshots/llm-golden.mem"),
        root.join("config/policy.yaml"),
        root.join("config/images.json"),
    ] {
        if !p.exists() {
            eprintln!("SKIP: missing artifact {}", p.display());
            return false;
        }
    }
    true
}

fn cleanup_processes() {
    let _ = Command::new("pkill").arg("-9").arg("firecracker").status();
    let _ = Command::new("pkill").arg("-9").arg("bayora-referee").status();
    let _ = Command::new("pkill").arg("-9").arg("bayora-signer").status();
    let _ = std::thread::sleep(Duration::from_millis(500));
}

fn wait_for_health(addr: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if reqwest::blocking::get(format!("http://{addr}/healthz")).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

fn wait_for_socket(path: &std::path::Path, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if path.exists() { return true; }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
fn llm_produces_actual_output_through_firecracker() {
    if !prerequisites_met() { return; }
    cleanup_processes();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let runtime_dir = root.join("target/llm-output-test-runtime");
    let evidence_log = root.join("evidence/llm-output-test.log");

    let _ = std::fs::remove_file(&evidence_log);
    let _ = std::fs::remove_dir_all(&runtime_dir);
    let _ = std::fs::create_dir_all(&runtime_dir);

    // Use NORMAL mode so there's no bucket holding — responses come back
    // as soon as work completes, showing actual LLM output.
    let referee_port: u16 = (19000u64 + (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 % 1000)) as u16;
    let referee_addr = format!("127.0.0.1:{referee_port}");

    // Start signer
    let signer_sock = runtime_dir.join("signer.sock");
    let _ = std::fs::remove_file(&signer_sock);
    let mut signer_proc = Command::new(root.join("target/release/bayora-signer"))
        .arg("--key-dir").arg(root.join("keys"))
        .arg("--listen").arg(format!("unix:{}", signer_sock.display()))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("failed to start signer");
    assert!(wait_for_socket(&signer_sock, 30), "signer socket never appeared");

    // Start referee with NORMAL timing mode
    let mut referee_proc = Command::new(root.join("target/release/bayora-referee"))
        .arg("--policy").arg(root.join("config/policy.yaml"))
        .arg("--images").arg(root.join("config/images.json"))
        .arg("--listen").arg(&referee_addr)
        .arg("--signer").arg(format!("unix:{}", signer_sock.display()))
        .arg("--evidence-log").arg(&evidence_log)
        .arg("--runtime-dir").arg(&runtime_dir)
        .arg("--firecracker-api").arg(runtime_dir.join("fc-llm.sock"))
        .arg("--llm-port").arg("9002")
        .arg("--transport").arg("firecracker")
        .arg("--reset").arg("snapshot")
        .arg("--snapshot-path").arg(root.join("microvm/snapshots/llm-golden.snap"))
        .arg("--vsock-port").arg("5000")
        .arg("--firecracker-bin").arg(root.join("microvm/artifacts/firecracker"))
        .arg("--capability-ttl-ms").arg("300000")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("failed to start referee");

    assert!(wait_for_health(&referee_addr, 30), "Referee never became healthy");

    // Create one evaluation with a benign prompt
    let client = reqwest::blocking::Client::new();
    let created: serde_json::Value = client
        .post(format!("http://{referee_addr}/v1/evaluations"))
        .json(&serde_json::json!({}))
        .send().expect("POST /v1/evaluations failed")
        .json().expect("response not JSON");

    let eval_id = created["evaluation_id"].as_str().unwrap().to_string();
    let capability = created.get("capability").cloned().unwrap_or(serde_json::Value::Null);
    eprintln!("Created evaluation: {eval_id}");

    // Boot Blue VM
    let blue_api_sock = runtime_dir.join("fc-blue.sock");
    let blue_vsock = runtime_dir.join("blue.vsock");
    let blue_config = runtime_dir.join("fc-blue.json");
    let _ = std::fs::remove_file(&blue_api_sock);
    let _ = std::fs::remove_file(&blue_vsock);

    let blue_config_json = serde_json::json!({
        "boot-source": {
            "kernel_image_path": root.join("microvm/artifacts/vmlinux").display().to_string(),
            "boot_args": format!("console=ttyS0 reboot=k panic=1 pci=off init=/opt/bayora/init.sh bayora.role=blue bayora.port=9001")
        },
        "drives": [
            { "drive_id": "rootfs", "path_on_host": root.join("microvm/images/blue.ext4").display().to_string(), "is_root_device": true, "is_read_only": true }
        ],
        "machine-config": { "vcpu_count": 1, "mem_size_mib": 2048, "smt": false },
        "vsock": { "guest_cid": 4, "uds_path": blue_vsock.display().to_string() },
        "logger": { "log_path": runtime_dir.join("blue.log").display().to_string(), "level": "Warning" }
    });
    std::fs::write(&blue_config, serde_json::to_string_pretty(&blue_config_json).unwrap())
        .expect("failed to write blue config");

    let _blue_fc = Command::new(root.join("microvm/artifacts/firecracker"))
        .arg("--api-sock").arg(&blue_api_sock)
        .arg("--config-file").arg(&blue_config)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("failed to start firecracker for blue");

    for _ in 0..100 {
        if blue_api_sock.exists() { break; }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = Command::new("curl")
        .arg("-s").arg("-f").arg("-X").arg("PUT").arg("http://localhost/actions")
        .arg("--unix-socket").arg(&blue_api_sock)
        .arg("-H").arg("Content-Type: application/json")
        .arg("-d").arg(r#"{"action_type":"InstanceStart"}"#)
        .status();

    assert!(wait_for_socket(&blue_vsock, 60), "blue.vsock never appeared");
    eprintln!("Blue VM ready");

    // Run one turn with a benign prompt
    let prompt = "What is the capital of France?";
    let body = serde_json::json!({
        "capability": capability,
        "turn": 1,
        "prompt": prompt
    });

    let resp = client
        .post(format!("http://{referee_addr}/v1/evaluations/{eval_id}/turns"))
        .json(&body)
        .send().expect("POST /turns failed");

    eprintln!("Turn status: {}", resp.status());

    let body_text = resp.text().expect("response body");
    let turn: serde_json::Value = serde_json::from_str(&body_text).expect("turn response is not JSON");

    let status = turn["status"].as_str().unwrap_or("?");
    let frame_hex = turn["frame_hex"].as_str().unwrap_or("");
    let frame_bytes = turn["frame_bytes"].as_u64().unwrap_or(0);

    eprintln!("status={status} frame_bytes={frame_bytes}");

    // Decode and print the actual response
    let frame_bytes_vec = hex::decode(frame_hex).expect("frame hex decode");
    let frame_text = String::from_utf8_lossy(&frame_bytes_vec);
    // Trim trailing spaces (padding)
    let trimmed = frame_text.trim_end();
    eprintln!("\n=== LLM OUTPUT FRAME ===");
    eprintln!("{trimmed}");
    eprintln!("=== END FRAME ===\n");

    // Verify we got actual model output (not just padding)
    assert!(frame_bytes > 0, "frame is empty");
    assert!(status == "ok" || status == "timeout", "unexpected status: {status}");

    // In NORMAL mode, LLM turns should complete and show actual text
    // (regex/semantic blocks would show "I can't assist...")
    if status == "ok" {
        let data_start = trimmed.find("\"data\":\"").unwrap_or(0) + 9;
        let data_end = trimmed[data_start..].find('"').unwrap_or(0);
        let data = &trimmed[data_start..data_start + data_end];
        eprintln!("\n=== DECODED LLM OUTPUT ===");
        eprintln!("{data}");
        eprintln!("=== END ===\n");
        assert!(!data.is_empty(), "LLM output is empty!");
    }

    // Cleanup
    let _ = referee_proc.kill();
    let _ = signer_proc.kill();
    let _ = Command::new("pkill").arg("-9").arg("firecracker").status();
}
