#!/usr/bin/env python3
"""
BAYORA ENCLAVE — Live Hackathon Dashboard CLI

Shows the full lifecycle of every prompt in real-time:
  Red → Referee → Blue VM → LLM VM → Evidence → Merkle Seal → Verifier

Usage:
    python3 scripts/demo_dashboard.py

Requires the Referee to be running on http://127.0.0.1:8080
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

API = "http://127.0.0.1:8080"
EVIDENCE_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "evidence",
    "evidence_log.ndjson",
)

# ── ANSI colors ─────────────────────────────────────────────────────────────
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"

# ── Box drawing ─────────────────────────────────────────────────────────────
def box(title, lines, color=C_CYAN, width=78):
    print(f"{color}┌{'─' * (width - 2)}┐{C_RESET}")
    print(f"{color}│{C_RESET} {C_BOLD}{title}{C_RESET}{color}{' ' * (width - 4 - len(title))}│{C_RESET}")
    print(f"{color}├{'─' * (width - 2)}┤{C_RESET}")
    for line in lines:
        print(f"{color}│{C_RESET} {line:<{width - 4}} {color}│{C_RESET}")
    print(f"{color}└{'─' * (width - 2)}┘{C_RESET}")

def kv(key, value, color=C_WHITE, width=78):
    print(f"  {C_DIM}{key:<22}{C_RESET} {color}{value}{C_RESET}")

def status_icon(ok):
    return f"{C_GREEN}●{C_RESET}" if ok else f"{C_RED}○{C_RESET}"

# ── API helpers ─────────────────────────────────────────────────────────────
def api_get(path, timeout=3):
    try:
        req = urllib.request.Request(f"{API}{path}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None

def read_evidence():
    if not os.path.exists(EVIDENCE_LOG):
        return []
    records = []
    with open(EVIDENCE_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def get_firecracker_procs():
    """Return list of running firecracker processes with their sockets."""
    import subprocess
    try:
        out = subprocess.run(
            ["pgrep", "-a", "firecracker"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        procs = []
        for line in out.strip().split("\n"):
            if not line:
                continue
            parts = line.split(None, 1)
            pid = parts[0] if parts else "?"
            cmd = parts[1] if len(parts) > 1 else ""
            # Extract socket name
            sock = "?"
            for token in cmd.split():
                if token.startswith("--api-sock="):
                    sock = token.split("=", 1)[1]
                elif token == "--api-sock":
                    pass  # next token
            procs.append((pid, sock, cmd))
        return procs
    except Exception:
        return []

def path_color(path):
    if path == "llm":
        return C_GREEN, "LLM (allowed)"
    elif path == "regex_block":
        return C_RED, "BLOCKED (regex)"
    elif path == "semantic_block":
        return C_RED, "BLOCKED (semantic)"
    return C_YELLOW, path

# ── Render ──────────────────────────────────────────────────────────────────
def clear():
    os.system("clear" if os.name == "posix" else "cls")

def render():
    posture = api_get("/v1/posture")
    evidence = read_evidence()
    eval_records = [e for e in evidence if e.get("record_type") == "evaluation"]
    seal_records = [e for e in evidence if e.get("record_type") == "batch_seal"]
    fc_procs = get_firecracker_procs()

    clear()
    print(f"{C_BOLD}{C_CYAN}╔══════════════════════════════════════════════════════════════════════════╗{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}║           BAYORA ENCLAVE — LIVE PIPELINE DASHBOARD (v3.0)             ║{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}╚══════════════════════════════════════════════════════════════════════════╝{C_RESET}")
    print(f"  {C_DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C_RESET}")
    print()

    # ── Pipeline topology ──────────────────────────────────────────────
    box("PIPELINE TOPOLOGY", [
        f"  {C_BLUE}[RED VM]{C_RESET}    CID 3   {C_DIM}→ submits prompts + capabilities{C_RESET}",
        f"  {C_BLUE}[Referee]{C_RESET}   host    {C_DIM}→ mediates, creates evaluations{C_RESET}",
        f"  {C_BLUE}[BLUE VM]{C_RESET}   CID 4   {C_DIM}→ regex + semantic classification{C_RESET}",
        f"  {C_BLUE}[LLM VM]{C_RESET}    CID 5   {C_DIM}→ GGUF inference, snapshot reset{C_RESET}",
        f"  {C_BLUE}[Evidence]{C_RESET}  host    {C_DIM}→ signed NDJSON log + Merkle tree{C_RESET}",
        f"  {C_BLUE}[Verifier]{C_RESET}  host    {C_DIM}→ independent validation → VALID{C_RESET}",
    ], color=C_BLUE)
    print()

    # ── MicroVM status ─────────────────────────────────────────────────
    print(f"  {C_BOLD}MicroVM Status:{C_RESET}")
    fc_map = {}
    for pid, sock, cmd in fc_procs:
        role = "unknown"
        if "fc-red" in sock: role = "red (CID 3)"
        elif "fc-blue" in sock: role = "blue (CID 4)"
        elif "fc-llm" in sock: role = "llm (CID 5)"
        fc_map[role] = (pid, sock)

    for role_name, role_cid in [("red", "3"), ("blue", "4"), ("llm", "5")]:
        key = f"{role_name} (CID {role_cid})"
        if key in fc_map:
            pid, sock = fc_map[key]
            print(f"    {status_icon(True)} {key:<20} PID {pid:<8} socket {sock}")
        else:
            print(f"    {status_icon(False)} {key:<20} not running")
    print()

    # ── Referee posture ────────────────────────────────────────────────
    if posture:
        p = posture
        box("REFEREE POSTURE", [
            kv("Evaluations completed", str(p.get("evaluations_completed", 0))),
            kv("Firecracker resets", str(p.get("resets", 0))),
            kv("Capability replays", str(p.get("capability_replays", 0)), C_RED if p.get("capability_replays", 0) > 0 else C_WHITE),
            kv("Cross-eval mismatches", str(p.get("cross_eval_mismatches", 0)), C_RED if p.get("cross_eval_mismatches", 0) > 0 else C_WHITE),
            kv("Frame rejections", str(p.get("frame_rejections", 0)), C_RED if p.get("frame_rejections", 0) > 0 else C_WHITE),
            kv("Deadline aborts", str(p.get("deadline_aborts", 0)), C_RED if p.get("deadline_aborts", 0) > 0 else C_WHITE),
            kv("Batch seals", str(len(seal_records))),
            kv("Last verification", p.get("last_verification", "pending"), C_GREEN if p.get("last_verification", "").startswith("VALID") else C_YELLOW),
        ], color=C_MAGENTA)
        print()

        # ── Timing bands ───────────────────────────────────────────────
        modes = p.get("modes", {})
        if modes:
            print(f"  {C_BOLD}Timing Bands (EVAL_500 — constant release):{C_RESET}")
            for mode, stats in modes.items():
                acc = stats.get("inference_accuracy", 0)
                acc_color = C_GREEN if acc < 0.5 else C_RED
                print(f"    {mode:<14} samples={stats.get('samples', 0):<3} "
                      f"mean={stats.get('mean_us', 0):>7.0f}µs "
                      f"stddev={stats.get('stddev_us', 0):>7.0f}µs "
                      f"inf_acc={acc_color}{acc:.1%}{C_RESET}")
            print()

    # ── Evaluation lifecycle ───────────────────────────────────────────
    print(f"  {C_BOLD}Evaluation Lifecycle (last 6):{C_RESET}")
    if eval_records:
        for rec in eval_records[-6:]:
            m = rec.get("manifest", {})
            events = rec.get("events", [])
            routed = [e for e in events if e.get("event_type") == "prompt_routed"]
            released = [e for e in events if e.get("event_type") == "response_released"]
            reset_ev = [e for e in events if e.get("event_type") == "state_reset"]

            eid = m.get("evaluation_id", "unknown")[:24]
            path = routed[0]["path"] if routed else "pending"
            pcolor, plabel = path_color(path)
            held = released[0]["held_us"] if released else "—"
            reset_us = reset_ev[0]["duration_us"] if reset_ev else "—"

            # Truncate prompt for display
            prompt = routed[0].get("prompt", "") if routed else ""
            prompt_disp = (prompt[:40] + "…") if len(prompt) > 40 else prompt

            line = (f"    {status_icon(True)} {eid}  "
                    f"{pcolor}{plabel:<20}{C_RESET}  "
                    f"{C_DIM}held={held:<7}µs reset={reset_us}µs{C_RESET}  "
                    f'"{prompt_disp}"')
            print(line)
    else:
        print(f"    {C_YELLOW}Waiting for evaluations…{C_RESET}")
    print()

    # ── Merkle chain ───────────────────────────────────────────────────
    if seal_records:
        box("MERKLE BATCH SEAL (latest)", [
            kv("Batch ID", seal_records[-1].get("batch_id", "?")),
            kv("Seq range", f"{seal_records[-1].get('seq_start', '?')}..{seal_records[-1].get('seq_end', '?')}"),
            kv("Merkle root", seal_records[-1].get("merkle_root", "?")[:32] + "…"),
            kv("Signature", seal_records[-1].get("signature", "?")[:32] + "…"),
            kv("Sealed at", seal_records[-1].get("sealed_at", "?")),
        ], color=C_GREEN)
        print()

    # ── Evidence log tail ──────────────────────────────────────────────
    print(f"  {C_BOLD}Evidence Log ({os.path.basename(EVIDENCE_LOG)}):{C_RESET}")
    total = len(evidence)
    evals = len(eval_records)
    seals = len(seal_records)
    print(f"    {C_DIM}Total records: {total}  |  Evaluations: {evals}  |  Seals: {seals}{C_RESET}")
    print()

    print(f"  {C_DIM}Refreshing every 2s  |  Ctrl-C to stop{C_RESET}")

def main():
    print(f"{C_CYAN}Starting Bayora Enclave Dashboard…{C_RESET}")
    print(f"{C_DIM}API: {API}{C_RESET}")
    print(f"{C_DIM}Evidence: {EVIDENCE_LOG}{C_RESET}")
    time.sleep(1)
    try:
        while True:
            render()
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{C_GREEN}Dashboard stopped.{C_RESET}")

if __name__ == "__main__":
    main()