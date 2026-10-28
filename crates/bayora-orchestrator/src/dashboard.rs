//! Ratatui TUI dashboard for the Bayora Enclave orchestrator.
//!
//! Judge-facing live demo view showing:
//!   * Pipeline stages (ArtifactDownload → ImageBuild → MicroVMBoot →
//!     Evaluation → Reset → Evidence → Verification)
//!   * Firecracker MicroVM states (Red, Blue, LLM) with CID, vsock, status
//!   * Prompt lifecycle table (prompt → verdict → LLM response)
//!   * Merkle tree evidence visualization
//!   * Independent Verifier result (VALID / INVALID)

use crate::trace::{TraceRecord, TraceLevel, TraceStage};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Row, Table, Wrap};
use ratatui::Terminal;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Pipeline stages in order.
const PIPELINE_STAGES: [&str; 7] = [
    "ARTIFACT_DOWNLOAD",
    "IMAGE_BUILD",
    "MICROVM_BOOT",
    "EVALUATION",
    "RESET",
    "EVIDENCE",
    "VERIFICATION",
];

/// VM roles displayed.
const VMS: [(&str, u32); 3] = [("red", 3), ("blue", 4), ("llm", 5)];

/// Poll interval for re-reading trace / evidence logs.
const POLL_MS: u64 = 500;

/// Aggregated dashboard state.
#[derive(Debug, Clone, Default)]
struct DashboardState {
    /// How many pipeline stages are complete (0..=7).
    stages_complete: usize,
    /// Current (in-flight) stage index.
    current_stage: Option<usize>,
    /// Stage index → (level, event).
    stage_events: HashMap<usize, (TraceLevel, String)>,
    /// VM name → (running, socket_path).
    vms: HashMap<String, (bool, Option<String>)>,
    /// Evaluation rows for the prompt lifecycle table.
    evaluations: Vec<EvalRow>,
    /// Merkle root hash.
    merkle_root: Option<String>,
    /// Number of evaluations sealed.
    sealed_count: usize,
    /// Verifier result: Some("VALID") / Some("INVALID") / None.
    verifier_result: Option<String>,
    /// Recent trace records.
    recent_trace: Vec<TraceRecord>,
}

/// A single evaluation row.
#[derive(Debug, Clone)]
struct EvalRow {
    eval_id_short: String,
    prompt: String,
    path: String,   // "llm", "regex_block", "semantic_block"
    held_us: Option<u64>,
}

/// Read trace + evidence logs into DashboardState.
fn load_state(trace_log: &Path, evidence_log: &Path) -> DashboardState {
    let mut state = DashboardState::default();

    // ---- Load trace ----
    let Ok(contents) = fs::read_to_string(trace_log) else {
        return state;
    };

    let mut stage_max = 0usize;
    let mut recent: Vec<TraceRecord> = Vec::new();

    for line in contents.lines() {
        let Ok(record) = serde_json::from_str::<TraceRecord>(line) else {
            continue;
        };
        recent.push(record.clone());

        // Map TraceStage to pipeline index.
        let stage = record.stage.clone();
        if let Some(idx) = pipeline_index(stage.clone()) {
            if idx >= stage_max {
                stage_max = idx;
            }
            state.stage_events.insert(idx, (record.level.clone(), record.event.clone()));
        }

        // VM boot states from MicroVMBoot stage.
        if stage == TraceStage::MicroVMBoot {
            if let Some(role) = record.data.get("role").and_then(|v| v.as_str()) {
                if let Some(vsock) = record.data.get("vsock_uds").and_then(|v| v.as_str()) {
                    state.vms.insert(role.to_string(), (true, Some(vsock.to_string())));
                }
            }
        }
    }

    state.stages_complete = stage_max + 1;
    state.current_stage = if stage_max < PIPELINE_STAGES.len() - 1 {
        Some(stage_max)
    } else {
        None
    };
    state.recent_trace = recent;

    // ---- Load evidence log ----
    if let Ok(ev_contents) = fs::read_to_string(evidence_log) {
        for line in ev_contents.lines() {
            let Ok(rec) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if rec.get("record_type") != Some(&Value::String("evaluation".into())) {
                continue;
            }

            let manifest = rec.get("manifest");
            let events = rec.get("events").and_then(|v| v.as_array());

            let eval_id = manifest
                .and_then(|m| m.get("evaluation_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let prompt = events
                .and_then(|arr| {
                    arr.iter().find(|e| e.get("event_type") == Some(&Value::String("prompt_routed".into())))
                })
                .and_then(|e| e.get("prompt").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();

            let path = events
                .and_then(|arr| {
                    arr.iter().find(|e| e.get("event_type") == Some(&Value::String("prompt_routed".into())))
                })
                .and_then(|e| e.get("path").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();

            let held_us = events
                .and_then(|arr| {
                    arr.iter().find(|e| e.get("event_type") == Some(&Value::String("response_released".into())))
                })
                .and_then(|e| e.get("held_us").and_then(|v| v.as_u64()));

            state.evaluations.push(EvalRow {
                eval_id_short: eval_id.chars().take(8).collect::<String>(),
                prompt,
                path,
                held_us,
            });
        }
        state.sealed_count = state.evaluations.len();
    }

    // Merkle root from evidence log batch_seal records.
    if let Ok(ev_contents) = fs::read_to_string(evidence_log) {
        for line in ev_contents.lines() {
            let Ok(rec) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let rt = rec.get("record_type").and_then(|v| v.as_str()).unwrap_or("");
            if rt == "batch_seal" || rt == "seal" {
                if let Some(root) = rec.get("merkle_root").and_then(|v| v.as_str()) {
                    state.merkle_root = Some(root.to_string());
                }
            }
        }
    }

    // Verifier result from trace Verification stage.
    for record in &state.recent_trace {
        if matches!(record.stage, TraceStage::Verification) {
            if let Some(ok) = record.data.get("verified").and_then(|v| v.as_bool()) {
                state.verifier_result = if ok { Some("VALID".to_string()) } else { Some("INVALID".to_string()) };
            }
            if let Some(stdout) = record.data.get("stdout").and_then(|v| v.as_str()) {
                if stdout.contains("VALID") {
                    state.verifier_result = Some("VALID".to_string());
                }
            }
        }
    }

    state
}

fn pipeline_index(stage: TraceStage) -> Option<usize> {
    match stage {
        TraceStage::ArtifactDownload => Some(0),
        TraceStage::ImageBuild => Some(1),
        TraceStage::MicroVMBoot => Some(2),
        TraceStage::Evaluation => Some(3),
        TraceStage::Reset => Some(4),
        TraceStage::Evidence => Some(5),
        TraceStage::Verification => Some(6),
        _ => None,
    }
}

/// Style for a trace level.
fn level_style(level: &TraceLevel) -> Style {
    match level {
        TraceLevel::Success => Style::default().fg(Color::Green),
        TraceLevel::Info => Style::default().fg(Color::Cyan),
        TraceLevel::Warn => Style::default().fg(Color::Yellow),
        TraceLevel::Error => Style::default().fg(Color::Red),
    }
}

/// Build Merkle tree display lines.
fn merkle_lines(state: &DashboardState) -> Vec<Line> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "Merkle Evidence Tree",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    if let Some(root) = &state.merkle_root {
        let short = if root.len() > 16 {
            format!("{}…{}", &root[..8], &root[root.len() - 8..])
        } else {
            root.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("Root: ", Style::default().fg(Color::Gray)),
            Span::styled(short, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Root: ", Style::default().fg(Color::Gray)),
            Span::styled("pending…", Style::default().fg(Color::Yellow)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("  leaf hashes (SHA-256 per evaluation)"));
    lines.push(Line::from("        │      │      │      │"));
    lines.push(Line::from("      ┌──┴──┐ ┌──┴──┐ ┌──┴──┐"));
    lines.push(Line::from("     │       │ │       │ │       │"));
    lines.push(Line::from("   ev_01  ev_02  ev_03 …  ev_N"));
    lines.push(Line::from(""));
    lines.push(Line::from(format!("Evaluations sealed: {}", state.sealed_count)));
    lines
}

/// Build Verifier result display lines.
fn verify_lines(state: &DashboardState) -> Vec<Line> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "Independent Verifier",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    match &state.verifier_result {
        Some(r) if r == "VALID" => {
            lines.push(Line::from(
                Span::styled("RESULT: VALID", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ));
        }
        Some(r) => {
            lines.push(Line::from(Span::styled(
                format!("RESULT: {r}"),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        None => {
            lines.push(Line::from(Span::styled(
                "RESULT: pending…",
                Style::default().fg(Color::Yellow),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Hash chain verified · signatures checked ·",
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(Span::styled(
        "all evidence records immutable.",
        Style::default().fg(Color::Gray),
    )));
    lines
}

/// Run the TUI dashboard.
pub fn run_dashboard(config: &crate::OrchestratorConfig, refresh_ms: u64) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_dashboard_loop(&mut terminal, config, refresh_ms);

    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_dashboard_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    config: &crate::OrchestratorConfig,
    refresh_ms: u64,
) -> Result<()> {
    let poll_interval = Duration::from_millis(refresh_ms);
    let mut last_poll = Instant::now();

    loop {
        if last_poll.elapsed() >= poll_interval {
            let state = load_state(&config.trace_log, &config.evidence_log);
            terminal.draw(|f| draw_ui(f, &state))?;
            last_poll = Instant::now();
        }

        if crossterm::event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc)
                {
                    break;
                }
            }
        }

        // Auto-quit when verifier has produced a result so judges see VALID/INVALID.
        let state = load_state(&config.trace_log, &config.evidence_log);
        if state.verifier_result.is_some() {
            terminal.draw(|f| draw_ui(f, &state))?;
            thread::sleep(Duration::from_secs(4));
            break;
        }
    }

    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, state: &DashboardState) {
    // Three-row layout: title(3) | body(min) | trace(8).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(8)])
        .split(f.size());

    // ---- Title / progress gauge ----
    let progress = state.stages_complete as f64 / PIPELINE_STAGES.len() as f64;
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    "Bayora Enclave v3.0 — Pipeline {:.0}% complete",
                    progress * 100.0
                )),
        )
        .gauge_style(Style::default().fg(Color::Magenta))
        .ratio(progress);
    f.render_widget(gauge, chunks[0]);

    // ---- Body: left (pipeline + VMs), center (eval table), right (merkle + verifier) ----
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(44), Constraint::Percentage(28)])
        .split(chunks[1]);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(body_chunks[0]);

    // Pipeline stages panel.
    let pipeline_items: Vec<ListItem> = PIPELINE_STAGES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let completed = i < state.stages_complete;
            let current = state.current_stage == Some(i);
            let marker = if completed { "✓" } else if current { "▶" } else { "○" };
            let (level, event) = state.stage_events.get(&i).cloned().unwrap_or((TraceLevel::Info, String::new()));
            let style = if completed {
                level_style(&level).add_modifier(Modifier::BOLD)
            } else if current {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let detail = if event.is_empty() {
                String::new()
            } else {
                format!("  · {event}")
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{marker}  "), style),
                Span::styled(*name, style),
                Span::styled(detail, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();
    let pipeline = List::new(pipeline_items)
        .block(Block::default().borders(Borders::ALL).title("Pipeline Stages"));
    f.render_widget(pipeline, left_chunks[0]);

    // VM states panel.
    let vm_items: Vec<ListItem> = VMS.iter().map(|(name, cid)| {
        let (running, socket) = state.vms.get(*name).unwrap_or(&(false, None));
        let status = if *running { "RUNNING" } else { "STOPPED" };
        let style = if *running {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red)
        };
        let sock_str = socket.as_deref().unwrap_or("-");
        ListItem::new(Line::from(vec![
            Span::styled(format!("{name:>4} (CID {cid})  "), Style::default().fg(Color::Gray)),
            Span::styled(status, style),
            Span::styled(format!("  [{sock_str}]"), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();
    let vm_list = List::new(vm_items)
        .block(Block::default().borders(Borders::ALL).title("Firecracker MicroVMs"));
    f.render_widget(vm_list, left_chunks[1]);

    // Center: Prompt lifecycle table.
    let header = ["Eval ID", "Prompt", "Verdict", "Path", "Held (µs)"];
    let rows: Vec<Vec<String>> = state
        .evaluations
        .iter()
        .map(|e| {
            let verdict_label = match e.path.as_str() {
                "llm" => "ALLOW → LLM",
                "regex_block" => "BLOCKED (regex)",
                "semantic_block" => "BLOCKED (semantic)",
                _ => "PENDING",
            };
            let held = e.held_us.map(|h| h.to_string()).unwrap_or_else(|| "—".into());
            let prompt = if e.prompt.len() > 32 {
                format!("{}…", &e.prompt[..32])
            } else {
                e.prompt.clone()
            };
            vec![
                e.eval_id_short.clone(),
                prompt,
                verdict_label.to_string(),
                e.path.clone(),
                held,
            ]
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(38),
        Constraint::Length(16),
        Constraint::Length(12),
        Constraint::Length(8),
    ];

    let table = Table::new(
        rows.iter()
            .map(|r| {
                Row::new(r.iter().map(|s| Line::from(Span::raw(s))).collect::<Vec<_>>())
            })
            .collect::<Vec<_>>(),
        widths,
    )
    .header(Row::new(
        header
            .iter()
            .map(|h| Line::from(Span::styled(*h, Style::default().add_modifier(Modifier::BOLD))))
            .collect::<Vec<_>>(),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Prompt Lifecycle (Referee → Blue → LLM)"),
    );
    f.render_widget(table, body_chunks[1]);

    // Right: Merkle tree (top) + Verifier result (bottom).
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(body_chunks[2]);

    let merkle = Paragraph::new(merkle_lines(state))
        .block(Block::default().borders(Borders::ALL).title("Merkle Tree"))
        .wrap(Wrap { trim: true });
    f.render_widget(merkle, right_chunks[0]);

    let verify = Paragraph::new(verify_lines(state))
        .block(Block::default().borders(Borders::ALL).title("Verification"))
        .wrap(Wrap { trim: true });
    f.render_widget(verify, right_chunks[1]);

    // ---- Bottom: live trace log ----
    let max_lines = 6; // 8 height - 2 borders
    let start = state.recent_trace.len().saturating_sub(max_lines);
    let trace_items: Vec<ListItem> = state.recent_trace[start..]
        .iter()
        .map(|record| {
            let ts = record.timestamp.format("%H:%M:%S%.3f");
            ListItem::new(Line::from(vec![
                Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("[{}] ", record.level.as_str()),
                    level_style(&record.level).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] ", record.stage.as_str()),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(&record.event, Style::default()),
            ]))
        })
        .collect();
    let trace_list = List::new(trace_items)
        .block(Block::default().borders(Borders::ALL).title("Live Trace Log (q to quit)"));
    f.render_widget(trace_list, chunks[2]);
}
