//! Ratatui TUI dashboard for the Bayora Enclave orchestrator.
//!
//! Shows live pipeline state: MicroVM status, Referee posture, evaluation
//! lifecycle, Merkle batch seals, and trace stream.
//!
//! Works headless too — when stdout is not a TTY, falls back to JSON lines.

use crate::trace::{Trace, TraceRecord, TraceLevel, TraceStage};
use anyhow::Result;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row},
    Terminal,
};
use serde_json::Value;
use std::io;
use std::path::Path;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Run the TUI dashboard.
pub fn run_dashboard(config: &crate::OrchestratorConfig, refresh_ms: u64) -> Result<()> {
    // Check if stdout is a TTY
    let is_tty = std::io::stdout().is_terminal();

    if !is_tty {

/// Headless dashboard — outputs JSON lines to stdout.
fn run_headless_dashboard(_config: &crate::OrchestratorConfig, _refresh_ms: u64) -> Result<()> {
    println!(
        "{}",
        serde_json::json!({
            "event": "dashboard_started",
            "mode": "headless",
            "timestamp": chrono::Utc::now()
        })
    );
    // In headless mode, just wait
    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;
    Ok(())
}

/// TUI dashboard with ratatui.
fn run_tui_dashboard(config: &crate::OrchestratorConfig, refresh_ms: u64) -> Result<()> {
    use crossterm::{
        event::{DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config, refresh_ms);

    let result = app.run(&mut terminal);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Dashboard application state.
struct App {
    config: Arc<crate::OrchestratorConfig>,
    refresh_ms: u64,
    trace_records: Vec<TraceRecord>,
    evaluations: Vec<EvalDisplay>,
    posture: Option<serde_json::Value>,
    microvms: Vec<MicroVMStatus>,
    last_refresh: std::time::Instant,
}

struct EvalDisplay {
    eval_id: String,
    prompt: String,
    path: String,
    held_us: Option<u64>,
}

struct MicroVMStatus {
    name: String,
    cid: u32,
    running: bool,
    pid: Option<u32>,
    socket: Option<String>,
}

impl App {
    fn new(config: &crate::OrchestratorConfig, refresh_ms: u64) -> Self {
        Self {
            config: Arc::new(config.clone()),
            refresh_ms,
            trace_records: Vec::new(),
            evaluations: Vec::new(),
            posture: None,
            microvms: vec![
                MicroVMStatus {
                    name: "red".into(),
                    cid: 3,
                    running: false,
                    pid: None,
                    socket: None,
                },
                MicroVMStatus {
                    name: "blue".into(),
                    cid: 4,
                    running: false,
                    pid: None,
                    socket: None,
                },
                MicroVMStatus {
                    name: "llm".into(),
                    cid: 5,
                    running: false,
                    pid: None,
                    socket: None,
                },
            ],
            last_refresh: std::time::Instant::now(),
        }
    }

    fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            // Refresh data if needed
            if self.last_refresh.elapsed() >= Duration::from_millis(self.refresh_ms) {
                self.refresh()?;
                self.last_refresh = std::time::Instant::now();
            }

            terminal.draw(|f| self.ui(f))?;

            // Handle events with timeout
            if crossterm::event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = crossterm::event::read()? {
                    if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn refresh(&mut self) -> Result<()> {
        // Refresh trace records from file
        if let Ok(contents) = std::fs::read_to_string(&self.config.trace_log) {
            self.trace_records = contents
                .lines()
                .filter_map(|l| serde_json::from_str::<TraceRecord>(l).ok())
                .collect();
        }

        // Refresh posture from Referee API
        if let Ok(posture) = reqwest::blocking::get(format!(
            "http://{}/v1/posture",
            self.config.referee_listen
        ))
        .and_then(|r| r.json::<serde_json::Value>())
        {
            self.posture = Some(posture);
        }

        // Refresh MicroVM status by checking sockets
        for vm in &mut self.microvms {
            let socket_path = self.config.runtime_dir.join(format!("fc-{}.sock", vm.name));
            let vsock_path = self.config.runtime_dir.join(format!("{}.vsock", vm.name));
            vm.running = vsock_path.exists();
            vm.socket = if vsock_path.exists() {
                Some(vsock_path.display().to_string())
            } else {
                None
            };
        }

        // Refresh evaluations from evidence log
        if let Ok(contents) = std::fs::read_to_string(&self.config.evidence_log) {
            self.evaluations = contents
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|r| r.get("record_type") == Some(&Value::String("evaluation".into())))
                .filter_map(|r| {
                    let manifest = r.get("manifest")?;
                    let eval_id = manifest.get("evaluation_id")?.as_str()?.to_string();
                    let events = r.get("events")?;
                    let routed = events.as_array()?.iter().find(|e| e.get("event_type") == Some(&Value::String("prompt_routed".into())))?;
                    let prompt = routed.get("prompt")?.as_str()?.to_string();
                    let path = routed.get("path")?.as_str()?.to_string();
                    let released = events.as_array()?.iter().find(|e| e.get("event_type") == Some(&Value::String("response_released".into())))?;
                    let held_us = released.get("held_us")?.as_u64();
                    Some(EvalDisplay {
                        eval_id,
                        prompt,
                        path,
                        held_us,
                    })
                })
                .collect();
        }

        Ok(())
    }

    fn ui(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(6),  // MicroVM status
                Constraint::Length(8),  // Posture metrics
                Constraint::Length(10), // Evaluations
                Constraint::Min(0),     // Trace stream
            ])
            .split(f.size());

        // Title
        let title = Paragraph::new(Span::styled(
            "BAYORA ENCLAVE — LIVE PIPELINE DASHBOARD",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // MicroVM status table
        self.render_microvm_table(f, chunks[1]);

        // Posture metrics
        self.render_posture(f, chunks[2]);

        // Evaluations
        self.render_evaluations(f, chunks[3]);

        // Trace stream
        self.render_trace(f, chunks[4]);
    }

    fn render_microvm_table(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let header = Row::new(vec!["Role", "CID", "Status", "Socket"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = self
            .microvms
            .iter()
            .map(|vm| {
                let status = if vm.running {
                    "RUNNING".to_string()
                } else {
                    "STOPPED".to_string()
                };
                let status_color = if vm.running { Color::Green } else { Color::Red };
                Row::new(vec![
                    vm.name.clone(),
                    vm.cid.to_string(),
                    status,
                    vm.socket.clone().unwrap_or_else(|| "-".into()),
                ])
                .style(Style::default().fg(status_color))
            })
            .collect();

        let table = Table::new(rows)
            .header(header)
            .widths([
                Constraint::Length(10),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(30),
            ])
            .block(Block::default().title("MicroVMs").borders(Borders::ALL));
        f.render_widget(table, area);
    }

    fn render_posture(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let lines: Vec<ListItem> = if let Some(ref p) = self.posture {
            let evals = p.get("evaluations_completed").and_then(|v| v.as_u64()).unwrap_or(0);
            let resets = p.get("resets").and_then(|v| v.as_u64()).unwrap_or(0);
            let replays = p.get("capability_replays").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_verify = p.get("last_verification").and_then(|v| v.as_str()).unwrap_or("pending");

            vec![
                ListItem::new(format!("Evaluations completed: {}", evals)),
                ListItem::new(format!("Firecracker resets: {}", resets)),
                ListItem::new(format!("Capability replays: {}", replays)),
                ListItem::new(format!("Last verification: {}", last_verify)),
            ]
        } else {
            vec![ListItem::new("Waiting for Referee posture...")]
        };

        let list = List::new(lines)
            .block(Block::default().title("Referee Posture").borders(Borders::ALL));
        f.render_widget(list, area);
    }

    fn render_evaluations(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .evaluations
            .iter()
            .rev()
            .take(6)
            .map(|e| {
                let (color, label) = match e.path.as_str() {
                    "llm" => (Color::Green, "LLM"),
                    "regex_block" => (Color::Red, "BLOCKED(regex)"),
                    "semantic_block" => (Color::Red, "BLOCKED(semantic)"),
                    _ => (Color::Yellow, "PENDING"),
                };
                let held = e.held_us.map(|h| format!("{}µs", h)).unwrap_or_else(|| "—".into());
                ListItem::new(Span::styled(
                    format!("{} | {} | {}µs | {}", e.eval_id.chars().take(20).collect::<String>(), label, held, e.prompt.chars().take(30).collect::<String>()),
                    Style::default().fg(color),
                ))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().title("Evaluation Lifecycle").borders(Borders::ALL));
        f.render_widget(list, area);
    }

    fn render_trace(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .trace_records
            .iter()
            .rev()
            .take(12)
            .map(|r| {
                let color = match r.level {
                    TraceLevel::Success => Color::Green,
                    TraceLevel::Warn => Color::Yellow,
                    TraceLevel::Error => Color::Red,
                    TraceLevel::Info => Color::Cyan,
                };
                ListItem::new(Span::styled(
                    format!(
                        "{} [{}] {} {}",
                        r.timestamp.format("%H:%M:%S%.3f"),
                        r.event,
                        r.data.get("detail").cloned().unwrap_or_default(),
                        r.data.get("eval_id").cloned().unwrap_or_default()
                    ),
                    Style::default().fg(color),
                ))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().title("Trace Stream (q to quit)").borders(Borders::ALL));
        f.render_widget(list, area);
    }
}