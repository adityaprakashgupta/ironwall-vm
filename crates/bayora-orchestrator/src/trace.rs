//! Structured trace logging for the Bayora Enclave orchestrator.
//!
//! Every action — artifact download, image build, microVM boot, evaluation
//! creation, prompt/response, Blue verdict, LLM output, reset, Merkle seal,
//! verifier result — is recorded as a JSON line in the trace file. This makes
//! the entire lifecycle auditable and replayable.

use chrono::{Utc, DateTime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};

/// When true, suppress the stderr echo of trace records (used during TUI dashboard mode
/// so crossterm has exclusive terminal control).
static SUPPRESS_STDERR_TRACE: AtomicBool = AtomicBool::new(false);

/// Suppress stderr echo of trace records.
pub fn suppress_stderr_trace(suppress: bool) {
    SUPPRESS_STDERR_TRACE.store(suppress, Ordering::SeqCst);
}

/// A single trace record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub timestamp: DateTime<Utc>,
    pub level: TraceLevel,
    pub stage: TraceStage,
    pub event: String,
    pub data: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceLevel {
    Info,
    Warn,
    Error,
    Success,
}

impl TraceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceLevel::Info => "INFO",
            TraceLevel::Warn => "WARN",
            TraceLevel::Error => "ERROR",
            TraceLevel::Success => "OK ",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceStage {
    ArtifactDownload,
    ImageBuild,
    MicroVMBoot,
    Evaluation,
    Reset,
    Evidence,
    Verification,
    Dashboard,
}

impl TraceStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceStage::ArtifactDownload => "artifact",
            TraceStage::ImageBuild => "image",
            TraceStage::MicroVMBoot => "microvm",
            TraceStage::Evaluation => "eval",
            TraceStage::Reset => "reset",
            TraceStage::Evidence => "evidence",
            TraceStage::Verification => "verify",
            TraceStage::Dashboard => "ui",
        }
    }
}

/// The trace writer — appends JSON lines to a file.
pub struct Trace {
    writer: Mutex<Option<BufWriter<File>>>,
    path: PathBuf,
}

impl Trace {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: Mutex::new(Some(BufWriter::new(file))),
            path: path.to_path_buf(),
        })
    }

    pub fn record(&self, level: TraceLevel, stage: TraceStage, event: &str, data: BTreeMap<String, serde_json::Value>) {
        let level_label = level.as_str();
        let stage_label = stage.as_str();
        let record = TraceRecord {
            timestamp: Utc::now(),
            level,
            stage,
            event: event.to_string(),
            data,
        };
        let line = serde_json::to_string(&record).unwrap_or_default();
        if let Ok(mut guard) = self.writer.lock() {
            if let Some(ref mut w) = *guard {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
        // Also print to stderr for visibility (unless suppressed during TUI dashboard mode).
        if !SUPPRESS_STDERR_TRACE.load(Ordering::SeqCst) {
            eprintln!("[{}] {} {} {}", record.timestamp.format("%H:%M:%S%.3f"), level_label, stage_label, event);
        }
    }

    pub fn info(&self, stage: TraceStage, event: &str, data: BTreeMap<String, serde_json::Value>) {
        self.record(TraceLevel::Info, stage, event, data);
    }

    pub fn success(&self, stage: TraceStage, event: &str, data: BTreeMap<String, serde_json::Value>) {
        self.record(TraceLevel::Success, stage, event, data);
    }

    pub fn warn(&self, stage: TraceStage, event: &str, data: BTreeMap<String, serde_json::Value>) {
        self.record(TraceLevel::Warn, stage, event, data);
    }

    pub fn error(&self, stage: TraceStage, event: &str, data: BTreeMap<String, serde_json::Value>) {
        self.record(TraceLevel::Error, stage, event, data);
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for Trace {
    fn default() -> Self {
        let path = std::env::temp_dir().join("bayora-orchestrator.trace.jsonl");
        Self::new(&path).expect("failed to create default trace")
    }
}

fn level_str(level: &TraceLevel) -> &'static str {
    match level {
        TraceLevel::Info => "INFO",
        TraceLevel::Warn => "WARN",
        TraceLevel::Error => "ERROR",
        TraceLevel::Success => "OK ",
    }
}

fn stage_str(stage: &TraceStage) -> &'static str {
    match stage {
        TraceStage::ArtifactDownload => "artifact",
        TraceStage::ImageBuild => "image",
        TraceStage::MicroVMBoot => "microvm",
        TraceStage::Evaluation => "eval",
        TraceStage::Reset => "reset",
        TraceStage::Evidence => "evidence",
        TraceStage::Verification => "verify",
        TraceStage::Dashboard => "ui",
    }
}

/// Convenience macro for recording trace events.
#[macro_export]
macro_rules! trace_event {
    ($trace:expr, $level:ident, $stage:expr, $event:expr, $($key:expr => $val:expr),* $(,)?) => {
        let mut __data = std::collections::BTreeMap::new();
        $(__data.insert($key.to_string(), serde_json::to_value($val).unwrap_or(serde_json::Value::Null));)*
        $trace.$level($stage, $event, __data);
    };
}