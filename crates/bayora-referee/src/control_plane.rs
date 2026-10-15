//! Control-plane HTTP API — the operator-facing side of the Referee.
//!
//! | Method | Path | Purpose |
//! |---|---|---|
//! | GET  | `/healthz` | liveness |
//! | GET  | `/v1/posture` | Security Posture HUD payload |
//! | POST | `/v1/evaluations` | create + sign manifest + mint capability |
//! | POST | `/v1/evaluations/{id}/turns` | run one bounded turn |
//! | GET  | `/v1/evaluations/{id}` | finalized evidence view |
//! | POST | `/v1/evaluations/seal` | force a Merkle batch seal |
//!
//! The Red MicroVM does *not* speak this protocol in production (it speaks
//! VSOCK frames — see [`crate::vsock_server`]); this API exists for the
//! operator, the dashboard and demos.

use crate::referee::{RefereeState, TurnOutcome};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bayora_common::capability::CapabilityToken;
use bayora_common::manifest::EvaluationManifest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Timing parameters the HUD and clients need to interpret a turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    pub mode: String,
    pub bucket_ms: Option<u64>,
    pub abort_margin_ms: u64,
    pub response_frame_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEvaluationResponse {
    pub evaluation_id: String,
    pub capability: CapabilityToken,
    pub manifest: EvaluationManifest,
    pub manifest_hash: String,
    pub manifest_signature: String,
    pub trust_anchor_public_key: String,
    pub capability_issuer_public_key: String,
    pub timing: TimingInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    pub capability: CapabilityToken,
    pub turn: u32,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub seq: u64,
    pub chain_hash: String,
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnTelemetry {
    pub path: String,
    pub held_us: u64,
    pub work_us: u64,
    pub deadline_aborted: bool,
    /// Inference accuracy an observer could reach from this mode's timings so
    /// far (lower is better; chance is ~0.33 for three stages).
    pub inference_accuracy: f64,
    pub samples_for_mode: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnResponse {
    pub evaluation_id: String,
    pub status: String,
    /// The exact padded bytes released to Red, hex-encoded.
    pub frame_hex: String,
    pub frame_bytes: u32,
    pub truncated: bool,
    pub telemetry: TurnTelemetry,
    pub evidence: EvidencePointer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationView {
    pub evaluation_id: String,
    pub status: String,
    pub path: String,
    pub manifest: EvaluationManifest,
    pub manifest_hash: String,
    pub manifest_signature: String,
    pub events: Vec<bayora_common::events::EvaluationEvent>,
    pub seq: u64,
    pub chain_hash: String,
    pub trust_anchor_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStatus {
    pub chain_len: u64,
    pub chain_head: String,
    pub pending_batch: usize,
    pub batch_size: usize,
    pub sinks: Vec<String>,
    pub trust_anchor_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureResponse {
    pub policy_version: String,
    pub timing: TimingInfo,
    pub reset_policy: String,
    pub transport: String,
    pub reset: String,
    pub evidence: EvidenceStatus,
    /// Metrics snapshot from [`crate::metrics::Metrics::posture`].
    pub metrics: crate::metrics::Posture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

/// API error carrying the canonical Referee error code.
pub struct ApiError(pub crate::referee::RefereeError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ApiErrorBody {
            code: self.0.code().to_string(),
            message: self.0.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<crate::referee::RefereeError> for ApiError {
    fn from(value: crate::referee::RefereeError) -> Self {
        ApiError(value)
    }
}

fn timing_info(state: &RefereeState) -> TimingInfo {
    TimingInfo {
        mode: state.policy().timing_mode().as_str().to_string(),
        bucket_ms: state.policy().bucket().map(|b| b.as_millis() as u64),
        abort_margin_ms: state.policy().abort_margin().as_millis() as u64,
        response_frame_bytes: state.policy().response_frame_bytes(),
    }
}

pub fn router(state: Arc<RefereeState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/posture", get(posture))
        .route("/v1/evaluations", post(create_evaluation))
        .route("/v1/evaluations/seal", post(seal_batch))
        .route("/v1/evaluations/{id}", get(get_evaluation))
        .route("/v1/evaluations/{id}/turns", post(run_turn))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Security Posture HUD payload: policy, trust anchors, evidence state and
/// live timing statistics.
async fn posture(State(state): State<Arc<RefereeState>>) -> Json<PostureResponse> {
    let evidence = EvidenceStatus {
        chain_len: state.evidence().chain_len(),
        chain_head: state.evidence().chain_head().to_hex(),
        pending_batch: state.evidence().pending_leaves(),
        batch_size: state.evidence().batch_size(),
        sinks: state.evidence().sink().descriptions(),
        trust_anchor_public_key: state.evidence().trust_anchor_public_key_hex(),
    };
    Json(PostureResponse {
        policy_version: state.policy().config().policy_version.clone(),
        timing: timing_info(&state),
        reset_policy: state.policy().reset_policy().as_str().to_string(),
        transport: state.transport().describe(),
        reset: state.reset().describe(),
        evidence,
        metrics: state.metrics().posture(),
    })
}

/// Create an evaluation: manifest is built *and signed* here, before any
/// prompt is processed; the capability token is minted for it.
async fn create_evaluation(
    State(state): State<Arc<RefereeState>>,
) -> Result<Json<CreateEvaluationResponse>, ApiError> {
    let created = state.create_evaluation().await?;
    let response = CreateEvaluationResponse {
        evaluation_id: created.evaluation_id,
        capability: created.token,
        manifest: created.manifest.clone(),
        manifest_hash: created.manifest_hash.to_hex(),
        manifest_signature: created.manifest_signature,
        trust_anchor_public_key: state.evidence().trust_anchor_public_key_hex(),
        capability_issuer_public_key: state.guard().issuer_public_key_hex(),
        timing: timing_info(&state),
    };
    Ok(Json(response))
}

/// Run one bounded, observable turn and return the released frame.
async fn run_turn(
    State(state): State<Arc<RefereeState>>,
    Path(evaluation_id): Path<String>,
    Json(request): Json<TurnRequest>,
) -> Result<Json<TurnResponse>, ApiError> {
    // One turn per evaluation: the Referee owns the turn counter, the client
    // may only restate it. Checked *before* the capability gate so a malformed
    // request can never burn a legitimate single-use nonce.
    if request.turn != 1 {
        return Err(ApiError(crate::referee::RefereeError::TurnMismatch {
            requested: request.turn,
            expected: 1,
        }));
    }
    let outcome: TurnOutcome = state
        .run_turn(&evaluation_id, &request.capability, &request.prompt)
        .await?;

    let posture = state.metrics().posture();
    let mode = state.policy().timing_mode().as_str().to_string();
    let (inference_accuracy, samples_for_mode) = posture
        .modes
        .get(&mode)
        .map(|s| (s.inference_accuracy, s.samples))
        .unwrap_or((0.0, 0));

    Ok(Json(TurnResponse {
        evaluation_id: outcome.evaluation_id.clone(),
        status: outcome.status,
        frame_hex: hex::encode(&outcome.frame),
        frame_bytes: outcome.frame_bytes,
        truncated: outcome.truncated,
        telemetry: TurnTelemetry {
            path: outcome.path.as_str().to_string(),
            held_us: outcome.held_us,
            work_us: outcome.work_us,
            deadline_aborted: outcome.deadline_aborted,
            inference_accuracy,
            samples_for_mode,
        },
        evidence: EvidencePointer {
            seq: outcome.seq,
            chain_hash: outcome.chain_hash.to_hex(),
            manifest_hash: state
                .get_evaluation(&outcome.evaluation_id)
                .await
                .map(|v| v.manifest_hash.to_hex())
                .unwrap_or_default(),
        },
    }))
}

/// Read back a finalized evaluation (operator/auditor view). Note this view
/// *does* include the defence path — it is never sent to Red.
async fn get_evaluation(
    State(state): State<Arc<RefereeState>>,
    Path(evaluation_id): Path<String>,
) -> Result<Json<EvaluationView>, ApiError> {
    match state.get_evaluation(&evaluation_id).await {
        Some(view) => Ok(Json(EvaluationView {
            evaluation_id,
            status: view.status,
            path: view.path.as_str().to_string(),
            manifest: view.manifest.clone(),
            manifest_hash: view.manifest_hash.to_hex(),
            manifest_signature: view.manifest_signature,
            events: view.events,
            seq: view.seq,
            chain_hash: view.chain_hash.to_hex(),
            trust_anchor_public_key: state.evidence().trust_anchor_public_key_hex(),
        })),
        None => Err(ApiError(crate::referee::RefereeError::UnknownEvaluation(
            evaluation_id,
        ))),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealResponse {
    pub sealed: bool,
    pub record: Option<bayora_common::records::EvidenceRecord>,
    pub pending_batch: usize,
}

/// Force a Merkle batch seal (auditors want a root before the auto batch
/// fills).
async fn seal_batch(
    State(state): State<Arc<RefereeState>>,
) -> Result<Json<SealResponse>, ApiError> {
    let record = state.seal_batch().await?;
    Ok(Json(SealResponse {
        sealed: record.is_some(),
        record,
        pending_batch: state.evidence().pending_leaves(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_guard::CapabilityGuard;
    use crate::evidence_emitter::{DualSink, EvidenceEmitter, MemorySink};
    use crate::metrics::Metrics;
    use crate::mini_http;
    use crate::policy_engine::PolicyEngine;
    use crate::snapshot_manager::NoopResetManager;
    use crate::transport::StubTransport;
    use crate::trust_anchor::{CapabilityIssuer, IsolatedSocketSigner, SignerEndpoint, TrustAnchorSigner};
    use bayora_common::manifest::ImageRegistry;
    use bayora_common::policy::{ResetPolicy, TimingMode};

    /// Full stack over real loopback TCP: signer daemon + referee HTTP API.
    async fn spawn_api(timing_mode: TimingMode) -> (std::net::SocketAddr, tempfile::TempDir) {
        let keydir = tempfile::tempdir().unwrap();
        let keys = Arc::new(bayora_signer::SignerKeys::load_or_create(keydir.path()).unwrap());
        let listener = bayora_signer::bind(&bayora_signer::ListenerSpec::Tcp(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
        let signer_addr = listener.local_addr().unwrap();
        bayora_signer::spawn(listener, Arc::clone(&keys));

        let socket_signer = Arc::new(
            IsolatedSocketSigner::connect(SignerEndpoint::Tcp(signer_addr))
                .await
                .unwrap(),
        );
        let issuer: Arc<dyn CapabilityIssuer> = socket_signer.clone();
        let trust_anchor: Arc<dyn TrustAnchorSigner> = socket_signer.clone();

        let yaml = include_str!("../../../config/policy.yaml").replacen(
            "timing_mode: \"EVAL_500\"",
            match timing_mode {
                TimingMode::Normal => "timing_mode: \"NORMAL\"",
                TimingMode::Eval500 => "timing_mode: \"EVAL_500\"",
                TimingMode::Eval1000 => "timing_mode: \"EVAL_1000\"",
            },
            1,
        );
        let policy = Arc::new(PolicyEngine::from_yaml(&yaml).unwrap());
        let images = Arc::new(
            ImageRegistry::load(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../config/images.json")
                    .as_path(),
            )
            .unwrap(),
        );
        let guard = Arc::new(CapabilityGuard::new(
            bayora_common::capability::IssuerPublicKey::from_hex(&keys.capability_issuer_pub_hex())
                .unwrap(),
            4096,
        ));
        let evidence = Arc::new(EvidenceEmitter::new(
            DualSink::new(vec![Arc::new(MemorySink::new())]),
            trust_anchor.clone(),
            policy.require_manifest_signature(),
            policy.batch_size(),
        ));
        let state = Arc::new(RefereeState::new(
            policy,
            images,
            trust_anchor,
            issuer,
            guard,
            Arc::new(StubTransport::default()),
            Arc::new(NoopResetManager::new(ResetPolicy::Snapshot)),
            evidence,
            Arc::new(Metrics::new()),
            60_000,
        ));

        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, keydir)
    }

    fn parse<T: serde::de::DeserializeOwned>(resp: &mini_http::HttpResponse) -> T {
        assert!(
            resp.is_success(),
            "expected 2xx, got {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        );
        serde_json::from_slice(&resp.body).unwrap()
    }

    #[tokio::test]
    async fn health_and_posture_serve_the_hud() {
        let (addr, _dir) = spawn_api(TimingMode::Eval500).await;
        let health = mini_http::tcp_request(addr, "GET", "/healthz", None).await.unwrap();
        assert_eq!(health.status, 200);
        assert_eq!(health.body_str().unwrap(), "ok");

        let resp = mini_http::tcp_request(addr, "GET", "/v1/posture", None).await.unwrap();
        let posture: PostureResponse = parse(&resp);
        assert_eq!(posture.policy_version, "2026.10.v3");
        assert_eq!(posture.timing.mode, "EVAL_500");
        assert_eq!(posture.timing.bucket_ms, Some(500));
        assert_eq!(posture.timing.abort_margin_ms, 15);
        assert_eq!(posture.reset_policy, "SNAPSHOT");
        assert_eq!(posture.evidence.chain_len, 0);
        assert_eq!(posture.evidence.sinks.len(), 1);
        assert!(posture
            .evidence
            .trust_anchor_public_key
            .parse::<String>()
            .is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn full_turn_flow_over_http() {
        let (addr, _dir) = spawn_api(TimingMode::Eval500).await;

        // 1. Create: manifest signed before any prompt exists.
        let created_resp = mini_http::tcp_request(addr, "POST", "/v1/evaluations", Some(b"{}"))
            .await
            .unwrap();
        let created: CreateEvaluationResponse = parse(&created_resp);
        assert!(created.evaluation_id.starts_with("eval_"));
        assert!(!created.manifest_signature.is_empty());

        // 2. Turn: capability presented, frame released at the bucket.
        let body = serde_json::json!({
            "capability": created.capability,
            "turn": 1,
            "prompt": "summarise the incident report",
        });
        let turn_resp = mini_http::tcp_request(
            addr,
            "POST",
            &format!("/v1/evaluations/{}/turns", created.evaluation_id),
            Some(&serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
        let turn: TurnResponse = parse(&turn_resp);
        assert_eq!(turn.status, "ok");
        assert_eq!(turn.frame_bytes, 4096);
        assert_eq!(turn.telemetry.path, "llm");
        assert_eq!(turn.telemetry.held_us, 500_000);
        assert!(!turn.telemetry.deadline_aborted);
        assert_eq!(turn.evidence.seq, 0);
        // The released frame parses and discloses no stage.
        let frame = hex::decode(&turn.frame_hex).unwrap();
        let env = bayora_common::frame::parse_padded_response(&frame).unwrap();
        assert_eq!(env.status, "ok");

        // 3. Replay the capability: canonical error code.
        let replay_resp = mini_http::tcp_request(
            addr,
            "POST",
            &format!("/v1/evaluations/{}/turns", created.evaluation_id),
            Some(&serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(replay_resp.status, 403);
        let err: ApiErrorBody = serde_json::from_slice(&replay_resp.body).unwrap();
        assert_eq!(err.code, "ERR_CAPABILITY_REPLAY_DENIED");

        // 4. Read back the evidence view.
        let view_resp = mini_http::tcp_request(
            addr,
            "GET",
            &format!("/v1/evaluations/{}", created.evaluation_id),
            None,
        )
        .await
        .unwrap();
        let view: EvaluationView = parse(&view_resp);
        assert_eq!(view.seq, 0);
        assert_eq!(view.path, "llm");
        assert_eq!(view.events.len(), 4, "started, reset, routed, released");

        // 5. Force a batch seal.
        let seal_resp = mini_http::tcp_request(addr, "POST", "/v1/evaluations/seal", Some(b""))
            .await
            .unwrap();
        let seal: SealResponse = parse(&seal_resp);
        assert!(seal.sealed);
        let record = seal.record.unwrap();
        assert_eq!(record.record_type(), "batch_seal");

        // 6. Posture now reflects the completed turn.
        let resp = mini_http::tcp_request(addr, "GET", "/v1/posture", None).await.unwrap();
        let posture: PostureResponse = parse(&resp);
        assert_eq!(posture.metrics.evaluations_completed, 1);
        assert_eq!(posture.evidence.chain_len, 1);
        assert_eq!(posture.evidence.pending_batch, 0);
    }

    #[tokio::test]
    async fn malformed_and_unknown_requests_are_canonical_errors() {
        let (addr, _dir) = spawn_api(TimingMode::Normal).await;

        // Unknown evaluation id.
        let resp = mini_http::tcp_request(addr, "GET", "/v1/evaluations/eval_nope", None)
            .await
            .unwrap();
        assert_eq!(resp.status, 404);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "ERR_UNKNOWN_EVALUATION");

        // Unknown field in the turn request body.
        let created_resp = mini_http::tcp_request(addr, "POST", "/v1/evaluations", Some(b"{}"))
            .await
            .unwrap();
        let created: CreateEvaluationResponse = parse(&created_resp);
        let body = serde_json::json!({
            "capability": created.capability,
            "turn": 1,
            "prompt": "x",
            "admin": true
        });
        let resp = mini_http::tcp_request(
            addr,
            "POST",
            &format!("/v1/evaluations/{}/turns", created.evaluation_id),
            Some(&serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 422, "{}", String::from_utf8_lossy(&resp.body));
    }

    #[tokio::test]
    async fn wrong_turn_index_is_refused_without_burning_the_capability() {
        let (addr, _dir) = spawn_api(TimingMode::Normal).await;
        let created_resp = mini_http::tcp_request(addr, "POST", "/v1/evaluations", Some(b"{}"))
            .await
            .unwrap();
        let created: CreateEvaluationResponse = parse(&created_resp);

        // The client may not invent a turn that does not exist.
        let refused = serde_json::json!({
            "capability": created.capability.clone(),
            "turn": 2,
            "prompt": "x",
        });
        let resp = mini_http::tcp_request(
            addr,
            "POST",
            &format!("/v1/evaluations/{}/turns", created.evaluation_id),
            Some(&serde_json::to_vec(&refused).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 400, "{}", String::from_utf8_lossy(&resp.body));
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "ERR_TURN_MISMATCH");

        // The refusal happened before the capability gate, so the single-use
        // nonce survived it: the same token still runs its real turn.
        let accepted = serde_json::json!({
            "capability": created.capability,
            "turn": 1,
            "prompt": "x",
        });
        let resp = mini_http::tcp_request(
            addr,
            "POST",
            &format!("/v1/evaluations/{}/turns", created.evaluation_id),
            Some(&serde_json::to_vec(&accepted).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
        let turn: TurnResponse = parse(&resp);
        assert_eq!(turn.status, "ok");
    }
}
