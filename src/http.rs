//! HTTP surface of the SRE agent: router construction and all request
//! handlers. Extracted from `main.rs` so integration tests can build the
//! exact production `Router` (routes, CORS, tracing layers) with
//! `tower::ServiceExt::oneshot` against an arbitrary `AppState` — `main()`
//! keeps only env/config setup and serving.

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;

use crate::agent;
use crate::agent::contracts::InvestigationWindow;
use crate::agent::memory::WorkingMemory;
use crate::agent::skill_store::SkillStore;
use crate::agent::stream::AgentEvent;
use crate::agent::templates;
use crate::agent::tools::{ToolContext, ToolRegistry};
use crate::cancellation::CancellationToken;
use crate::metrics::AgentMetrics;
use crate::state::AppState;

/// Build the production router: all API routes plus the CORS and trace
/// layers, with the given state attached. This is the exact app served by
/// `main()`.
pub fn router(state: AppState) -> Router {
    // query-api is the authenticated public boundary. The agent only accepts
    // calls carrying its internal credential, even when reached inside the
    // cluster directly.
    let protected = Router::new()
        .route("/api/v1/investigate", post(investigate))
        // Templates
        .route(
            "/api/v1/investigation-templates",
            get(list_investigation_templates),
        )
        .route("/metrics", get(metrics))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_internal_token,
        ));

    Router::new()
        .merge(protected)
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn require_internal_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    use subtle::ConstantTimeEq;

    let supplied = headers
        .get("x-rush-internal-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let expected = state.internal_auth_token.as_bytes();
    let valid = supplied.len() == expected.len() && supplied.as_bytes().ct_eq(expected).into();
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

fn default_tenant() -> String {
    "default".to_string()
}

fn default_scopes() -> Vec<String> {
    vec!["all".to_string()]
}

/// Default number of recent turns to include in the context window for
/// follow-up investigations.
fn default_context_turns() -> usize {
    10
}

#[derive(Debug, Deserialize)]
struct InvestigateRequest {
    /// If non-empty, continue this session. If empty, create a new session.
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    question: String,
    #[serde(default)]
    additional_context: String,
    /// Legacy field: kept for backwards compat with older frontends that
    /// send the full prior conversation. Ignored when `session_id` is set.
    #[serde(default)]
    prior_messages: Vec<serde_json::Value>,
    /// Tenant ID forwarded to query-api for server-side data isolation.
    #[serde(default = "default_tenant")]
    tenant_id: String,
    /// Scopes the caller has access to.
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    /// Template ID for new sessions. Ignored on follow-ups.
    #[serde(default)]
    template_id: String,
    /// User-chosen model for this investigation. Validated server-side against
    /// the admin policy (`sre_agent_allowed_models`); a disallowed value falls
    /// back to the default. Empty = use the policy/env default.
    #[serde(default)]
    model: String,
    /// User-chosen thinking level (minimal/low/medium/high). Honored only when
    /// the resolved model is a reasoning model AND the level is allowed for it
    /// by the policy; otherwise ignored.
    #[serde(default)]
    reasoning_effort: String,
    /// Optional explicit incident/baseline scope for this turn. A changed
    /// window partitions old causal evidence instead of reusing it as proof.
    #[serde(default)]
    window: Option<InvestigationWindow>,
    /// Continue an unresolved dead-end intentionally; otherwise escalation is
    /// reset for a normal follow-up turn.
    #[serde(default)]
    continue_dead_end: bool,
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn readyz(State(state): State<AppState>) -> Response {
    let query_api_started = std::time::Instant::now();
    let query_api_ready = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.query_api.ready("default"),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    state
        .metrics
        .query_api_finished(query_api_started.elapsed(), query_api_ready);
    let llm_ready = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.query_api.llm_ready("default"),
    )
    .await
    .is_ok_and(|result| result.unwrap_or(false));
    // Provider configuration is tenant-specific and can be completed after
    // deployment. Keep it visible as a diagnostic without making an otherwise
    // healthy agent pod fail readiness for the special `default` tenant.
    let ready = query_api_ready;
    state.metrics.set_ready(ready);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "status": if ready { "ready" } else { "not_ready" },
            "checks": {
                "query_api": query_api_ready,
                "default_tenant_llm": llm_ready,
            }
        })),
    )
        .into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Body::from(state.metrics.render()))
        .expect("metrics response builder accepts static headers")
}

/// Convert agent events into an SSE body and emit a comment heartbeat while
/// the agent is waiting on a tool or provider response. Without heartbeats,
/// an otherwise healthy investigation can be dropped by an idle proxy before
/// the next evidence event arrives.
struct SseCancellationGuard {
    cancellation: CancellationToken,
    metrics: Arc<AgentMetrics>,
}

impl Drop for SseCancellationGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.metrics.sse_closed();
    }
}

fn sse_body(
    rx: mpsc::Receiver<AgentEvent>,
    cancellation: CancellationToken,
    metrics: Arc<AgentMetrics>,
) -> Body {
    metrics.sse_opened();
    let guard = SseCancellationGuard {
        cancellation,
        metrics,
    };
    let heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(15),
    );
    let stream = futures_util::stream::unfold(
        (rx, heartbeat, guard),
        |(mut rx, mut heartbeat, guard)| async move {
            tokio::select! {
                event = rx.recv() => event.map(|event| {
                    (
                        Ok::<_, std::convert::Infallible>(Bytes::from(event.to_sse_bytes())),
                        (rx, heartbeat, guard),
                    )
                }),
                _ = heartbeat.tick() => Some((
                    Ok::<_, std::convert::Infallible>(Bytes::from_static(b": keep-alive\n\n")),
                    (rx, heartbeat, guard),
                )),
            }
        },
    );
    Body::from_stream(stream)
}

const MAX_SAVED_ACTIVITY_BYTES: usize = 900_000;
const MAX_SAVED_TOOL_RESULT_CHARS: usize = 128_000;

#[derive(Default)]
struct SavedActivityLog {
    events: Vec<serde_json::Value>,
    bytes: usize,
    truncated: bool,
}

impl SavedActivityLog {
    fn push(&mut self, event: &AgentEvent) {
        let value = match event {
            AgentEvent::ToolCall { name, args } => serde_json::json!({
                "type": "tool_call",
                "name": name,
                "args": args,
            }),
            AgentEvent::ToolResult { name, data, .. } => serde_json::json!({
                "type": "tool_result",
                "name": name,
                "data": truncate_saved_tool_result(data),
            }),
            _ => return,
        };

        let event_bytes = serde_json::to_vec(&value).map_or(MAX_SAVED_ACTIVITY_BYTES, |v| v.len());
        if self.bytes.saturating_add(event_bytes) > MAX_SAVED_ACTIVITY_BYTES {
            self.truncated = true;
            return;
        }

        self.bytes += event_bytes;
        self.events.push(value);
    }

    fn to_json(&self) -> String {
        let mut events = self.events.clone();
        if self.truncated {
            events.push(serde_json::json!({
                "type": "tool_result",
                "name": "saved_activity",
                "data": "Additional tool activity was omitted because the saved log reached its size limit.",
            }));
        }
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string())
    }
}

fn truncate_saved_tool_result(data: &str) -> String {
    match data.char_indices().nth(MAX_SAVED_TOOL_RESULT_CHARS) {
        Some((index, _)) => format!("{}\n[truncated in saved session]", &data[..index]),
        None => data.to_string(),
    }
}

// ── Investigate handler (session-aware) ──

async fn investigate(
    State(state): State<AppState>,
    Json(req): Json<InvestigateRequest>,
) -> Result<Response, (StatusCode, String)> {
    let is_legacy_follow_up = !req.prior_messages.is_empty() && req.session_id.is_empty();

    if req.event_id.is_empty()
        && req.question.is_empty()
        && !is_legacy_follow_up
        && req.session_id.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "provide event_id, question, or session_id".to_string(),
        ));
    }

    // Admit the full investigation before doing session/setup work. This keeps
    // expensive LLM and tool work bounded under burst traffic while retaining
    // the tenant from the request in ToolContext unchanged.
    let permit = state
        .admission
        .acquire()
        .await
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    let investigation_started = std::time::Instant::now();

    // Build the unified skill store, cached for 60s — skill edits show up on
    // the next investigation within a minute, without paying an HTTP fetch to
    // query-api (or a config_db scan) on every single request.
    const SKILL_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
    let cached_skills = {
        let guard = state.caches.skills.read().await;
        guard
            .as_ref()
            .filter(|(built_at, _)| built_at.elapsed() < SKILL_CACHE_TTL)
            .map(|(_, store)| store.clone())
    };
    let skill_store = match cached_skills {
        Some(store) => store,
        None => {
            let store = Arc::new(
                SkillStore::load_with_metrics(
                    &state.query_api,
                    &req.tenant_id,
                    Some(state.metrics.as_ref()),
                )
                .await,
            );
            *state.caches.skills.write().await = Some((std::time::Instant::now(), store.clone()));
            store
        }
    };

    // Determine whether this is a new or existing session.
    let is_new_session = req.session_id.is_empty();
    let session_id = if is_new_session {
        uuid::Uuid::new_v4().to_string()
    } else {
        req.session_id.clone()
    };

    // Determine if we are in session mode (enables question-asking).
    let session_mode = !is_legacy_follow_up;

    // Load or create session state and working memory.
    let mut restored_memory: Option<WorkingMemory> = None;

    if is_new_session && session_mode {
        // Create session in DB
        let auto_title = if !req.question.is_empty() {
            // Use first 100 chars of question as title
            req.question.chars().take(100).collect::<String>()
        } else if !req.event_id.is_empty() {
            format!("Alert: {}", &req.event_id)
        } else {
            "New investigation".to_string()
        };
        state
            .query_api
            .create_session(
                &session_id,
                &req.tenant_id,
                &auto_title,
                "",
                &req.template_id,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else if !is_new_session && session_mode {
        // Load session from DB and verify tenant
        let session = state
            .query_api
            .get_session(&req.tenant_id, &session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "session not found".to_string()))?;

        if session.tenant_id != req.tenant_id {
            return Err((
                StatusCode::FORBIDDEN,
                "session belongs to a different tenant".to_string(),
            ));
        }

        // Reactivate completed sessions on follow-up
        if session.status == "completed" || session.status == "paused" {
            state
                .query_api
                .update_session_status(&req.tenant_id, &session_id, "active")
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        // Deserialize persisted working memory
        if session.working_memory != "{}" && !session.working_memory.is_empty() {
            match WorkingMemory::from_json(&session.working_memory) {
                Ok(mem) => restored_memory = Some(mem),
                Err(e) => {
                    tracing::warn!(
                        "failed to deserialize working memory for session {session_id}: {e}"
                    );
                }
            }
        }
    }

    // Build the user turn content.
    let user_content = if !req.event_id.is_empty() {
        let event = state
            .query_api
            .get_anomaly_event(&req.tenant_id, &req.event_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "anomaly event not found".to_string()))?;
        let rule = state
            .query_api
            .get_anomaly_rule(&req.tenant_id, &event.rule_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "anomaly rule not found".to_string()))?;

        let mut ctx = agent::prompt::anomaly_context(&event, &rule);
        if !req.additional_context.is_empty() {
            ctx.push_str(&format!(
                "\n\nAdditional context from the user:\n{}",
                req.additional_context
            ));
        }
        ctx
    } else if !req.question.is_empty() {
        agent::prompt::question_context(&req.question, &req.additional_context)
    } else {
        "Continue the investigation.".to_string()
    };

    if let Some(memory) = restored_memory.as_mut() {
        let transition = memory.prepare_follow_up(
            user_content.clone(),
            req.window.clone(),
            req.continue_dead_end,
        );
        tracing::info!(
            session_id,
            scope_changed = transition.scope_changed,
            window_changed = transition.window_changed,
            historical_evidence = transition.historical_evidence,
            retired_hypotheses = transition.retired_hypotheses,
            reason = %transition.reason,
            "prepared investigation follow-up state"
        );
    } else if let Some(window) = req.window.clone() {
        let mut memory = WorkingMemory::new(user_content.clone());
        memory.window = Some(window);
        restored_memory = Some(memory);
    }

    // Save user turn to DB (session mode only).
    if session_mode {
        let turn_index = state
            .query_api
            .count_turns(&req.tenant_id, &session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let turn_id = uuid::Uuid::new_v4().to_string();
        state
            .query_api
            .add_turn(
                &req.tenant_id,
                &turn_id,
                &session_id,
                turn_index,
                "user",
                &user_content,
                "[]",
                "",
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Build the message list for the LLM.
    let messages: Vec<serde_json::Value> = if is_legacy_follow_up {
        // Legacy path: client sends prior_messages
        let mut msgs = req.prior_messages.clone();
        msgs.push(serde_json::json!({
            "role": "user",
            "content": user_content,
        }));
        msgs
    } else {
        // Session-based path: reconstruct from DB
        let template = if !req.template_id.is_empty() {
            templates::get_template(&req.template_id)
        } else {
            None
        };

        // GitOps controllers enabled for this environment, derived from the same
        // env vars the tools use (set by the helm chart when argocd/fluxcd.enabled).
        let mut gitops: Vec<String> = Vec::new();
        if std::env::var("ARGOCD_NAMESPACE").is_ok() {
            gitops.push("argocd".to_string());
        }
        if std::env::var("FLUXCD_NAMESPACE").is_ok() {
            gitops.push("flux".to_string());
        }
        let mut system_content =
            agent::prompt::system_prompt(&skill_store.catalog(), &req.scopes, &gitops);

        // Append template modifier if present
        if let Some(tmpl) = template {
            system_content.push_str(&format!(
                "\n\n## INVESTIGATION TEMPLATE: {}\n{}",
                tmpl.name, tmpl.prompt_modifier
            ));
        }

        // In session mode, allow the agent to ask clarifying questions
        if !is_new_session || session_mode {
            system_content.push_str(
                "\n\n## SESSION MODE\n\
                 When investigating within a multi-turn session, you MAY ask the user a clarifying \
                 question if you encounter genuine ambiguity that would significantly change your \
                 investigation direction. Frame it as a brief question with the options you see. \
                 Prefix your question with [QUESTION] so the harness can detect it.\n\
                 Do NOT ask for confirmation of routine actions. Do NOT ask permission to use tools. \
                 Only ask when two or more investigation paths are roughly equally promising and \
                 the user's preference would save significant time.",
            );
        }

        // NOTE: restored working memory is intentionally NOT spliced into this
        // system message. Mutating message[0] every turn invalidates the LLM
        // provider's prompt-prefix cache for the whole transcript; the memory
        // block is appended as a separate trailing system message below instead.
        let system_msg = serde_json::json!({
            "role": "system",
            "content": system_content,
        });

        let mut msgs = vec![system_msg];

        // Reconstruct recent turns from DB for follow-ups
        if !is_new_session {
            let context_turns = default_context_turns();
            let recent = state
                .query_api
                .get_recent_turns(&req.tenant_id, &session_id, context_turns as i64)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            for turn in &recent {
                let role = turn.role.as_str();
                match role {
                    "user" => {
                        msgs.push(serde_json::json!({
                            "role": "user",
                            "content": turn.content,
                        }));
                    }
                    "assistant" => {
                        msgs.push(serde_json::json!({
                            "role": "assistant",
                            "content": turn.content,
                        }));
                    }
                    _ => {
                        // system turns from prior context
                        msgs.push(serde_json::json!({
                            "role": "system",
                            "content": turn.content,
                        }));
                    }
                }
            }
        }

        // Append the new user message (only if not already added from DB
        // recent turns — the DB turn was just saved and would appear in
        // get_recent_turns, but since we push it inside the loop above,
        // we skip re-adding it. However, for new sessions the user turn
        // we just saved IS the only turn, so it will appear. For
        // follow-ups, the just-saved user turn IS the latest in the DB
        // and will appear in recent turns. So we do NOT add user_content
        // again here.)
        // Actually, on second thought: we just saved the user turn to
        // the DB, and then get_recent_turns will include it. So for
        // follow-ups, the user message is already in `msgs`. For new
        // sessions, we need to make sure the first user turn is included.
        // Let's check: for new sessions, we save the turn, then call
        // get_recent_turns only for !is_new_session. For new sessions,
        // we skip the recent turns block entirely, so we DO need to add
        // the user message here for new sessions.
        if is_new_session {
            msgs.push(serde_json::json!({
                "role": "user",
                "content": user_content,
            }));
        }

        // Inject restored working memory as a SEPARATE system message at the
        // end of the restored history, just before the new user message. The
        // memory block changes every turn; keeping it at the tail leaves the
        // original system prompt + history prefix byte-identical across turns
        // so the provider's prompt cache keeps hitting.
        if let Some(ref mem) = restored_memory {
            let mem_msg = serde_json::json!({
                "role": "system",
                "content": mem.to_prompt_block(),
            });
            let is_trailing_user = msgs
                .last()
                .and_then(|m| m.get("role"))
                .and_then(|r| r.as_str())
                == Some("user");
            let insert_at = if is_trailing_user {
                msgs.len() - 1
            } else {
                msgs.len()
            };
            msgs.insert(insert_at, mem_msg);
        }

        msgs
    };

    // Set up tool registry
    let mut registry = ToolRegistry::new();
    agent::built_in::register_all(&mut registry);

    let tool_ctx = ToolContext {
        state: state.clone(),
        skill_store,
        tenant_id: req.tenant_id.clone(),
        scopes: req.scopes,
    };

    // Create a channel for SSE events
    let (tx, rx) = mpsc::channel::<AgentEvent>(64);

    // Send SessionCreated event for new sessions so frontend gets the ID
    let session_id_clone = session_id.clone();
    if is_new_session && session_mode {
        let _ = tx
            .send(AgentEvent::SessionCreated {
                session_id: session_id_clone.clone(),
            })
            .await;
    }

    // Resolve the cost-control budget for this run. Settings (set in the UI,
    // stored in config_settings) win; env vars are the fallback for
    // deployments without the settings UI; defaults otherwise. Values are
    // untrusted strings either way — LoopBudget::from_overrides clamps them.
    // Cached for 30s — saves two `config_settings FINAL` scans per request;
    // operator changes to the budget take effect within half a minute.
    const BUDGET_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
    let cached_budget = {
        let guard = state.caches.budget.read().await;
        guard
            .as_ref()
            .filter(|(read_at, _)| read_at.elapsed() < BUDGET_CACHE_TTL)
            .map(|(_, b)| *b)
    };
    let budget = match cached_budget {
        Some(b) => b,
        None => {
            let read = |key: &'static str, env: &'static str| {
                let api = state.query_api.clone();
                let tenant_id = req.tenant_id.clone();
                async move {
                    match api.get_setting(&tenant_id, key).await {
                        Ok(Some(v)) => v.trim().parse::<u32>().ok(),
                        _ => std::env::var(env)
                            .ok()
                            .and_then(|v| v.trim().parse::<u32>().ok()),
                    }
                }
            };
            let b = agent::loop_runner::LoopBudget::from_overrides(
                read("sre_agent_max_tool_steps", "SRE_AGENT_MAX_TOOL_STEPS").await,
                read("sre_agent_max_llm_calls", "SRE_AGENT_MAX_LLM_CALLS").await,
            );
            *state.caches.budget.write().await = Some((std::time::Instant::now(), b));
            b
        }
    };

    // Fail fast with a setup-oriented message when no LLM is configured.
    // otherwise the user sees a bare provider-key error mid-stream. The
    // "LLM not configured:" prefix is a stable marker the UI styles as a
    // setup card. No credential details are returned.
    if !state
        .query_api
        .llm_ready(&req.tenant_id)
        .await
        .unwrap_or(false)
    {
        state
            .metrics
            .investigation_failed(investigation_started.elapsed());
        let _ = tx
            .send(AgentEvent::Error {
                message: "LLM not configured: add a provider and at least one enabled model in \
                          Settings → AI Agent. Provider credentials stay in query-api. \
                          Telemetry browsing in the rest of the app is unaffected."
                    .to_string(),
            })
            .await;
        drop(tx);
        return Ok(Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .body(sse_body(
                rx,
                CancellationToken::new(),
                state.metrics.clone(),
            ))
            .unwrap());
    }

    // Spawn the agent loop in a background task, then persist results
    let query_api = state.query_api.clone();
    let tenant_id_for_task = req.tenant_id.clone();
    let session_id_for_task = session_id.clone();
    let session_mode_for_task = session_mode;
    let restored_mem = restored_memory;
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task_metrics = state.metrics.clone();

    // The browser selects a Rush model ID and effort. query-api validates both,
    // resolves the upstream model, and applies the matching provider secret.
    let mut llm = agent::loop_runner::LlmConfig::from_env()
        .expect("query-api transport is configured at process startup");
    if !req.model.trim().is_empty() {
        llm.model = req.model.trim().to_string();
    }
    llm.reasoning_effort = match req.reasoning_effort.trim() {
        "minimal" | "low" | "medium" | "high" => Some(req.reasoning_effort.trim().to_string()),
        _ => None,
    };

    // Capture the bounded tool trail while forwarding the same events to the
    // browser. The final report remains in the turn content column.
    let (agent_tx, mut agent_rx) = mpsc::channel::<AgentEvent>(64);
    let saved_activity = Arc::new(Mutex::new(SavedActivityLog::default()));
    let activity_for_forwarder = saved_activity.clone();
    let client_tx = tx.clone();
    let activity_forwarder = tokio::spawn(async move {
        while let Some(event) = agent_rx.recv().await {
            if let Ok(mut activity) = activity_for_forwarder.lock() {
                activity.push(&event);
            }
            if client_tx.send(event).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let _permit = permit;
        let result = agent::loop_runner::run_with_config_and_budget_cancelable(
            messages,
            &registry,
            &tool_ctx,
            &agent_tx,
            llm,
            restored_mem,
            &session_id_for_task,
            budget,
            task_cancellation.clone(),
        )
        .await;
        let was_cancelled = task_cancellation.is_cancelled();
        let succeeded = result.is_ok();

        if let Err(error) = &result {
            let _ = agent_tx
                .send(AgentEvent::Error {
                    message: error.to_string(),
                })
                .await;
        }
        drop(agent_tx);
        let _ = activity_forwarder.await;
        let saved_activity_json = saved_activity
            .lock()
            .map(|activity| activity.to_json())
            .unwrap_or_else(|_| "[]".to_string());

        if let Ok((
            summary_text,
            report_kind,
            final_memory,
            total_prompt,
            total_completion,
            llm_model_used,
        )) = result
        {
            // Persist assistant turn and updated working memory
            if session_mode_for_task {
                let turn_index = query_api
                    .count_turns(&tenant_id_for_task, &session_id_for_task)
                    .await
                    .unwrap_or(0);
                let turn_id = uuid::Uuid::new_v4().to_string();
                let kind_str = match report_kind {
                    agent::stream::ReportKind::Final => "final",
                    agent::stream::ReportKind::Preliminary => "preliminary",
                    agent::stream::ReportKind::Question => "question",
                };
                let _ = query_api
                    .add_turn(
                        &tenant_id_for_task,
                        &turn_id,
                        &session_id_for_task,
                        turn_index,
                        "assistant",
                        &summary_text,
                        &saved_activity_json,
                        kind_str,
                    )
                    .await;

                // Persist memory + accumulated tokens (+ status for final
                // reports) in one read + one versioned insert instead of
                // three read-modify-write cycles.
                let mem_json =
                    serde_json::to_string(&final_memory).unwrap_or_else(|_| "{}".to_string());
                let status = if report_kind == agent::stream::ReportKind::Final {
                    Some("completed")
                } else {
                    None
                };
                let _ = query_api
                    .update_session_after_turn(
                        &tenant_id_for_task,
                        &session_id_for_task,
                        &mem_json,
                        total_prompt,
                        total_completion,
                        &llm_model_used,
                        status,
                    )
                    .await;
            }
        }
        if was_cancelled {
            task_metrics.investigation_cancelled(investigation_started.elapsed());
        } else if succeeded {
            task_metrics.investigation_completed(investigation_started.elapsed());
        } else {
            task_metrics.investigation_failed(investigation_started.elapsed());
        }
    });

    // Convert the receiver into an SSE byte stream
    let body = sse_body(rx, cancellation, state.metrics.clone());

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(body)
        .unwrap())
}

// ── Templates endpoint ──

async fn list_investigation_templates() -> Json<serde_json::Value> {
    let templates = templates::built_in_templates();
    Json(serde_json::json!({ "templates": templates }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::contracts::ToolResultEnvelope;

    #[test]
    fn saved_activity_keeps_tool_calls_and_results_in_order() {
        let mut activity = SavedActivityLog::default();
        activity.push(&AgentEvent::ThinkingDelta {
            text: "private reasoning".to_string(),
        });
        activity.push(&AgentEvent::ToolCall {
            name: "search_logs".to_string(),
            args: serde_json::json!({"service": "checkout"}),
        });
        activity.push(&AgentEvent::ToolResult {
            name: "search_logs".to_string(),
            data: "three errors".to_string(),
            provenance: Box::new(ToolResultEnvelope::from_legacy(
                "search_logs",
                &serde_json::json!({}),
                "three errors",
                None,
            )),
        });

        let stored: Vec<serde_json::Value> = serde_json::from_str(&activity.to_json()).unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0]["type"], "tool_call");
        assert_eq!(stored[1]["type"], "tool_result");
        assert_eq!(stored[1]["data"], "three errors");
    }

    #[test]
    fn saved_activity_truncates_large_tool_results_on_char_boundaries() {
        let data = "é".repeat(MAX_SAVED_TOOL_RESULT_CHARS + 1);
        let saved = truncate_saved_tool_result(&data);
        let prefix = saved
            .strip_suffix("\n[truncated in saved session]")
            .unwrap();

        assert!(saved.ends_with("[truncated in saved session]"));
        assert!(saved.is_char_boundary(saved.len()));
        assert_eq!(prefix.chars().count(), MAX_SAVED_TOOL_RESULT_CHARS);
    }
}
