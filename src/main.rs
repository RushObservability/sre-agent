use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::Response,
    routing::{delete, get, post},
};
use clickhouse::Client;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use sre_agent::state::probe_row_policy_support;
use sre_agent::agent::memory::WorkingMemory;
use sre_agent::agent::skill_store::SkillStore;
use sre_agent::agent::stream::AgentEvent;
use sre_agent::agent::templates;
use sre_agent::agent::tools::{ToolContext, ToolRegistry};
use sre_agent::config_db::ConfigDb;
use sre_agent::{AppState, agent};

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
    /// Tenant ID for multi-tenant ClickHouse query scoping.
    #[serde(default = "default_tenant")]
    tenant_id: String,
    /// Scopes the caller has access to.
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    /// Template ID for new sessions. Ignored on follow-ups.
    #[serde(default)]
    template_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("sre_agent=debug,tower_http=debug")),
        )
        .init();

    let clickhouse_url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    let clickhouse_db =
        std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "observability".to_string());
    let clickhouse_user =
        std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_string());
    let clickhouse_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();

    let ch = Client::default()
        .with_url(&clickhouse_url)
        .with_database(&clickhouse_db)
        .with_user(&clickhouse_user)
        .with_password(&clickhouse_password)
        .with_option("max_execution_time", "30");

    probe_row_policy_support(&ch).await;

    // ConfigDb uses the session-default database (`default`), matching query-api —
    // config_* tables live there, not in `observability` (which holds telemetry data).
    let config_db = Arc::new(
        ConfigDb::open(
            &clickhouse_url,
            &clickhouse_user,
            &clickhouse_password,
        )
        .await?,
    );
    tracing::info!(
        "sre-agent config db opened against ClickHouse at {clickhouse_url} (config tables in default database)"
    );

    // Optional: URL of the query-api used to fetch custom skills.
    let query_api_url = std::env::var("QUERY_API_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    if let Some(url) = &query_api_url {
        tracing::info!("sre-agent will fetch custom skills from query-api at {url}");
    } else {
        tracing::info!("QUERY_API_URL not set; custom skills will read from local config_db");
    }

    let state = AppState {
        ch,
        config_db,
        query_api_url,
    };

    let port: u16 = std::env::var("SRE_AGENT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8081);

    let app = Router::new()
        .route("/api/v1/investigate", post(investigate))
        // Session management
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/sessions/{id}", get(get_session))
        .route("/api/v1/sessions/{id}", delete(delete_session))
        // Templates
        .route(
            "/api/v1/investigation-templates",
            get(list_investigation_templates),
        )
        .route("/healthz", get(healthz))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("sre-agent listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
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

    // Build the unified skill store (fresh per request).
    let skill_store =
        Arc::new(SkillStore::load_unified(&state.config_db, state.query_api_url.as_deref()).await);

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
            .config_db
            .create_session(&session_id, &req.tenant_id, &auto_title, "", &req.template_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else if !is_new_session && session_mode {
        // Load session from DB and verify tenant
        let session = state
            .config_db
            .get_session(&session_id)
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
                .config_db
                .update_session_status(&session_id, "active")
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        // Deserialize persisted working memory
        if session.working_memory != "{}" && !session.working_memory.is_empty() {
            match serde_json::from_str::<WorkingMemory>(&session.working_memory) {
                Ok(mem) => restored_memory = Some(mem),
                Err(e) => {
                    tracing::warn!("failed to deserialize working memory for session {session_id}: {e}");
                }
            }
        }
    }

    // Build the user turn content.
    let user_content = if !req.event_id.is_empty() {
        let event = state
            .config_db
            .get_anomaly_event(&req.event_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "anomaly event not found".to_string()))?;
        let rule = state
            .config_db
            .get_anomaly_rule(&event.rule_id)
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

    // Save user turn to DB (session mode only).
    if session_mode {
        let turn_index = state
            .config_db
            .count_turns(&session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let turn_id = uuid::Uuid::new_v4().to_string();
        state
            .config_db
            .add_turn(
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

        let mut system_content = agent::prompt::system_prompt(&skill_store.catalog(), &req.scopes);

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

        // Inject working memory block into system prompt if present
        if let Some(ref mem) = restored_memory {
            system_content.push_str(&format!("\n\n{}", mem.to_prompt_block()));
        }

        let system_msg = serde_json::json!({
            "role": "system",
            "content": system_content,
        });

        let mut msgs = vec![system_msg];

        // Reconstruct recent turns from DB for follow-ups
        if !is_new_session {
            let context_turns = default_context_turns();
            let recent = state
                .config_db
                .get_recent_turns(&session_id, context_turns as i64)
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

        msgs
    };

    // Set up tool registry
    let mut registry = ToolRegistry::new();
    agent::built_in::register_all(&mut registry);

    let tool_ctx = ToolContext {
        state: state.clone(),
        skill_store,
        tenant_id: req.tenant_id,
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

    // Spawn the agent loop in a background task, then persist results
    let config_db = state.config_db.clone();
    let session_id_for_task = session_id.clone();
    let session_mode_for_task = session_mode;
    let restored_mem = restored_memory;
    tokio::spawn(async move {
        let result =
            agent::loop_runner::run_with_session(messages, &registry, &tool_ctx, &tx, restored_mem, &session_id_for_task)
                .await;

        match result {
            Ok((summary_text, report_kind, final_memory, total_prompt, total_completion, llm_model_used)) => {
                // Persist assistant turn and updated working memory
                if session_mode_for_task {
                    let turn_index = config_db
                        .count_turns(&session_id_for_task)
                        .await
                        .unwrap_or(0);
                    let turn_id = uuid::Uuid::new_v4().to_string();
                    let kind_str = match report_kind {
                        agent::stream::ReportKind::Final => "final",
                        agent::stream::ReportKind::Preliminary => "preliminary",
                        agent::stream::ReportKind::Question => "question",
                    };
                    let _ = config_db
                        .add_turn(
                            &turn_id,
                            &session_id_for_task,
                            turn_index,
                            "assistant",
                            &summary_text,
                            "[]", // tool_calls summary omitted for now
                            kind_str,
                        )
                        .await;

                    // Serialize and persist working memory
                    if let Ok(mem_json) = serde_json::to_string(&final_memory) {
                        let _ = config_db
                            .update_session_memory(&session_id_for_task, &mem_json)
                            .await;
                    }

                    // Accumulate token usage
                    let _ = config_db
                        .update_session_tokens(
                            &session_id_for_task,
                            total_prompt,
                            total_completion,
                            &llm_model_used,
                        )
                        .await;

                    // If the report is final, mark session completed
                    if report_kind == agent::stream::ReportKind::Final {
                        let _ = config_db
                            .update_session_status(&session_id_for_task, "completed")
                            .await;
                    }
                }
            }
            Err(e) => {
                let _ = tx
                    .send(AgentEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        }
    });

    // Convert the receiver into an SSE byte stream
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body_stream = futures_util::StreamExt::map(stream, |event| {
        Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(event.to_sse_bytes()))
    });

    let body = Body::from_stream(body_stream);

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(body)
        .unwrap())
}

// ── Session API endpoints ──

#[derive(Debug, Deserialize)]
struct ListSessionsQuery {
    #[serde(default = "default_tenant")]
    tenant_id: String,
    #[serde(default = "default_session_limit")]
    limit: i64,
}

fn default_session_limit() -> i64 {
    50
}

async fn list_sessions(
    State(state): State<AppState>,
    Query(params): Query<ListSessionsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sessions = state
        .config_db
        .list_sessions(&params.tenant_id, params.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return sessions without working_memory to reduce payload
    let slim: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "tenant_id": s.tenant_id,
                "title": s.title,
                "status": s.status,
                "template_id": s.template_id,
                "created_by": s.created_by,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
                "prompt_tokens": s.prompt_tokens,
                "completion_tokens": s.completion_tokens,
                "llm_model": s.llm_model,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "sessions": slim })))
}

async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let session = state
        .config_db
        .get_session(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "session not found".to_string()))?;

    let turns = state
        .config_db
        .get_turns(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "session": {
            "id": session.id,
            "tenant_id": session.tenant_id,
            "title": session.title,
            "status": session.status,
            "template_id": session.template_id,
            "created_by": session.created_by,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "prompt_tokens": session.prompt_tokens,
            "completion_tokens": session.completion_tokens,
            "llm_model": session.llm_model,
        },
        "turns": turns,
    })))
}

async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Soft-delete: archive instead of hard delete
    state
        .config_db
        .update_session_status(&id, "archived")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Templates endpoint ──

async fn list_investigation_templates() -> Json<serde_json::Value> {
    let templates = templates::built_in_templates();
    Json(serde_json::json!({ "templates": templates }))
}
