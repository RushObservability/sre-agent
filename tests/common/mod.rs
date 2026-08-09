//! Shared integration-test infrastructure: a mock OpenAI-compatible LLM
//! server plus fixtures (fake tools, disconnected ToolContext, event
//! collection helpers).
//!
//! The mock server:
//! - replies to `POST /v1/chat/completions` with pre-scripted streaming
//!   responses (one [`Script`] entry per request, in order);
//! - records every received request body so tests can assert on what the
//!   agent loop actually sent over the wire (compaction, memory injection,
//!   tools presence/absence, …);
//! - supports a raw-chunk variant ([`Script::RawChunks`]) that streams
//!   hand-cut byte chunks for SSE-parser torture tests.

#![allow(dead_code)] // shared module — not every test file uses every helper

use axum::{Router, extract::State, response::Response, routing::post};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use sre_agent::agent::stream::AgentEvent;
use sre_agent::agent::tools::{Tool, ToolContext, ToolRegistry};

// ────────────────────────────────────────────────────────────────────────────
// Mock LLM server
// ────────────────────────────────────────────────────────────────────────────

/// A scripted response from the mock LLM. Each entry corresponds to one
/// chat/completions request.
#[derive(Debug, Clone)]
pub enum Script {
    /// Stream a single tool call (name + args) plus a usage chunk.
    ToolCall {
        name: String,
        args: Value,
        call_id: String,
    },
    /// Stream SEVERAL tool calls in one assistant response (one per index),
    /// plus a usage chunk. Each entry is `(name, args, call_id)`.
    ToolCalls(Vec<(String, Value, String)>),
    /// Stream plain final text plus a usage chunk.
    Final(String),
    /// Empty content + no tool calls — triggers the loop's parse-retry path.
    Empty,
    /// Stream these exact byte chunks, one per HTTP body frame, verbatim.
    /// For SSE-parser torture tests: split lines mid-token, mid-UTF-8, etc.
    RawChunks(Vec<Vec<u8>>),
}

#[derive(Clone)]
pub struct MockState {
    pub scripts: Arc<Mutex<Vec<Script>>>,
    pub call_count: Arc<Mutex<usize>>,
    /// Every request body received, in arrival order, for assertions.
    pub requests: Arc<Mutex<Vec<Value>>>,
}

/// Handle to a running mock LLM server.
pub struct MockServer {
    pub base_url: String,
    pub call_count: Arc<Mutex<usize>>,
    /// Request bodies received so far (parsed JSON), in arrival order.
    pub requests: Arc<Mutex<Vec<Value>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockServer {
    /// Number of chat/completions calls received so far.
    pub fn calls(&self) -> usize {
        *self.call_count.lock().unwrap()
    }

    /// Snapshot of the request bodies received so far.
    pub fn recorded_requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

async fn mock_completions(State(state): State<MockState>, body: String) -> Response {
    // Record the request body for assertions (tolerate non-JSON defensively).
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::String(body));
    state.requests.lock().unwrap().push(parsed);

    let idx = {
        let mut c = state.call_count.lock().unwrap();
        let i = *c;
        *c += 1;
        i
    };
    let scripts = state.scripts.lock().unwrap();
    let script = scripts
        .get(idx)
        .cloned()
        .unwrap_or(Script::Final("No more scripted responses".to_string()));
    drop(scripts);

    if let Script::RawChunks(chunks) = script {
        // Stream the hand-cut byte chunks verbatim, one body frame each.
        let stream = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(c))),
        );
        return Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(axum::body::Body::from_stream(stream))
            .unwrap();
    }

    // Build an OpenAI-compatible streaming chat/completions response.
    let body = build_stream_body(&script);

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from(body))
        .unwrap()
}

pub fn build_stream_body(script: &Script) -> String {
    let mut out = String::new();

    match script {
        Script::ToolCall {
            name,
            args,
            call_id,
        } => {
            // Chunk 1: tool_call with name
            let c1 = json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "id": call_id,
                            "type": "function",
                            "function": { "name": name }
                        }]
                    }
                }]
            });
            out.push_str(&format!("data: {c1}\n\n"));

            // Chunk 2: args
            let args_str = serde_json::to_string(args).unwrap();
            let c2 = json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "function": { "arguments": args_str }
                        }]
                    }
                }]
            });
            out.push_str(&format!("data: {c2}\n\n"));

            // Usage chunk
            let c3 = json!({
                "choices": [],
                "usage": { "prompt_tokens": 100, "completion_tokens": 20 }
            });
            out.push_str(&format!("data: {c3}\n\n"));
        }
        Script::ToolCalls(calls) => {
            for (idx, (name, args, call_id)) in calls.iter().enumerate() {
                // Chunk: tool_call with id + name at this index
                let c1 = json!({
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "index": idx,
                                "id": call_id,
                                "type": "function",
                                "function": { "name": name }
                            }]
                        }
                    }]
                });
                out.push_str(&format!("data: {c1}\n\n"));

                // Chunk: args for this index
                let args_str = serde_json::to_string(args).unwrap();
                let c2 = json!({
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "index": idx,
                                "function": { "arguments": args_str }
                            }]
                        }
                    }]
                });
                out.push_str(&format!("data: {c2}\n\n"));
            }

            let c3 = json!({
                "choices": [],
                "usage": { "prompt_tokens": 100, "completion_tokens": 20 }
            });
            out.push_str(&format!("data: {c3}\n\n"));
        }
        Script::Final(text) => {
            let c1 = json!({
                "choices": [{
                    "delta": { "content": text }
                }]
            });
            out.push_str(&format!("data: {c1}\n\n"));

            let c2 = json!({
                "choices": [],
                "usage": { "prompt_tokens": 100, "completion_tokens": 30 }
            });
            out.push_str(&format!("data: {c2}\n\n"));
        }
        Script::Empty => {
            let c1 = json!({
                "choices": [{ "delta": { "content": "" } }]
            });
            out.push_str(&format!("data: {c1}\n\n"));
        }
        Script::RawChunks(_) => {
            unreachable!("RawChunks is streamed directly, not via build_stream_body")
        }
    }

    out.push_str("data: [DONE]\n\n");
    out
}

/// Spawn the mock server on an ephemeral port.
pub async fn start_mock(scripts: Vec<Script>) -> MockServer {
    let call_count = Arc::new(Mutex::new(0usize));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        scripts: Arc::new(Mutex::new(scripts)),
        call_count: call_count.clone(),
        requests: requests.clone(),
    };

    let app = Router::new()
        .route("/v1/chat/completions", post(mock_completions))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to bind
    tokio::time::sleep(Duration::from_millis(10)).await;
    MockServer {
        base_url,
        call_count,
        requests,
        handle,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Test fixtures
// ────────────────────────────────────────────────────────────────────────────

/// A fake tool that returns a fixed response. Used in place of real tools
/// that would hit ClickHouse/kube.
pub struct FakeTool {
    pub name_s: &'static str,
    pub response: String,
}

#[async_trait::async_trait]
impl Tool for FakeTool {
    fn name(&self) -> &str {
        self.name_s
    }
    fn description(&self) -> &str {
        "fake tool for testing"
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {"type": "string"}
            }
        })
    }
    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> anyhow::Result<String> {
        Ok(self.response.clone())
    }
}

/// A fake tool that sleeps before returning a fixed response. Used to test
/// that parallel tool execution preserves original call order even when a
/// later call finishes first, and to widen race windows deterministically.
pub struct SleepTool {
    pub name_s: &'static str,
    pub response: String,
    pub delay_ms: u64,
}

#[async_trait::async_trait]
impl Tool for SleepTool {
    fn name(&self) -> &str {
        self.name_s
    }
    fn description(&self) -> &str {
        "fake sleeping tool for testing"
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {"type": "string"}
            }
        })
    }
    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> anyhow::Result<String> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        Ok(self.response.clone())
    }
}

/// Build a ToolContext with NO live backends: the ClickHouse client and the
/// ConfigDb both point at an unroutable port, so any accidental query fails
/// fast instead of hanging. Skill loading tolerates the failure (falls back
/// to built-ins), so this works in plain `cargo test` with no infrastructure.
pub async fn make_ctx() -> ToolContext {
    let ch = clickhouse::Client::default().with_url("http://127.0.0.1:1");
    let config_db = Arc::new(sre_agent::config_db::ConfigDb::new_disconnected_for_tests());
    let skill_store = Arc::new(sre_agent::agent::skill_store::SkillStore::load(&config_db).await);
    ToolContext {
        state: sre_agent::AppState {
            ch,
            config_db,
            query_api_url: None,
            internal_auth_token: "test-not-an-http-server".to_string(),
            caches: Arc::new(Default::default()),
            metrics: Arc::new(sre_agent::metrics::AgentMetrics::new()),
            admission: Arc::new(sre_agent::state::InvestigationAdmission::new(
                4,
                16,
                Arc::new(sre_agent::metrics::AgentMetrics::new()),
            )),
        },
        skill_store,
        tenant_id: "default".to_string(),
        scopes: vec!["all".to_string()],
    }
}

pub fn make_registry(tools: Vec<(&'static str, String)>) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    for (name, response) in tools {
        r.register(Arc::new(FakeTool {
            name_s: name,
            response,
        }));
    }
    r
}

pub fn initial_messages(user_msg: &str) -> Vec<Value> {
    vec![
        json!({"role": "system", "content": "You are a test agent."}),
        json!({"role": "user", "content": user_msg}),
    ]
}

/// Count messages in a recorded request body with the given role whose
/// content contains `needle`. Useful for asserting on gate gap messages,
/// retry notices, and the self-review critique in what the loop actually
/// sent over the wire.
pub fn count_messages_containing(request: &serde_json::Value, role: &str, needle: &str) -> usize {
    request
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|msgs| {
            msgs.iter()
                .filter(|m| {
                    m.get("role").and_then(|r| r.as_str()) == Some(role)
                        && m.get("content")
                            .and_then(|c| c.as_str())
                            .is_some_and(|c| c.contains(needle))
                })
                .count()
        })
        .unwrap_or(0)
}

pub async fn collect_events(rx: &mut mpsc::Receiver<AgentEvent>) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    while let Some(e) = rx.recv().await {
        out.push(e);
    }
    out
}
