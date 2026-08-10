use serde::Serialize;

use crate::agent::contracts::ToolResultEnvelope;

/// Whether an investigation report is a final root-cause analysis, a
/// preliminary set of findings with open questions, or a clarifying
/// question the agent is posing back to the user.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportKind {
    Final,
    Preliminary,
    Question,
}

/// Events sent over the SSE stream during an investigation.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum AgentEvent {
    #[serde(rename = "thinking_delta")]
    ThinkingDelta { text: String },
    #[serde(rename = "tool_call")]
    ToolCall {
        name: String,
        args: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        name: String,
        data: String,
        provenance: Box<ToolResultEnvelope>,
    },
    #[serde(rename = "summary")]
    Summary {
        text: String,
        #[serde(rename = "kind")]
        kind: ReportKind,
    },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "session_created")]
    SessionCreated { session_id: String },
    #[serde(rename = "done")]
    Done {
        rounds: u32,
        tool_calls: u32,
        prompt_tokens: u64,
        completion_tokens: u64,
        session_id: String,
        model: String,
    },
}

impl AgentEvent {
    /// Format as an SSE frame: `data: {json}\n\n`
    pub fn to_sse_bytes(&self) -> Vec<u8> {
        let json = serde_json::to_string(self).unwrap_or_default();
        format!("data: {json}\n\n").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn as_string(event: AgentEvent) -> String {
        String::from_utf8(event.to_sse_bytes()).unwrap()
    }

    #[test]
    fn sse_frame_has_prefix_and_double_newline() {
        let out = as_string(AgentEvent::ThinkingDelta { text: "hi".into() });
        assert!(out.starts_with("data: "));
        assert!(out.ends_with("\n\n"));
    }

    #[test]
    fn thinking_delta_serializes() {
        let out = as_string(AgentEvent::ThinkingDelta {
            text: "hello".into(),
        });
        assert!(out.contains(r#""type":"thinking_delta""#));
        assert!(out.contains(r#""text":"hello""#));
    }

    #[test]
    fn tool_call_serializes_args_as_object() {
        let out = as_string(AgentEvent::ToolCall {
            name: "search_logs".into(),
            args: json!({"service": "api"}),
        });
        assert!(out.contains(r#""type":"tool_call""#));
        assert!(out.contains(r#""name":"search_logs""#));
        assert!(out.contains(r#""service":"api""#));
    }

    #[test]
    fn tool_result_serializes() {
        let out = as_string(AgentEvent::ToolResult {
            name: "search_logs".into(),
            data: "Found 10 logs".into(),
            provenance: Box::new(ToolResultEnvelope::from_legacy(
                "search_logs",
                &json!({}),
                "Found 10 logs",
                None,
            )),
        });
        assert!(out.contains(r#""type":"tool_result""#));
        assert!(out.contains("Found 10 logs"));
    }

    #[test]
    fn done_includes_counts() {
        let out = as_string(AgentEvent::Done {
            rounds: 5,
            tool_calls: 5,
            prompt_tokens: 1000,
            completion_tokens: 500,
            session_id: "sess_abc".into(),
            model: "test-model".into(),
        });
        assert!(out.contains(r#""type":"done""#));
        assert!(out.contains(r#""rounds":5"#));
        assert!(out.contains(r#""prompt_tokens":1000"#));
        assert!(out.contains(r#""completion_tokens":500"#));
        assert!(out.contains(r#""session_id":"sess_abc""#));
    }

    #[test]
    fn error_event() {
        let out = as_string(AgentEvent::Error {
            message: "LLM failed".into(),
        });
        assert!(out.contains(r#""type":"error""#));
        assert!(out.contains("LLM failed"));
    }

    #[test]
    fn summary_event() {
        let out = as_string(AgentEvent::Summary {
            text: "## Root Cause\nfoo".into(),
            kind: ReportKind::Final,
        });
        assert!(out.contains(r#""type":"summary""#));
        assert!(out.contains(r#""kind":"final""#));
    }

    #[test]
    fn summary_event_preliminary_serializes_kind() {
        let out = as_string(AgentEvent::Summary {
            text: "## Preliminary Findings".into(),
            kind: ReportKind::Preliminary,
        });
        assert!(out.contains(r#""kind":"preliminary""#));
    }

    #[test]
    fn summary_event_question_serializes_kind() {
        let out = as_string(AgentEvent::Summary {
            text: "Which service should I investigate first?".into(),
            kind: ReportKind::Question,
        });
        assert!(out.contains(r#""kind":"question""#));
    }

    #[test]
    fn session_created_event() {
        let out = as_string(AgentEvent::SessionCreated {
            session_id: "sess_xyz".into(),
        });
        assert!(out.contains(r#""type":"session_created""#));
        assert!(out.contains(r#""session_id":"sess_xyz""#));
    }
}
