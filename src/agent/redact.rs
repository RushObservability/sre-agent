//! Best-effort credential removal before tool data reaches a model or activity log.
//! Arbitrary secrets without recognizable keys or formats cannot be detected.
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

const REDACTED: &str = "<redacted>";

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "authorization",
        "cookie",
        "privatekey",
        "credential",
        "accesskey",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

pub fn value(input: &Value) -> Value {
    match input {
        Value::Object(map) => {
            let k8s_secret = map.get("kind").and_then(Value::as_str) == Some("Secret");
            Value::Object(
                map.iter()
                    .map(|(key, item)| {
                        let item = if sensitive_key(key)
                            || (k8s_secret && matches!(key.as_str(), "data" | "stringData"))
                        {
                            Value::String(REDACTED.into())
                        } else {
                            value(item)
                        };
                        (key.clone(), item)
                    })
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(value).collect()),
        Value::String(s) => Value::String(text(s)),
        _ => input.clone(),
    }
}

pub fn text(input: &str) -> String {
    // Structured values may hold arrays/objects under a sensitive key.
    if let Ok(parsed) = serde_json::from_str::<Value>(input)
        && !parsed.is_string()
    {
        return value(&parsed).to_string();
    }
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\z)",
            r#"(?i)\b(?:authorization|proxy-authorization)\s*["']?\s*[:=]\s*["']?[^\r\n"',}]+"#,
            r#"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]+"#,
            r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@]+(?::[^\s/@]*)?@"#,
            r#"(?i)\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|cookie)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)"#,
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        ].into_iter().map(|pattern| Regex::new(pattern).expect("valid redaction pattern")).collect()
    });
    patterns.iter().fold(input.to_string(), |output, pattern| {
        pattern.replace_all(&output, REDACTED).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_credentials_and_kubernetes_secrets_are_removed() {
        let input = json!({"items": [{"password": {"nested": "dummy-password"}},
            {"kind": "Secret", "data": {"db": "dummy-base64"}}],
            "access_token": "dummy-token", "latency_ms": 42, "prompt_tokens": 20});
        let output = text(&input.to_string());
        for secret in ["dummy-password", "dummy-base64", "dummy-token"] {
            assert!(!output.contains(secret));
        }
        assert_eq!(
            serde_json::from_str::<Value>(&output).unwrap()["latency_ms"],
            42
        );
        assert_eq!(value(&input)["prompt_tokens"], 20);
    }

    #[test]
    fn text_credentials_and_multiline_keys_are_removed() {
        for input in [
            "Authorization: Bearer dummy-bearer",
            "password = 'dummy with spaces'",
            "postgres://user:dummy-uri@db/app",
            "X-Api-Key: dummy-key",
            "-----BEGIN RSA PRIVATE KEY-----\ndummy-pem\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\ndummy-truncated",
            r#"log: {"client_secret": "dummy-json"}"#,
        ] {
            assert!(!text(input).contains("dummy"), "{input}");
        }
        assert_eq!(
            text("Found 12 logs: latency=42ms"),
            "Found 12 logs: latency=42ms"
        );
    }
}
