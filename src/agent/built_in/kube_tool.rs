use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use kube::api::DynamicObject;
use kube::discovery::ApiResource;
use kube::{Api, Client, api::ListParams};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const TENANT_NAMESPACES_ENV: &str = "SRE_AGENT_KUBE_TENANT_NAMESPACES";
const CLUSTER_SCOPE_ENV: &str = "SRE_AGENT_KUBE_ALLOW_CLUSTER_SCOPED";

/// Parse the tenant-to-namespace allowlist. The value is a JSON object such
/// as `{ "tenant-a": ["payments"], "*": ["shared-observability"] }`.
/// Invalid or missing policy is deliberately treated as deny-all.
fn parse_namespace_policy(raw: Option<&str>) -> Option<HashMap<String, HashSet<String>>> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed: HashMap<String, Vec<String>> = serde_json::from_str(raw).ok()?;
    let policy = parsed
        .into_iter()
        .map(|(tenant, namespaces)| {
            (
                tenant,
                namespaces
                    .into_iter()
                    .map(|namespace| namespace.trim().to_string())
                    .filter(|namespace| !namespace.is_empty())
                    .collect(),
            )
        })
        .collect::<HashMap<_, _>>();
    Some(policy)
}

fn namespace_allowed_for(raw: Option<&str>, tenant_id: &str, namespace: &str) -> bool {
    let Some(policy) = parse_namespace_policy(raw) else {
        return false;
    };
    policy
        .get(tenant_id)
        .or_else(|| policy.get("*"))
        .is_some_and(|namespaces| namespaces.contains(namespace))
}

fn namespace_allowed(ctx: &ToolContext, namespace: &str) -> bool {
    namespace_allowed_for(
        std::env::var(TENANT_NAMESPACES_ENV).ok().as_deref(),
        &ctx.tenant_id,
        namespace,
    )
}

fn cluster_scope_allowed(ctx: &ToolContext) -> bool {
    let enabled = std::env::var(CLUSTER_SCOPE_ENV)
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    cluster_scope_allowed_for(&ctx.scopes, enabled)
}

fn cluster_scope_allowed_for(scopes: &[String], enabled: bool) -> bool {
    enabled && scopes.iter().any(|scope| scope == "kube_cluster")
}

fn namespace_denied(namespace: &str) -> String {
    format!("Access to Kubernetes namespace '{namespace}' is not allowed for this tenant.")
}

/// Process-wide Kubernetes client, built once on first use. The kubeconfig /
/// in-cluster service account doesn't change at runtime, so rebuilding the
/// client (config discovery + connection setup) on every tool call is pure
/// overhead. `kube::Client` is cheaply cloneable. Failures are NOT cached —
/// `get_or_try_init` leaves the cell empty so the next call retries.
pub(crate) async fn shared_kube_client() -> Result<Client, kube::Error> {
    static KUBE_CLIENT: tokio::sync::OnceCell<Client> = tokio::sync::OnceCell::const_new();
    KUBE_CLIENT
        .get_or_try_init(|| async { Client::try_default().await })
        .await
        .cloned()
}

pub struct KubeDescribe;

#[async_trait::async_trait]
impl Tool for KubeDescribe {
    fn name(&self) -> &str {
        "kube_describe"
    }

    fn description(&self) -> &str {
        "Describe a Kubernetes resource to see its full status, conditions, events, and configuration. \
         Supports pods, deployments, replicasets, services, events, configmaps, nodes, jobs, and more. \
         Use this to debug why a pod is failing, a deployment is stuck, or a resource is unhealthy."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["kind", "name"],
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "Kubernetes resource kind: pod, deployment, replicaset, service, event, configmap, node, job, statefulset, daemonset, ingress, hpa, pvc"
                },
                "name": {
                    "type": "string",
                    "description": "Resource name. Use '*' to list all resources of this kind in the namespace."
                },
                "namespace": {
                    "type": "string",
                    "description": "Namespace (required for namespaced resources). Omit for cluster-scoped resources like nodes."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let kind = args
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("pod")
            .to_lowercase();
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let namespace = args.get("namespace").and_then(|v| v.as_str()).unwrap_or("");

        if name.is_empty() {
            return Ok("'name' is required. Use '*' to list all resources.".to_string());
        }

        let (api_group, api_version, plural) = match kind.as_str() {
            "pod" | "pods" => ("", "v1", "pods"),
            "service" | "svc" | "services" => ("", "v1", "services"),
            "configmap" | "cm" | "configmaps" => ("", "v1", "configmaps"),
            "event" | "events" => ("", "v1", "events"),
            "node" | "nodes" => ("", "v1", "nodes"),
            "namespace" | "ns" | "namespaces" => ("", "v1", "namespaces"),
            "pvc" | "persistentvolumeclaim" | "persistentvolumeclaims" => {
                ("", "v1", "persistentvolumeclaims")
            }
            "sa" | "serviceaccount" | "serviceaccounts" => ("", "v1", "serviceaccounts"),
            "endpoint" | "endpoints" => ("", "v1", "endpoints"),
            "deployment" | "deploy" | "deployments" => ("apps", "v1", "deployments"),
            "replicaset" | "rs" | "replicasets" => ("apps", "v1", "replicasets"),
            "statefulset" | "sts" | "statefulsets" => ("apps", "v1", "statefulsets"),
            "daemonset" | "ds" | "daemonsets" => ("apps", "v1", "daemonsets"),
            "job" | "jobs" => ("batch", "v1", "jobs"),
            "cronjob" | "cj" | "cronjobs" => ("batch", "v1", "cronjobs"),
            "ingress" | "ing" | "ingresses" => ("networking.k8s.io", "v1", "ingresses"),
            "hpa" | "horizontalpodautoscaler" => ("autoscaling", "v2", "horizontalpodautoscalers"),
            _ => {
                return Ok(format!(
                    "Unknown resource kind: '{kind}'. Supported: pod, deployment, replicaset, service, event, configmap, node, job, statefulset, daemonset, ingress, hpa, pvc"
                ));
            }
        };

        let ar = ApiResource {
            group: api_group.into(),
            version: api_version.into(),
            kind: kind.clone(),
            api_version: if api_group.is_empty() {
                api_version.into()
            } else {
                format!("{api_group}/{api_version}")
            },
            plural: plural.into(),
        };

        let is_cluster_scoped = matches!(
            kind.as_str(),
            "node" | "nodes" | "namespace" | "ns" | "namespaces"
        );

        if is_cluster_scoped {
            if !cluster_scope_allowed(ctx) {
                return Ok(
                    "Cluster-scoped Kubernetes reads are restricted to administrators and must be explicitly enabled."
                        .to_string(),
                );
            }
        } else {
            if namespace.is_empty() {
                return Ok(format!("'namespace' is required for {kind} resources."));
            }
            if !namespace_allowed(ctx, namespace) {
                return Ok(namespace_denied(namespace));
            }
        }

        // Resolve the client only after the tenant and scope checks. Denied
        // requests must not even attempt a Kubernetes connection.
        let client = match shared_kube_client().await {
            Ok(c) => c,
            Err(e) => return Ok(format!("Cannot connect to Kubernetes: {e}")),
        };

        // List mode
        if name == "*" {
            let api: Api<DynamicObject> = if is_cluster_scoped || namespace.is_empty() {
                Api::all_with(client, &ar)
            } else {
                Api::namespaced_with(client, namespace, &ar)
            };

            let list = match api.list(&ListParams::default()).await {
                Ok(l) => l,
                Err(e) => return Ok(format!("Failed to list {plural}: {e}")),
            };

            if list.items.is_empty() {
                return Ok(format!(
                    "No {plural} found{}",
                    if !namespace.is_empty() {
                        format!(" in namespace '{namespace}'")
                    } else {
                        String::new()
                    }
                ));
            }

            let mut out = format!(
                "Found {} {plural}{}:\n",
                list.items.len(),
                if !namespace.is_empty() {
                    format!(" in {namespace}")
                } else {
                    String::new()
                }
            );
            for obj in &list.items {
                let n = obj.metadata.name.as_deref().unwrap_or("?");
                let ns = obj.metadata.namespace.as_deref().unwrap_or("");
                // Try to extract status info
                let phase = obj
                    .data
                    .pointer("/status/phase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let ready = extract_ready_status(&obj.data);
                let age = extract_age(&obj.metadata);
                out.push_str(&format!("  {n}"));
                if !ns.is_empty() {
                    out.push_str(&format!("  (ns: {ns})"));
                }
                if !phase.is_empty() {
                    out.push_str(&format!("  {phase}"));
                }
                if !ready.is_empty() {
                    out.push_str(&format!("  {ready}"));
                }
                if !age.is_empty() {
                    out.push_str(&format!("  age: {age}"));
                }
                out.push('\n');
            }
            return Ok(out);
        }

        // Get single resource
        let api: Api<DynamicObject> = if is_cluster_scoped {
            Api::all_with(client.clone(), &ar)
        } else if namespace.is_empty() {
            return Ok(format!("'namespace' is required for {kind} resources."));
        } else {
            Api::namespaced_with(client.clone(), namespace, &ar)
        };

        let obj = match api.get(name).await {
            Ok(o) => o,
            Err(e) => {
                return Ok(format!(
                    "{kind} '{name}' not found{}: {e}",
                    if !namespace.is_empty() {
                        format!(" in namespace '{namespace}'")
                    } else {
                        String::new()
                    }
                ));
            }
        };

        let mut out = format!("{kind}/{name}");
        if !namespace.is_empty() {
            out.push_str(&format!(" (namespace: {namespace})"));
        }
        out.push('\n');

        // Format based on resource type
        match kind.as_str() {
            "pod" | "pods" => format_pod(&obj.data, &mut out),
            "deployment" | "deploy" | "deployments" => format_deployment(&obj.data, &mut out),
            "event" | "events" => {
                // If asking for a specific event, show it. But usually you want events for a resource.
                // Let's also fetch events in the namespace
                format_generic(&obj.data, &mut out);
            }
            _ => format_generic(&obj.data, &mut out),
        }

        // Also fetch events for this resource
        if !is_cluster_scoped
            && !namespace.is_empty()
            && !matches!(kind.as_str(), "event" | "events")
        {
            let events_ar = ApiResource {
                group: String::new(),
                version: "v1".into(),
                kind: "Event".into(),
                api_version: "v1".into(),
                plural: "events".into(),
            };
            let events_api: Api<DynamicObject> =
                Api::namespaced_with(client, namespace, &events_ar);
            if let Ok(event_list) = events_api.list(&ListParams::default()).await {
                let related: Vec<_> = event_list
                    .items
                    .iter()
                    .filter(|e| {
                        let involved = &e.data["involvedObject"];
                        involved["name"].as_str() == Some(name)
                    })
                    .collect();
                if !related.is_empty() {
                    out.push_str(&format!("\nEvents ({}):\n", related.len()));
                    for ev in related.iter().rev().take(15) {
                        let reason = ev.data["reason"].as_str().unwrap_or("?");
                        let msg = ev.data["message"].as_str().unwrap_or("");
                        let etype = ev.data["type"].as_str().unwrap_or("Normal");
                        let count = ev.data["count"].as_u64().unwrap_or(1);
                        let last = ev.data["lastTimestamp"].as_str().unwrap_or("");
                        out.push_str(&format!("  [{etype}] {reason}"));
                        if count > 1 {
                            out.push_str(&format!(" (x{count})"));
                        }
                        out.push_str(&format!(": {msg}"));
                        if !last.is_empty() {
                            out.push_str(&format!("  ({last})"));
                        }
                        out.push('\n');
                    }
                }
            }
        }

        Ok(out)
    }
}

/// Tool to list events in a namespace, optionally filtered by involved object
pub struct KubeEvents;

#[async_trait::async_trait]
impl Tool for KubeEvents {
    fn name(&self) -> &str {
        "kube_events"
    }

    fn description(&self) -> &str {
        "List Kubernetes events in a namespace. Events reveal why pods fail, deployments stall, \
         or resources are unhealthy. Filter by resource name to see events for a specific pod or deployment."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["namespace"],
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to get events from"
                },
                "resource_name": {
                    "type": "string",
                    "description": "Optional: filter events to those involving this resource name"
                },
                "warnings_only": {
                    "type": "boolean",
                    "description": "Only show Warning events (default: false)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let namespace = args.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
        let resource_name = args
            .get("resource_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let warnings_only = args
            .get("warnings_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if namespace.is_empty() {
            return Ok("'namespace' is required.".to_string());
        }
        if !namespace_allowed(ctx, namespace) {
            return Ok(namespace_denied(namespace));
        }

        let client = match shared_kube_client().await {
            Ok(c) => c,
            Err(e) => return Ok(format!("Cannot connect to Kubernetes: {e}")),
        };

        let ar = ApiResource {
            group: String::new(),
            version: "v1".into(),
            kind: "Event".into(),
            api_version: "v1".into(),
            plural: "events".into(),
        };

        let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
        let list = match api.list(&ListParams::default()).await {
            Ok(l) => l,
            Err(e) => return Ok(format!("Failed to list events: {e}")),
        };

        let mut events: Vec<&DynamicObject> = list
            .items
            .iter()
            .filter(|e| {
                if !resource_name.is_empty() {
                    let name_match =
                        e.data["involvedObject"]["name"].as_str() == Some(resource_name);
                    if !name_match {
                        return false;
                    }
                }
                if warnings_only {
                    return e.data["type"].as_str() == Some("Warning");
                }
                true
            })
            .collect();

        // Sort by lastTimestamp descending
        events.sort_by(|a, b| {
            let ta = a.data["lastTimestamp"].as_str().unwrap_or("");
            let tb = b.data["lastTimestamp"].as_str().unwrap_or("");
            tb.cmp(ta)
        });

        if events.is_empty() {
            return Ok(format!(
                "No events found in namespace '{namespace}'{}",
                if !resource_name.is_empty() {
                    format!(" for '{resource_name}'")
                } else {
                    String::new()
                }
            ));
        }

        let mut out = format!("Events in {namespace}");
        if !resource_name.is_empty() {
            out.push_str(&format!(" for '{resource_name}'"));
        }
        out.push_str(&format!(" ({} events):\n", events.len().min(30)));

        for ev in events.iter().take(30) {
            let reason = ev.data["reason"].as_str().unwrap_or("?");
            let msg = ev.data["message"].as_str().unwrap_or("");
            let etype = ev.data["type"].as_str().unwrap_or("Normal");
            let count = ev.data["count"].as_u64().unwrap_or(1);
            let last = ev.data["lastTimestamp"].as_str().unwrap_or("");
            let obj_kind = ev.data["involvedObject"]["kind"].as_str().unwrap_or("");
            let obj_name = ev.data["involvedObject"]["name"].as_str().unwrap_or("");

            out.push_str(&format!("  [{etype}] {obj_kind}/{obj_name}: {reason}"));
            if count > 1 {
                out.push_str(&format!(" (x{count})"));
            }
            if !msg.is_empty() {
                out.push_str(&format!(
                    " — {}",
                    if msg.len() > 200 { &msg[..200] } else { msg }
                ));
            }
            if !last.is_empty() {
                out.push_str(&format!("  ({last})"));
            }
            out.push('\n');
        }

        Ok(out)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::{cluster_scope_allowed_for, namespace_allowed_for, parse_namespace_policy};

    #[test]
    fn tenant_namespace_policy_is_exact_and_supports_shared_namespaces() {
        let raw = r#"{"tenant-a":["payments"],"*":["shared-observability"]}"#;
        assert!(namespace_allowed_for(Some(raw), "tenant-a", "payments"));
        assert!(!namespace_allowed_for(Some(raw), "tenant-a", "other"));
        assert!(namespace_allowed_for(
            Some(raw),
            "tenant-b",
            "shared-observability"
        ));
    }

    #[test]
    fn malformed_or_missing_policy_denies() {
        assert!(parse_namespace_policy(None).is_none());
        assert!(!namespace_allowed_for(
            Some("not-json"),
            "tenant-a",
            "payments"
        ));
    }

    #[test]
    fn cluster_scope_requires_the_admin_switch_and_scope() {
        assert!(!cluster_scope_allowed_for(&["all".to_string()], true));
        assert!(!cluster_scope_allowed_for(
            &["kube_cluster".to_string()],
            false
        ));
        assert!(cluster_scope_allowed_for(
            &["all".to_string(), "kube_cluster".to_string()],
            true
        ));
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn extract_ready_status(data: &Value) -> String {
    if let Some(conditions) = data
        .pointer("/status/conditions")
        .and_then(|v| v.as_array())
    {
        for c in conditions {
            if c["type"].as_str() == Some("Ready") {
                let status = c["status"].as_str().unwrap_or("?");
                return format!("Ready={status}");
            }
        }
    }
    // For deployments: ready/total replicas
    if let (Some(ready), Some(desired)) = (
        data.pointer("/status/readyReplicas")
            .and_then(|v| v.as_u64()),
        data.pointer("/status/replicas").and_then(|v| v.as_u64()),
    ) {
        return format!("{ready}/{desired} ready");
    }
    String::new()
}

fn extract_age(meta: &kube::api::ObjectMeta) -> String {
    if let Some(ts) = &meta.creation_timestamp {
        // Compare epoch seconds rather than the wrapped datetime value.
        // k8s-openapi 0.28 changed Time's inner type from chrono::DateTime to
        // jiff::Timestamp; going through seconds keeps this independent of
        // whichever time crate k8s-openapi wraps, and jiff is not a direct
        // dependency of ours.
        let secs = chrono::Utc::now().timestamp() - ts.0.as_second();
        if secs >= 86_400 {
            return format!("{}d", secs / 86_400);
        }
        if secs >= 3_600 {
            return format!("{}h", secs / 3_600);
        }
        if secs >= 60 {
            return format!("{}m", secs / 60);
        }
        return format!("{secs}s");
    }
    String::new()
}

fn format_pod(data: &Value, out: &mut String) {
    let status = &data["status"];
    let spec = &data["spec"];
    let phase = status["phase"].as_str().unwrap_or("Unknown");

    out.push_str(&format!("Phase: {phase}\n"));

    // Node
    if let Some(node) = spec["nodeName"].as_str() {
        out.push_str(&format!("Node: {node}\n"));
    }

    // Container statuses
    if let Some(containers) = status["containerStatuses"].as_array() {
        out.push_str(&format!("\nContainers ({}):\n", containers.len()));
        for c in containers {
            let name = c["name"].as_str().unwrap_or("?");
            let ready = c["ready"].as_bool().unwrap_or(false);
            let restarts = c["restartCount"].as_u64().unwrap_or(0);
            let image = c["image"].as_str().unwrap_or("?");

            out.push_str(&format!(
                "  {name}: ready={ready} restarts={restarts} image={image}\n"
            ));

            // Waiting state (most important for debugging)
            if let Some(waiting) = c["state"]["waiting"].as_object() {
                let reason = waiting
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let msg = waiting
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                out.push_str(&format!("    WAITING: {reason}"));
                if !msg.is_empty() {
                    out.push_str(&format!(
                        " — {}",
                        if msg.len() > 300 { &msg[..300] } else { msg }
                    ));
                }
                out.push('\n');
            }

            // Terminated state
            if let Some(terminated) = c["state"]["terminated"].as_object() {
                let reason = terminated
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let exit_code = terminated
                    .get("exitCode")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(-1);
                out.push_str(&format!(
                    "    TERMINATED: {reason} (exit code: {exit_code})\n"
                ));
            }

            // Last terminated (for crash loops)
            if let Some(last) = c["lastState"]["terminated"].as_object() {
                let reason = last.get("reason").and_then(|v| v.as_str()).unwrap_or("?");
                let exit_code = last.get("exitCode").and_then(|v| v.as_i64()).unwrap_or(-1);
                out.push_str(&format!(
                    "    LAST TERMINATED: {reason} (exit code: {exit_code})\n"
                ));
            }
        }
    }

    // Conditions
    if let Some(conditions) = status["conditions"].as_array() {
        let non_true: Vec<_> = conditions
            .iter()
            .filter(|c| c["status"].as_str() != Some("True"))
            .collect();
        if !non_true.is_empty() {
            out.push_str("\nFailing Conditions:\n");
            for c in non_true {
                let ctype = c["type"].as_str().unwrap_or("?");
                let reason = c["reason"].as_str().unwrap_or("");
                let msg = c["message"].as_str().unwrap_or("");
                out.push_str(&format!("  {ctype}: {reason}"));
                if !msg.is_empty() {
                    out.push_str(&format!(" — {msg}"));
                }
                out.push('\n');
            }
        }
    }
}

fn format_deployment(data: &Value, out: &mut String) {
    let status = &data["status"];
    let spec = &data["spec"];

    let replicas = spec["replicas"].as_u64().unwrap_or(0);
    let ready = status["readyReplicas"].as_u64().unwrap_or(0);
    let available = status["availableReplicas"].as_u64().unwrap_or(0);
    let updated = status["updatedReplicas"].as_u64().unwrap_or(0);

    out.push_str(&format!(
        "Replicas: {ready}/{replicas} ready, {available} available, {updated} updated\n"
    ));

    // Strategy
    if let Some(strategy) = spec["strategy"]["type"].as_str() {
        out.push_str(&format!("Strategy: {strategy}\n"));
    }

    // Conditions
    if let Some(conditions) = status["conditions"].as_array() {
        out.push_str("\nConditions:\n");
        for c in conditions {
            let ctype = c["type"].as_str().unwrap_or("?");
            let cstatus = c["status"].as_str().unwrap_or("?");
            let reason = c["reason"].as_str().unwrap_or("");
            let msg = c["message"].as_str().unwrap_or("");
            out.push_str(&format!("  {ctype}={cstatus} ({reason})"));
            if !msg.is_empty() {
                out.push_str(&format!(": {msg}"));
            }
            out.push('\n');
        }
    }

    // Container images
    if let Some(containers) = spec
        .pointer("/template/spec/containers")
        .and_then(|v| v.as_array())
    {
        out.push_str("\nContainers:\n");
        for c in containers {
            let name = c["name"].as_str().unwrap_or("?");
            let image = c["image"].as_str().unwrap_or("?");
            out.push_str(&format!("  {name}: {image}\n"));
        }
    }
}

fn format_generic(data: &Value, out: &mut String) {
    // Show status section if present
    if let Some(status) = data.get("status")
        && status.is_object()
        && !status.as_object().unwrap().is_empty()
    {
        // Conditions
        if let Some(conditions) = status["conditions"].as_array() {
            out.push_str("\nConditions:\n");
            for c in conditions {
                let ctype = c["type"].as_str().unwrap_or("?");
                let cstatus = c["status"].as_str().unwrap_or("?");
                let reason = c["reason"].as_str().unwrap_or("");
                let msg = c["message"].as_str().unwrap_or("");
                out.push_str(&format!("  {ctype}={cstatus}"));
                if !reason.is_empty() {
                    out.push_str(&format!(" ({reason})"));
                }
                if !msg.is_empty() {
                    out.push_str(&format!(
                        ": {}",
                        if msg.len() > 200 { &msg[..200] } else { msg }
                    ));
                }
                out.push('\n');
            }
        }

        // Phase
        if let Some(phase) = status["phase"].as_str() {
            out.push_str(&format!("Phase: {phase}\n"));
        }
    }

    // Show spec highlights for services
    if let Some(spec) = data.get("spec")
        && let Some(ports) = spec["ports"].as_array()
    {
        out.push_str("\nPorts:\n");
        for p in ports {
            let name = p["name"].as_str().unwrap_or("?");
            let port = p["port"].as_u64().unwrap_or(0);
            let target = p["targetPort"].as_u64().unwrap_or(0);
            let proto = p["protocol"].as_str().unwrap_or("TCP");
            out.push_str(&format!("  {name}: {port}->{target}/{proto}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta_created_secs_ago(secs: i64) -> kube::api::ObjectMeta {
        let created = chrono::Utc::now() - chrono::Duration::seconds(secs);
        serde_json::from_value(serde_json::json!({
            "creationTimestamp": created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }))
        .expect("ObjectMeta should deserialize")
    }

    // Guards the k8s-openapi 0.28 migration: Time's inner type moved from
    // chrono::DateTime to jiff::Timestamp. Build ObjectMeta by deserializing so
    // the test does not name either time crate.
    #[test]
    fn extract_age_buckets_by_largest_unit() {
        // Values sit well inside their bucket, so the assertion cannot flake on
        // the second of slack that RFC3339 truncation can introduce.
        for (ago_secs, expected) in [(600_i64, "10m"), (7_200, "2h"), (172_800, "2d")] {
            assert_eq!(
                extract_age(&meta_created_secs_ago(ago_secs)),
                expected,
                "{ago_secs}s ago"
            );
        }
    }

    #[test]
    fn extract_age_reports_bare_seconds_under_a_minute() {
        let age = extract_age(&meta_created_secs_ago(30));
        let secs: i64 = age
            .strip_suffix('s')
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("expected a seconds age, got {age}"));
        assert!((30..=31).contains(&secs), "expected ~30s, got {age}");
    }

    #[test]
    fn extract_age_is_empty_without_a_creation_timestamp() {
        assert_eq!(extract_age(&kube::api::ObjectMeta::default()), "");
    }
}
