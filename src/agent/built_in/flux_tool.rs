use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde_json::{Value, json};

pub struct GetFluxResource;

/// Map a Flux kind to its (group, version, plural). Flux v2 only.
fn flux_gvp(kind: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match kind {
        "Kustomization" => Some(("kustomize.toolkit.fluxcd.io", "v1", "kustomizations")),
        "HelmRelease" => Some(("helm.toolkit.fluxcd.io", "v2", "helmreleases")),
        "GitRepository" => Some(("source.toolkit.fluxcd.io", "v1", "gitrepositories")),
        "OCIRepository" => Some(("source.toolkit.fluxcd.io", "v1beta2", "ocirepositories")),
        "HelmRepository" => Some(("source.toolkit.fluxcd.io", "v1", "helmrepositories")),
        "Bucket" => Some(("source.toolkit.fluxcd.io", "v1", "buckets")),
        _ => None,
    }
}

#[async_trait::async_trait]
impl Tool for GetFluxResource {
    fn name(&self) -> &str {
        "get_flux_resource"
    }

    fn description(&self) -> &str {
        "Get the full status of a Flux v2 (GitOps Toolkit) resource: its Ready condition, \
         all conditions, suspended flag, source reference, applied vs attempted revision, and \
         dependsOn. Use this when investigating GitOps deployment issues on a Flux-managed cluster — \
         a Kustomization or HelmRelease that is not Ready, stalled, or stuck reconciling."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["kind", "name"],
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["Kustomization", "HelmRelease", "GitRepository", "OCIRepository", "HelmRepository", "Bucket"],
                    "description": "The Flux resource kind. Kustomization/HelmRelease are the 'deployments'; the others are sources."
                },
                "name": {
                    "type": "string",
                    "description": "Name of the Flux resource. Flux resources live in the namespace they manage (often flux-system or an app namespace)."
                },
                "namespace": {
                    "type": "string",
                    "description": "Optional namespace. If omitted, the resource is found by name across all namespaces."
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<String> {
        let kind = args
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("kind is required"))?;
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("name is required"))?;
        let ns_filter = args.get("namespace").and_then(|v| v.as_str());

        let Some((group, version, plural)) = flux_gvp(kind) else {
            return Ok(format!(
                "Unknown Flux kind '{kind}'. Supported: Kustomization, HelmRelease, GitRepository, OCIRepository, HelmRepository, Bucket."
            ));
        };

        let client = match crate::agent::built_in::kube_tool::shared_kube_client().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(format!(
                    "Cannot connect to Kubernetes: {e}. The Flux integration requires running in a K8s cluster."
                ));
            }
        };

        let ar = kube::discovery::ApiResource {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
            api_version: format!("{group}/{version}"),
            plural: plural.into(),
        };

        // Fetch by name in the given namespace, or search across all namespaces.
        let obj = if let Some(ns) = ns_filter {
            let api: kube::Api<kube::api::DynamicObject> =
                kube::Api::namespaced_with(client.clone(), ns, &ar);
            match api.get(name).await {
                Ok(o) => o,
                Err(e) => return Ok(format!("Flux {kind} '{name}' not found in {ns}: {e}")),
            }
        } else {
            let api: kube::Api<kube::api::DynamicObject> = kube::Api::all_with(client.clone(), &ar);
            match api
                .list(&kube::api::ListParams::default().fields(&format!("metadata.name={name}")))
                .await
            {
                Ok(list) if !list.items.is_empty() => list.items.into_iter().next().unwrap(),
                Ok(_) => return Ok(format!("Flux {kind} '{name}' not found in any namespace.")),
                Err(e) => return Ok(format!("Flux {kind} '{name}' not found: {e}")),
            }
        };

        let found_ns = obj.metadata.namespace.as_deref().unwrap_or("");
        let data = &obj.data;
        let spec = data.get("spec").unwrap_or(&Value::Null);
        let status = data.get("status").unwrap_or(&Value::Null);

        let conditions = status
            .get("conditions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let ready = conditions
            .iter()
            .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Ready"));
        let ready_status = ready
            .and_then(|c| c.get("status"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let ready_msg = ready
            .and_then(|c| c.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let suspended = spec
            .get("suspend")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let source_ref = spec
            .get("sourceRef")
            .or_else(|| spec.pointer("/chart/spec/sourceRef"))
            .or_else(|| spec.get("chartRef"));
        let source = source_ref
            .map(|r| {
                let k = r.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                format!("{k}/{n}")
            })
            .unwrap_or_default();

        let applied = status
            .get("lastAppliedRevision")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let attempted = status
            .get("lastAttemptedRevision")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut out = format!("Flux {kind}: {name} (namespace: {found_ns})\n");
        out.push_str(&format!("Ready: {ready_status}"));
        if !ready_msg.is_empty() {
            out.push_str(&format!(" — {ready_msg}"));
        }
        out.push('\n');
        if suspended {
            out.push_str("Suspended: true (reconciliation is paused — this is often why it is not updating)\n");
        }
        if !source.is_empty() {
            out.push_str(&format!("Source: {source}\n"));
        }
        if let Some(p) = spec.get("path").and_then(|v| v.as_str()) {
            out.push_str(&format!("Path: {p}\n"));
        }
        if !applied.is_empty() {
            out.push_str(&format!("Last applied revision: {applied}\n"));
        }
        if !attempted.is_empty() && attempted != applied {
            out.push_str(&format!(
                "Last attempted revision: {attempted} (differs from applied — a reconcile is failing or in progress)\n"
            ));
        }

        // HelmRelease chart info
        if let Some(chart) = spec.pointer("/chart/spec/chart").and_then(|v| v.as_str()) {
            let ver = spec
                .pointer("/chart/spec/version")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            out.push_str(&format!("Chart: {chart}"));
            if !ver.is_empty() {
                out.push_str(&format!(" @ {ver}"));
            }
            out.push('\n');
        }

        // dependsOn
        if let Some(deps) = spec.get("dependsOn").and_then(|v| v.as_array())
            && !deps.is_empty()
        {
            let names: Vec<String> = deps
                .iter()
                .filter_map(|d| d.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect();
            out.push_str(&format!("Depends on: {}\n", names.join(", ")));
        }

        if !conditions.is_empty() {
            out.push_str(&format!("\nConditions ({}):\n", conditions.len()));
            for c in &conditions {
                let ctype = c.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                let cstat = c.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let reason = c.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                let msg = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
                out.push_str(&format!("  [{ctype}={cstat}]"));
                if !reason.is_empty() {
                    out.push_str(&format!(" {reason}:"));
                }
                if !msg.is_empty() {
                    out.push_str(&format!(" {msg}"));
                }
                out.push('\n');
            }
        }

        out.push_str(
            "\nNext: use kube_describe / kube_events on the workloads in the target namespace, \
             and search_logs for the affected service, to find why the reconcile is unhealthy.\n",
        );

        Ok(out)
    }
}
