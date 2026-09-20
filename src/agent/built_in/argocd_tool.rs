use super::gitops_policy::{GitOpsPolicy, resource_name};
use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde_json::{Value, json};

pub struct GetArgocdApp;

#[async_trait::async_trait]
impl Tool for GetArgocdApp {
    fn name(&self) -> &str {
        "get_argocd_app"
    }

    fn description(&self) -> &str {
        "Get the full status of an ArgoCD Application including health, sync status, conditions, \
         unhealthy resources, and recent sync history. Use this when investigating deployment issues \
         or when an ArgoCD app is reported as Degraded/Unhealthy."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the Argo CD Application in the configured controller namespace. Both its controller namespace and local destination must be authorized for this tenant."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        inspect(
            args,
            GitOpsPolicy::from_env(ctx, "ARGOCD_NAMESPACE")?,
            super::kube_tool::shared_kube_client(),
        )
        .await
    }
}

async fn inspect(
    args: Value,
    policy: GitOpsPolicy,
    client: impl std::future::Future<Output = Result<kube::Client, kube::Error>>,
) -> Result<String> {
    let name = resource_name(&args)?;
    let argocd_ns = &policy.controller_namespace;
    policy.namespace(argocd_ns)?;
    let client = match client.await {
        Ok(c) => c,
        Err(e) => {
            return Ok(format!(
                "Cannot connect to Kubernetes: {e}. ArgoCD integration requires running in a K8s cluster."
            ));
        }
    };

    let ar = kube::discovery::ApiResource {
        group: "argoproj.io".into(),
        version: "v1alpha1".into(),
        kind: "Application".into(),
        api_version: "argoproj.io/v1alpha1".into(),
        plural: "applications".into(),
    };

    let apps_ns: kube::Api<kube::api::DynamicObject> =
        kube::Api::namespaced_with(client, argocd_ns, &ar);

    let app = apps_ns.get(name).await.map_err(|_| {
        anyhow::anyhow!("Argo CD Application unavailable in the authorized namespace")
    })?;
    policy.object(&app, argocd_ns, name)?;
    policy.argocd_destination(&app.data)?;

    let found_ns = argocd_ns;

    // Extract status fields from the dynamic object
    let data = &app.data;
    let status = data.get("status").unwrap_or(&Value::Null);
    let spec = data.get("spec").unwrap_or(&Value::Null);

    let health_status = status
        .pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let health_message = status
        .pointer("/health/message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sync_status = status
        .pointer("/sync/status")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let sync_revision = status
        .pointer("/sync/revision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let reconciled_at = status
        .get("reconciledAt")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Source
    let repo = spec
        .pointer("/source/repoURL")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let path = spec
        .pointer("/source/path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_rev = spec
        .pointer("/source/targetRevision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let chart = spec
        .pointer("/source/chart")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Destination
    let dest_ns = spec
        .pointer("/destination/namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let dest_server = spec
        .pointer("/destination/server")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let project = spec
        .get("project")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    // Operation state
    let op_phase = status
        .pointer("/operationState/phase")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let op_message = status
        .pointer("/operationState/message")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Conditions
    let conditions = status
        .get("conditions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Resources (filter to non-healthy)
    let resources = status
        .get("resources")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let unhealthy: Vec<&Value> = resources
        .iter()
        .filter(|r| {
            let h = r
                .get("health")
                .and_then(|h| h.get("status"))
                .and_then(|s| s.as_str())
                .unwrap_or("Healthy");
            h != "Healthy"
        })
        .collect();

    // History (last 5)
    let history = status
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let recent_history: Vec<&Value> = history.iter().rev().take(5).collect();

    // Build output
    let mut out = format!("ArgoCD Application: {name} (CRD in namespace: {found_ns})\n");
    out.push_str(&format!("Project: {project}\n"));
    out.push_str(&format!("Health: {health_status}"));
    if !health_message.is_empty() {
        out.push_str(&format!(" — {health_message}"));
    }
    out.push('\n');
    out.push_str(&format!(
        "Sync: {sync_status} (revision: {})\n",
        if sync_revision.len() > 8 {
            &sync_revision[..8]
        } else {
            sync_revision
        }
    ));
    out.push_str(&format!("Source: {repo} / {path}"));
    if !chart.is_empty() {
        out.push_str(&format!(" (chart: {chart})"));
    }
    out.push_str(&format!(" @ {target_rev}\n"));
    out.push_str(&format!("Deploys to: {dest_server} / {dest_ns}\n"));
    out.push_str(&format!("Reconciled: {reconciled_at}\n"));

    if !op_phase.is_empty() {
        out.push_str(&format!("\nLast Operation: {op_phase}"));
        if !op_message.is_empty() {
            out.push_str(&format!(" — {op_message}"));
        }
        out.push('\n');
    }

    if !conditions.is_empty() {
        out.push_str(&format!("\nConditions ({}):\n", conditions.len()));
        for c in &conditions {
            let ctype = c.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            let msg = c.get("message").and_then(|v| v.as_str()).unwrap_or("");
            out.push_str(&format!("  [{ctype}] {msg}\n"));
        }
    }

    if !unhealthy.is_empty() {
        out.push_str(&format!("\nUnhealthy Resources ({}):\n", unhealthy.len()));
        for r in &unhealthy {
            let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
            let rname = r.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let rns = r.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
            let rh = r
                .pointer("/health/status")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let rm = r
                .pointer("/health/message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            out.push_str(&format!("  {kind}/{rname}"));
            if !rns.is_empty() {
                out.push_str(&format!(" (ns: {rns})"));
            }
            out.push_str(&format!(" — {rh}"));
            if !rm.is_empty() {
                out.push_str(&format!(": {rm}"));
            }
            out.push('\n');
        }
    }

    if !recent_history.is_empty() {
        out.push_str(&format!(
            "\nSync History (last {}):\n",
            recent_history.len()
        ));
        for h in &recent_history {
            let rev = h.get("revision").and_then(|v| v.as_str()).unwrap_or("?");
            let short_rev = if rev.len() > 8 { &rev[..8] } else { rev };
            let deployed = h.get("deployedAt").and_then(|v| v.as_str()).unwrap_or("?");
            let src = h
                .pointer("/source/repoURL")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            out.push_str(&format!("  {short_rev} deployed at {deployed}"));
            if !src.is_empty() {
                out.push_str(&format!(" from {src}"));
            }
            out.push('\n');
        }
    }

    // Images
    let images = status.pointer("/summary/images").and_then(|v| v.as_array());
    if let Some(imgs) = images
        && !imgs.is_empty()
    {
        out.push_str(&format!("\nImages ({}):\n", imgs.len()));
        for img in imgs.iter().take(10) {
            if let Some(s) = img.as_str() {
                out.push_str(&format!("  {s}\n"));
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::built_in::gitops_policy::test_support::*;

    fn application() -> Value {
        json!({"apiVersion":"argoproj.io/v1alpha1","kind":"Application",
            "metadata":{"name":"web","namespace":"argocd"},
            "spec":{"destination":{"server":"https://kubernetes.default.svc","namespace":"app-a"}},
            "status":{"health":{"status":"Degraded","message":"PRIVATE_MARKER"}}})
    }

    #[tokio::test]
    async fn denies_before_client_initialization() {
        for raw in [
            None,
            Some("invalid"),
            Some("{}"),
            Some(r#"{"tenant-a":["app-a"]}"#),
        ] {
            assert!(
                inspect(
                    json!({"name":"web"}),
                    policy("argocd", raw),
                    unexpected_client()
                )
                .await
                .is_err()
            );
        }
        for name in ["", "../private", "web/../../private", "web%2fprivate"] {
            assert!(
                inspect(
                    json!({"name":name}),
                    policy("argocd", Some(NAMESPACES)),
                    unexpected_client()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn authorized_application_uses_one_namespaced_get() {
        let (client, requests) = client(200, application());
        let result = inspect(
            json!({"name":"web"}),
            policy("argocd", Some(NAMESPACES)),
            async { Ok(client) },
        )
        .await
        .unwrap();
        assert!(result.contains("PRIVATE_MARKER"));
        assert_eq!(
            *requests.lock().unwrap(),
            ["GET /apis/argoproj.io/v1alpha1/namespaces/argocd/applications/web"]
        );
    }

    #[tokio::test]
    async fn denies_other_tenant_destination_before_rendering() {
        for field in ["destination", "identity", "remote"] {
            let mut app = application();
            match field {
                "destination" => app["spec"]["destination"]["namespace"] = json!("app-b"),
                "identity" => app["metadata"]["namespace"] = json!("app-b"),
                _ => app["spec"]["destination"]["server"] = json!("https://other-cluster"),
            }
            let (client, _) = client(200, app);
            let error = inspect(
                json!({"name":"web"}),
                policy("argocd", Some(NAMESPACES)),
                async { Ok(client) },
            )
            .await
            .unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_MARKER"));
        }
    }

    #[tokio::test]
    async fn failures_never_fall_back_to_cluster_listing_or_echo_error_bodies() {
        for status in [403, 404, 500] {
            let (client, requests) = client(
                status,
                json!({"kind":"Status","apiVersion":"v1","status":"Failure","message":"PRIVATE_MARKER","reason":"NotFound","code":status}),
            );
            let error = inspect(
                json!({"name":"web"}),
                policy("argocd", Some(NAMESPACES)),
                async { Ok(client) },
            )
            .await
            .unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_MARKER"));
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }
}
