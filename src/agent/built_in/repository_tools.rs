use crate::agent::tools::{Tool, ToolContext};
use crate::models::anomaly::DeployMarker;
use crate::models::service_link::ServiceLink;
use crate::repository::{Comparison, compare_revisions, ensure_snapshot, resolve_under};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_LISTED_FILES: usize = 500;
const MAX_SEARCH_RESULTS: usize = 200;
const MAX_READ_LINES: usize = 400;
const MAX_TOOL_OUTPUT: usize = 32 * 1024;
const MAX_SEARCH_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
struct RevisionInfo {
    git_ref: String,
    commit_sha: String,
    image_ref: String,
    verified: bool,
}

pub struct ListRepositoryFiles;
pub struct SearchRepository;
pub struct ReadRepositoryFile;
pub struct ListChanges;

const MAX_CHANGE_PULLS: usize = 60;
const MAX_CHANGE_COMMITS: usize = 40;
const MAX_PATCH_LINES: usize = 60;

fn require_code_scope(ctx: &ToolContext) -> Result<()> {
    if !ctx.has_scope("code") {
        bail!("code scope is required for repository access")
    }
    Ok(())
}

fn required_string<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))
}

async fn linked_snapshot(
    ctx: &ToolContext,
    service_name: &str,
) -> Result<(ServiceLink, PathBuf, RevisionInfo)> {
    let link = ctx
        .state
        .query_api
        .get_service_link(&ctx.tenant_id, service_name)
        .await?
        .with_context(|| {
            format!("no repository is linked to service {service_name:?} in this tenant")
        })?;
    // Deployment markers are the current source of deployed revision metadata.
    // A commit SHA is safe to use as the repository ref; an image tag/digest is
    // retained as context but is not blindly passed to GitHub because tags may
    // not be repository refs. Missing commit metadata is explicitly marked
    // unverified rather than presented as the healthy deployed revision.
    let deployment = match ctx
        .state
        .query_api
        .list_deploy_markers(&ctx.tenant_id, Some(service_name), None, None)
        .await
    {
        Ok(markers) => markers.into_iter().next(),
        Err(error) => {
            tracing::warn!(%error, service = service_name, "deployed revision metadata unavailable");
            None
        }
    };
    let revision = if let Some(deployment) = deployment {
        let commit_sha = deployment.commit_sha.trim().to_string();
        RevisionInfo {
            git_ref: if commit_sha.is_empty() {
                link.default_branch.clone()
            } else {
                commit_sha.clone()
            },
            commit_sha,
            image_ref: deployment.version.trim().to_string(),
            verified: !deployment.commit_sha.trim().is_empty(),
        }
    } else {
        RevisionInfo {
            git_ref: link.default_branch.clone(),
            commit_sha: String::new(),
            image_ref: String::new(),
            verified: false,
        }
    };
    let snapshot = ensure_snapshot(
        &ctx.tenant_id,
        &link.github_repo,
        link.github_installation_id,
        link.github_repository_id,
        &revision.git_ref,
    )
    .await?;
    let root = if link.root_path.trim().is_empty() {
        snapshot.root
    } else {
        resolve_under(&snapshot.root, link.root_path.trim())?
    };
    if !root.is_dir() {
        bail!("configured repository root_path does not exist in the downloaded snapshot")
    }
    Ok((link, root, revision))
}

fn repository_header(link: &ServiceLink, revision: &RevisionInfo) -> String {
    let status = if revision.verified {
        "verified_revision"
    } else {
        "unverified_revision"
    };
    let commit = if revision.commit_sha.is_empty() {
        "unknown".to_string()
    } else {
        revision.commit_sha.clone()
    };
    let image = if revision.image_ref.is_empty() {
        "unknown".to_string()
    } else {
        revision.image_ref.clone()
    };
    format!(
        "Repository: {} @ {}\nDeployed revision: {} (image/tag: {})\nRevision status: {}",
        link.github_repo, revision.git_ref, commit, image, status
    )
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_hidden_repository_metadata(entry: &walkdir::DirEntry) -> bool {
    sensitive_path(entry.path())
}

fn sensitive_path(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            name.as_str(),
            ".git"
                | ".ssh"
                | ".aws"
                | ".kube"
                | ".gnupg"
                | ".npmrc"
                | ".netrc"
                | ".pypirc"
                | "credentials"
                | "credentials.json"
                | "secrets"
                | "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "kubeconfig"
        ) || name == ".env"
            || name.starts_with(".env.")
            || [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"]
                .iter()
                .any(|ext| name.ends_with(ext))
    })
}

fn require_safe_path(path: &Path) -> Result<()> {
    anyhow::ensure!(
        !sensitive_path(path),
        "credential files are not available to repository tools"
    );
    Ok(())
}

fn read_text_file(path: &Path, max_bytes: u64) -> Result<String> {
    require_safe_path(path)?;
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("path is not a regular file")
    }
    if metadata.len() > max_bytes {
        bail!("file is larger than the code-reading limit")
    }
    let bytes = std::fs::read(path)?;
    if bytes.contains(&0) {
        bail!("binary files are not available to the code-reading tools")
    }
    let text = String::from_utf8(bytes).context("file is not valid UTF-8 text")?;
    // Redact before selecting lines so a partial PEM block cannot escape.
    Ok(crate::agent::redact::text(&text))
}

/// Audit sensitive source reads through query-api's tamper-evident audit log.
/// This is intentionally fire-and-forget so an unavailable audit sink cannot
/// stall an investigation; failures are still emitted to the agent log.
fn audit_access(ctx: &ToolContext, link: &ServiceLink, action: &'static str, path: &str) {
    let api = ctx.state.query_api.clone();
    let tenant_id = ctx.tenant_id.clone();
    let service_name = link.service_name.clone();
    let repository = link.github_repo.clone();
    let path = path.to_string();
    tokio::spawn(async move {
        let result = api
            .audit_repository_access(&tenant_id, &service_name, &repository, action, &path)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "failed to submit repository access audit event");
        }
    });
}

impl ListRepositoryFiles {
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        require_code_scope(ctx)?;
        let service = required_string(&args, "service_name")?;
        let requested_path = args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let max_depth = args
            .get("max_depth")
            .and_then(Value::as_u64)
            .unwrap_or(4)
            .clamp(1, 12) as usize;
        let (link, root, revision) = linked_snapshot(ctx, service).await?;
        let start = resolve_under(&root, requested_path)?;
        require_safe_path(&start)?;
        if !start.is_dir() {
            bail!("requested path is not a directory")
        }

        let list_root = root.clone();
        let paths = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut paths = Vec::new();
            for entry in WalkDir::new(&start)
                .follow_links(false)
                .max_depth(max_depth)
                .into_iter()
                .filter_entry(|entry| !is_hidden_repository_metadata(entry))
            {
                let entry = entry?;
                if entry.file_type().is_file() {
                    paths.push(relative_display(&list_root, entry.path()));
                    if paths.len() >= MAX_LISTED_FILES {
                        break;
                    }
                }
            }
            paths.sort();
            Ok(paths)
        })
        .await??;
        audit_access(ctx, &link, "list", requested_path);
        Ok(format!(
            "{}\nFiles{}:\n{}",
            repository_header(&link, &revision),
            if paths.len() == MAX_LISTED_FILES {
                " (truncated)"
            } else {
                ""
            },
            paths.join("\n")
        ))
    }
}

#[async_trait::async_trait]
impl Tool for ListRepositoryFiles {
    fn name(&self) -> &str {
        "list_repository_files"
    }
    fn description(&self) -> &str {
        "List source files from the read-only GitHub snapshot linked to a service. Does not execute repository code."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service_name": { "type": "string", "description": "Observed service whose repository is linked in Settings" },
                "path": { "type": "string", "description": "Optional repository-relative directory" },
                "max_depth": { "type": "integer", "minimum": 1, "maximum": 12 }
            },
            "required": ["service_name"],
            "additionalProperties": false
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        self.run(args, ctx).await
    }
}

impl SearchRepository {
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        require_code_scope(ctx)?;
        let service = required_string(&args, "service_name")?;
        let query = required_string(&args, "query")?;
        if query.len() > 256 {
            bail!("query is too long")
        }
        let requested_path = args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let requested_limit = args
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(50) as usize;
        let limit = requested_limit.clamp(1, MAX_SEARCH_RESULTS);
        let (link, root, revision) = linked_snapshot(ctx, service).await?;
        let start = resolve_under(&root, requested_path)?;
        require_safe_path(&start)?;
        if !start.is_dir() {
            bail!("requested path is not a directory")
        }
        let search_root = root.clone();
        let needle = query.to_lowercase();
        let results = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut results = Vec::new();
            let mut output_bytes = 0usize;
            'files: for entry in WalkDir::new(&start)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| !is_hidden_repository_metadata(entry))
            {
                let entry = entry?;
                if !entry.file_type().is_file() || entry.metadata()?.len() > MAX_SEARCH_FILE_BYTES {
                    continue;
                }
                let Ok(text) = read_text_file(entry.path(), MAX_SEARCH_FILE_BYTES) else {
                    continue;
                };
                for (index, line) in text.lines().enumerate() {
                    if line.to_lowercase().contains(&needle) {
                        let display = relative_display(&search_root, entry.path());
                        let clipped: String = line.chars().take(300).collect();
                        let result = format!("{}:{}: {}", display, index + 1, clipped.trim());
                        output_bytes += result.len() + 1;
                        if output_bytes > MAX_TOOL_OUTPUT {
                            break 'files;
                        }
                        results.push(result);
                        if results.len() >= limit {
                            break 'files;
                        }
                    }
                }
            }
            Ok(results)
        })
        .await??;
        audit_access(ctx, &link, "search", requested_path);
        Ok(format!(
            "{}\nLiteral matches for {:?}{}:\n{}",
            repository_header(&link, &revision),
            query,
            if results.len() >= limit {
                " (truncated)"
            } else {
                ""
            },
            if results.is_empty() {
                "(none)".to_string()
            } else {
                results.join("\n")
            }
        ))
    }
}

#[async_trait::async_trait]
impl Tool for SearchRepository {
    fn name(&self) -> &str {
        "search_repository"
    }
    fn description(&self) -> &str {
        "Search text literally across the read-only GitHub snapshot linked to a service. Bounded to text files and never executes code."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service_name": { "type": "string" },
                "query": { "type": "string", "description": "Case-insensitive literal text; not a regex" },
                "path": { "type": "string", "description": "Optional repository-relative directory" },
                "max_results": { "type": "integer", "minimum": 1, "maximum": 200 }
            },
            "required": ["service_name", "query"],
            "additionalProperties": false
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        self.run(args, ctx).await
    }
}

impl ReadRepositoryFile {
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        require_code_scope(ctx)?;
        let service = required_string(&args, "service_name")?;
        let requested_path = required_string(&args, "path")?;
        let start_line = args
            .get("start_line")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as usize;
        let requested_end = args
            .get("end_line")
            .and_then(Value::as_u64)
            .unwrap_or((start_line + 199) as u64) as usize;
        let end_line = requested_end
            .max(start_line)
            .min(start_line + MAX_READ_LINES - 1);
        let (link, root, revision) = linked_snapshot(ctx, service).await?;
        let path = resolve_under(&root, requested_path)?;
        let output = tokio::task::spawn_blocking(move || -> Result<String> {
            let text = read_text_file(&path, MAX_SEARCH_FILE_BYTES)?;
            let mut output = String::new();
            for (index, line) in text
                .lines()
                .enumerate()
                .skip(start_line - 1)
                .take(end_line - start_line + 1)
            {
                let rendered = format!("{:>6}  {}\n", index + 1, line);
                if output.len().saturating_add(rendered.len()) > MAX_TOOL_OUTPUT {
                    break;
                }
                output.push_str(&rendered);
            }
            Ok(output)
        })
        .await??;
        audit_access(ctx, &link, "read", requested_path);
        Ok(format!(
            "{}\nFile: {} (lines {}-{})\n{}",
            repository_header(&link, &revision),
            requested_path,
            start_line,
            end_line,
            output
        ))
    }
}

#[async_trait::async_trait]
impl Tool for ReadRepositoryFile {
    fn name(&self) -> &str {
        "read_repository_file"
    }
    fn description(&self) -> &str {
        "Read a bounded line range from a text file in the read-only GitHub snapshot linked to a service."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service_name": { "type": "string" },
                "path": { "type": "string", "description": "Repository-relative file path" },
                "start_line": { "type": "integer", "minimum": 1 },
                "end_line": { "type": "integer", "minimum": 1 }
            },
            "required": ["service_name", "path"],
            "additionalProperties": false
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        self.run(args, ctx).await
    }
}

/// The deploy running at the requested time (the newest marker, since markers
/// arrive newest first and already end at that time) and the newest earlier
/// deploy in the same environment with a different commit.
fn select_deploys(markers: &[DeployMarker]) -> Result<(&DeployMarker, &DeployMarker)> {
    let Some(head) = markers.first() else {
        bail!("no deploys are recorded for this service at or before that time")
    };
    let head_sha = head.commit_sha.trim();
    if head_sha.is_empty() {
        bail!(
            "the deploy running then ({} at {}) has no commit SHA; send commit_sha with the deploy event to compare deploys",
            head.version,
            head.deployed_at
        )
    }
    let base = markers[1..]
        .iter()
        .find(|marker| {
            let sha = marker.commit_sha.trim();
            marker.environment == head.environment && !sha.is_empty() && sha != head_sha
        })
        .context("no earlier deploy with a different commit SHA to compare against")?;
    Ok((head, base))
}

/// PR number and title from a merge commit ("Merge pull request #12 from ...")
/// or a squash merge ("Title (#12)"). Rebase merges carry no PR reference.
fn pull_request(message: &str) -> Option<(u64, String)> {
    let mut lines = message.lines();
    let first = lines.next()?.trim();
    if let Some(rest) = first.strip_prefix("Merge pull request #") {
        let number = rest.split_whitespace().next()?.parse().ok()?;
        let title = lines
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("");
        return Some((number, title.to_string()));
    }
    let open = first.rfind("(#")?;
    let number = first[open + 2..].strip_suffix(')')?.parse().ok()?;
    Some((number, first[..open].trim_end().to_string()))
}

fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn describe_deploy(marker: &DeployMarker) -> String {
    let mut text = format!(
        "{} (version {}, deployed {}",
        short_sha(marker.commit_sha.trim()),
        if marker.version.is_empty() {
            "unknown"
        } else {
            marker.version.as_str()
        },
        marker.deployed_at
    );
    if !marker.deployed_by.is_empty() {
        text.push_str(&format!(" by {}", marker.deployed_by));
    }
    if !marker.environment.is_empty() {
        text.push_str(&format!(", {}", marker.environment));
    }
    text.push(')');
    text
}

fn format_changes(
    link: &ServiceLink,
    head: &DeployMarker,
    base: &DeployMarker,
    comparison: &Comparison,
) -> String {
    let mut out = format!(
        "Repository: {}\nSuspect deploy: {}\nPrevious deploy: {}\nGitHub: {}, {} commit(s) between them\n",
        link.github_repo,
        describe_deploy(head),
        describe_deploy(base),
        comparison.status,
        comparison.total_commits
    );
    if comparison.status == "behind" || comparison.status == "diverged" {
        out.push_str("Note: the suspect deploy is not ahead of the previous one, so it may be a rollback or a deploy from another branch.\n");
    }

    let mut pulls = Vec::new();
    let mut others = Vec::new();
    for commit in &comparison.commits {
        let author = commit.commit.author.as_ref();
        let who = commit
            .author
            .as_ref()
            .map(|user| user.login.as_str())
            .or(author.map(|a| a.name.as_str()))
            .unwrap_or("unknown");
        let when = author.map(|a| a.date.as_str()).unwrap_or("");
        let message = crate::agent::redact::text(&commit.commit.message);
        match pull_request(&message) {
            Some((number, title)) => pulls.push(format!(
                "- #{number} {title} (merged {when} by {who}, commit {})",
                short_sha(&commit.sha)
            )),
            None => others.push(format!(
                "- {} {when} {who}: {}",
                short_sha(&commit.sha),
                message.lines().next().unwrap_or("").trim()
            )),
        }
    }
    // GitHub lists commits oldest first; the newest are the likelier suspects.
    pulls.reverse();
    others.reverse();
    if !pulls.is_empty() {
        let shown = pulls.len().min(MAX_CHANGE_PULLS);
        out.push_str(&format!("\nPull requests ({shown} of {}):\n", pulls.len()));
        out.push_str(&pulls[..shown].join("\n"));
        out.push('\n');
    }
    if !others.is_empty() {
        let shown = others.len().min(MAX_CHANGE_COMMITS);
        out.push_str(&format!("\nOther commits ({shown} of {}):\n", others.len()));
        out.push_str(&others[..shown].join("\n"));
        out.push('\n');
    }

    let root = link.root_path.trim().trim_matches('/');
    let files: Vec<_> = comparison
        .files
        .iter()
        .filter(|file| root.is_empty() || file.filename.starts_with(&format!("{root}/")))
        .collect();
    // Headroom for the closing "more files" line.
    let budget = MAX_TOOL_OUTPUT - 64;
    let outside_root = comparison.files.len() - files.len();
    out.push_str(&format!("\nChanged files ({}", files.len()));
    if outside_root > 0 {
        out.push_str(&format!(", {outside_root} outside {root}/ omitted"));
    }
    out.push_str("):\n");
    for (index, file) in files.iter().enumerate() {
        let entry = format!(
            "- {} {} (+{} -{})\n",
            file.status, file.filename, file.additions, file.deletions
        );
        if out.len() + entry.len() > budget {
            out.push_str(&format!("[{} more files not shown]\n", files.len() - index));
            break;
        }
        out.push_str(&entry);
        if require_safe_path(Path::new(&file.filename)).is_err() {
            out.push_str("  (diff withheld: credential file)\n");
            continue;
        }
        let Some(patch) = &file.patch else { continue };
        let patch = crate::agent::redact::text(patch);
        let lines: Vec<_> = patch.lines().collect();
        let mut diff = lines[..lines.len().min(MAX_PATCH_LINES)].join("\n");
        if lines.len() > MAX_PATCH_LINES {
            diff.push_str(&format!(
                "\n[{} more diff lines]",
                lines.len() - MAX_PATCH_LINES
            ));
        }
        let block = format!("```diff\n{diff}\n```\n");
        // Past the budget, keep listing file names without their diffs.
        if out.len() + block.len() <= budget {
            out.push_str(&block);
        }
    }
    out
}

impl ListChanges {
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        require_code_scope(ctx)?;
        let service = required_string(&args, "service_name")?;
        let around = args
            .get("around")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|time| {
                        time.with_timezone(&chrono::Utc)
                            .format("%Y-%m-%dT%H:%M:%SZ")
                            .to_string()
                    })
                    .context("around must be an ISO 8601 timestamp")
            })
            .transpose()?;
        let link = ctx
            .state
            .query_api
            .get_service_link(&ctx.tenant_id, service)
            .await?
            .with_context(|| {
                format!("no repository is linked to service {service:?} in this tenant")
            })?;
        let markers = ctx
            .state
            .query_api
            .list_deploy_markers(&ctx.tenant_id, Some(service), None, around.as_deref())
            .await
            .context("failed to list deploys")?;
        let (head, base) = select_deploys(&markers)?;
        let (base_sha, head_sha) = (base.commit_sha.trim(), head.commit_sha.trim());
        let comparison = compare_revisions(
            &ctx.tenant_id,
            &link.github_repo,
            link.github_installation_id,
            link.github_repository_id,
            base_sha,
            head_sha,
        )
        .await?;
        audit_access(ctx, &link, "compare", &format!("{base_sha}...{head_sha}"));
        Ok(format_changes(&link, head, base, &comparison))
    }
}

#[async_trait::async_trait]
impl Tool for ListChanges {
    fn name(&self) -> &str {
        "list_changes"
    }
    fn description(&self) -> &str {
        "List what a deploy changed: the pull requests, commits, and changed files with diffs between the service's deploy running at a given time and the deploy before it, from the GitHub repository linked to the service. Use it when an incident lines up with a deploy."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service_name": { "type": "string" },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 time, usually the incident start. Compares the deploy running then with the one before it. Defaults to the latest deploy."
                }
            },
            "required": ["service_name"],
            "additionalProperties": false
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        self.run(args, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_tools_exclude_secret_paths() {
        for path in [
            ".env",
            "app/.env.production",
            "certs/private.key",
            "tls/key.pem",
            ".aws/credentials",
            ".kube/config",
            ".ssh/id_rsa",
            "config/.netrc",
            "secrets/passwords",
        ] {
            assert!(require_safe_path(Path::new(path)).is_err(), "{path}");
            assert!(
                read_text_file(Path::new(path), MAX_SEARCH_FILE_BYTES)
                    .unwrap_err()
                    .to_string()
                    .contains("credential files")
            );
        }
        assert!(require_safe_path(Path::new("src/auth.rs")).is_ok());
        assert!(require_safe_path(Path::new("config/settings.yaml")).is_ok());
    }

    fn link() -> ServiceLink {
        ServiceLink {
            tenant_id: "tenant-a".into(),
            service_name: "api".into(),
            github_repo: "acme/api".into(),
            github_installation_id: 1,
            github_repository_id: 2,
            default_branch: "main".into(),
            root_path: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn repository_header_marks_unverified_revision_explicitly() {
        let header = repository_header(
            &link(),
            &RevisionInfo {
                git_ref: "main".into(),
                commit_sha: String::new(),
                image_ref: "api:latest".into(),
                verified: false,
            },
        );
        assert!(header.contains("unverified_revision"));
        assert!(header.contains("api:latest"));
        assert!(header.contains("main"));
    }

    #[test]
    fn repository_header_reports_verified_commit_revision() {
        let header = repository_header(
            &link(),
            &RevisionInfo {
                git_ref: "abc123".into(),
                commit_sha: "abc123".into(),
                image_ref: "api@sha256:deadbeef".into(),
                verified: true,
            },
        );
        assert!(header.contains("verified_revision"));
        assert!(header.contains("abc123"));
        assert!(header.contains("api@sha256:deadbeef"));
    }

    fn marker(sha: &str, environment: &str, deployed_at: &str) -> DeployMarker {
        DeployMarker {
            id: deployed_at.into(),
            service_name: "api".into(),
            version: format!("v-{sha}"),
            commit_sha: sha.into(),
            description: String::new(),
            environment: environment.into(),
            deployed_by: "ci".into(),
            deployed_at: deployed_at.into(),
        }
    }

    #[test]
    fn deploy_selection_compares_the_running_deploy_with_the_previous_commit_in_its_environment() {
        let markers = vec![
            marker("cccccccc", "prod", "2026-11-08 10:00:00"),
            marker("cccccccc", "prod", "2026-11-08 09:30:00"), // redeploy of the same commit
            marker("dddddddd", "staging", "2026-11-08 09:00:00"),
            marker("", "prod", "2026-11-08 08:30:00"),
            marker("bbbbbbbb", "prod", "2026-11-08 08:00:00"),
        ];
        let (head, base) = select_deploys(&markers).unwrap();
        assert_eq!(head.commit_sha, "cccccccc");
        assert_eq!(base.commit_sha, "bbbbbbbb");

        assert!(
            select_deploys(&[])
                .unwrap_err()
                .to_string()
                .contains("no deploys")
        );
        assert!(
            select_deploys(&[
                marker("", "prod", "now"),
                marker("bbbbbbbb", "prod", "then")
            ])
            .unwrap_err()
            .to_string()
            .contains("no commit SHA")
        );
        assert!(
            select_deploys(&[marker("cccccccc", "prod", "now")])
                .unwrap_err()
                .to_string()
                .contains("no earlier deploy")
        );
    }

    #[test]
    fn pull_requests_are_read_from_merge_and_squash_commit_messages() {
        assert_eq!(
            pull_request("Merge pull request #412 from acme/fix-retry\n\nFix retry timeout"),
            Some((412, "Fix retry timeout".into()))
        );
        assert_eq!(
            pull_request("Fix retry timeout (#413)\n\n* body"),
            Some((413, "Fix retry timeout".into()))
        );
        assert_eq!(pull_request("Bump tokio"), None);
        assert_eq!(pull_request("Explain (#notes)"), None);
    }

    fn comparison(status: &str, files: Value) -> Comparison {
        serde_json::from_value(json!({
            "status": status,
            "total_commits": 3,
            "commits": [
                {"sha": "1111111111111111", "commit": {"message": "Merge pull request #10 from acme/a\n\nAdd cache", "author": {"name": "Bo", "date": "2026-11-08T08:10:00Z"}}, "author": {"login": "bo"}},
                {"sha": "2222222222222222", "commit": {"message": "Raise retry timeout (#11)", "author": {"name": "Al", "date": "2026-11-08T09:10:00Z"}}, "author": null},
                {"sha": "3333333333333333", "commit": {"message": "Tidy logging\n\nlonger body", "author": {"name": "Cy", "date": "2026-11-08T09:20:00Z"}}, "author": null}
            ],
            "files": files
        }))
        .unwrap()
    }

    #[test]
    fn changes_list_newest_pull_requests_first_and_withhold_credential_diffs() {
        let text = format_changes(
            &link(),
            &marker("3333333333333333", "prod", "2026-11-08 10:00:00"),
            &marker("0000000000000000", "prod", "2026-11-08 08:00:00"),
            &comparison(
                "ahead",
                json!([
                    {"filename": "src/client.rs", "status": "modified", "additions": 1, "deletions": 1, "patch": "@@ -1 +1 @@\n-timeout = 5\n+timeout = 30"},
                    {"filename": "config/.env.production", "status": "modified", "additions": 1, "deletions": 0, "patch": "+TOKEN=abc"}
                ]),
            ),
        );
        let newest = text.find("#11 Raise retry timeout").unwrap();
        let older = text.find("#10 Add cache").unwrap();
        assert!(newest < older, "{text}");
        assert!(text.contains("by bo"));
        assert!(text.contains("333333333333 2026-11-08T09:20:00Z Cy: Tidy logging"));
        assert!(text.contains("+timeout = 30"));
        assert!(text.contains("diff withheld: credential file"));
        assert!(!text.contains("TOKEN=abc"));
        assert!(!text.contains("rollback"));
    }

    #[test]
    fn changes_respect_the_service_root_and_flag_rollbacks() {
        let mut monorepo = link();
        monorepo.root_path = "services/api/".into();
        let text = format_changes(
            &monorepo,
            &marker("1111111", "prod", "now"),
            &marker("2222222", "prod", "then"),
            &comparison(
                "behind",
                json!([
                    {"filename": "services/api/main.go", "status": "modified", "additions": 1, "deletions": 0},
                    {"filename": "services/web/main.go", "status": "modified", "additions": 1, "deletions": 0}
                ]),
            ),
        );
        assert!(text.contains("services/api/main.go"));
        assert!(!text.contains("services/web/main.go"));
        assert!(text.contains("1 outside services/api/ omitted"));
        assert!(text.contains("may be a rollback"));
    }

    #[test]
    fn changes_stay_within_the_tool_output_budget() {
        let patch = format!("@@ -1 +1 @@\n{}", "+line\n".repeat(50));
        let files: Vec<_> = (0..300)
            .map(|i| json!({"filename": format!("src/f{i}.rs"), "status": "modified", "additions": 50, "deletions": 0, "patch": patch}))
            .collect();
        let text = format_changes(
            &link(),
            &marker("1111111", "prod", "now"),
            &marker("2222222", "prod", "then"),
            &comparison("ahead", Value::Array(files)),
        );
        assert!(text.len() <= MAX_TOOL_OUTPUT, "{}", text.len());
        assert!(text.contains("more files not shown"));
    }
}
