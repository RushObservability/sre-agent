use crate::agent::tools::{Tool, ToolContext};
use crate::models::service_link::ServiceLink;
use crate::repository::{ensure_snapshot, resolve_under};
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
    entry.file_name() == ".git"
}

fn read_text_file(path: &Path, max_bytes: u64) -> Result<String> {
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
    String::from_utf8(bytes).context("file is not valid UTF-8 text")
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
