//! Read-only GitHub source snapshots for code-assisted investigations.
//!
//! This module deliberately does not invoke `git` or a shell. It downloads a
//! GitHub archive using a short-lived App installation token, rejects links and
//! special files, enforces compressed/uncompressed limits, and exposes only a
//! local source tree to the bounded repository tools.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tar::Archive;
use tokio::sync::Mutex;

const MAX_ARCHIVE_BYTES: usize = 50 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 250 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_FILES: usize = 25_000;
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const REPOSITORY_POLICY_ENV: &str = "SRE_AGENT_GITHUB_REPOSITORY_POLICY";

static DOWNLOAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone)]
struct GitHubAppConfig {
    app_id: String,
    private_key_pem: Arc<Vec<u8>>,
    api_base: String,
    cache_dir: PathBuf,
    repository_policy: HashMap<String, Vec<GitHubRepositoryGrant>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GitHubRepositoryGrant {
    repository: String,
    installation_id: u64,
    repository_id: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub root: PathBuf,
    pub repository: String,
    pub git_ref: String,
}

#[derive(Serialize)]
struct AppClaims<'a> {
    iat: u64,
    exp: u64,
    iss: &'a str,
}

#[derive(Deserialize)]
struct InstallationToken {
    token: String,
}

impl GitHubAppConfig {
    fn from_env() -> Result<Self> {
        let app_id = required_env("GITHUB_APP_ID")?;
        let private_key_path = required_env("GITHUB_APP_PRIVATE_KEY_PATH")?;
        let private_key_pem = std::fs::read(&private_key_path)
            .with_context(|| format!("cannot read GitHub App private key at {private_key_path}"))?;
        let repository_policy = parse_repository_policy(&required_env(REPOSITORY_POLICY_ENV)?)?;
        let api_base = std::env::var("GITHUB_API_URL")
            .unwrap_or_else(|_| "https://api.github.com".to_string())
            .trim_end_matches('/')
            .to_string();
        let cache_dir = std::env::var("REPOSITORY_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/rush-repositories"));
        Ok(Self {
            app_id,
            private_key_pem: Arc::new(private_key_pem),
            api_base,
            cache_dir,
            repository_policy,
        })
    }

    fn app_jwt(&self) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
        let claims = AppClaims {
            iat: now.saturating_sub(60),
            exp: now + 9 * 60,
            iss: &self.app_id,
        };
        let key = EncodingKey::from_rsa_pem(&self.private_key_pem)
            .context("invalid GitHub App RSA private key")?;
        encode(&Header::new(Algorithm::RS256), &claims, &key)
            .context("failed to sign GitHub App JWT")
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} is not configured"))
}

fn parse_repository(value: &str) -> Result<(String, String)> {
    let trimmed = value
        .trim()
        .trim_end_matches(".git")
        .trim_start_matches("https://github.com/");
    let parts: Vec<_> = trimmed.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        bail!("repository must be a GitHub owner/name pair")
    }
    Ok((parts[0].to_ascii_lowercase(), parts[1].to_ascii_lowercase()))
}

fn parse_repository_policy(value: &str) -> Result<HashMap<String, Vec<GitHubRepositoryGrant>>> {
    let mut policy: HashMap<String, Vec<GitHubRepositoryGrant>> =
        serde_json::from_str(value).context("invalid GitHub repository policy JSON")?;
    let mut repositories = HashSet::new();
    for (tenant_id, grants) in &mut policy {
        if tenant_id.is_empty() {
            bail!("GitHub repository policy tenant IDs cannot be empty")
        }
        for grant in grants {
            if grant.installation_id == 0 || grant.repository_id == 0 {
                bail!("GitHub repository policy IDs must be non-zero")
            }
            let (owner, name) = parse_repository(&grant.repository)
                .context("invalid repository in GitHub repository policy")?;
            grant.repository = format!("{owner}/{name}");
            if !repositories.insert((tenant_id.clone(), grant.repository.clone())) {
                bail!("duplicate GitHub repository grant")
            }
        }
    }
    Ok(policy)
}

fn authorize_repository(
    policy: &HashMap<String, Vec<GitHubRepositoryGrant>>,
    tenant_id: &str,
    repository: &str,
    installation_id: u64,
    repository_id: u64,
) -> Result<String> {
    if installation_id == 0 || repository_id == 0 {
        bail!("repository access is not approved for this tenant")
    }
    let (owner, name) = parse_repository(repository)?;
    let canonical = format!("{owner}/{name}");
    let approved = policy.get(tenant_id).is_some_and(|grants| {
        grants.iter().any(|grant| {
            grant.repository == canonical
                && grant.installation_id == installation_id
                && grant.repository_id == repository_id
        })
    });
    if !approved {
        bail!("repository access is not approved for this tenant")
    }
    Ok(canonical)
}

fn cache_key(
    tenant_id: &str,
    repository: &str,
    installation_id: u64,
    repository_id: u64,
    git_ref: &str,
) -> String {
    let digest = Sha256::digest(
        format!("{tenant_id}\0{repository}\0{installation_id}\0{repository_id}\0{git_ref}")
            .as_bytes(),
    );
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn cache_is_fresh(path: &Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .map(|age| age < CACHE_TTL)
        .unwrap_or(false)
}

fn safe_relative_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let _archive_root = components.next();
    let mut safe = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) => safe.push(value),
            _ => bail!("archive contains an unsafe path"),
        }
    }
    Ok(safe)
}

fn extract_archive(bytes: Vec<u8>, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut expanded = 0u64;
    let mut files = 0usize;

    for entry in archive.entries().context("invalid repository archive")? {
        let mut entry = entry.context("invalid repository archive entry")?;
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            continue;
        }
        let relative = safe_relative_path(&entry.path()?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let output = destination.join(relative);
        if entry_type.is_dir() {
            std::fs::create_dir_all(&output)?;
            continue;
        }
        files += 1;
        let size = entry.header().size()?;
        expanded = expanded.saturating_add(size);
        if files > MAX_FILES || size > MAX_FILE_BYTES || expanded > MAX_EXPANDED_BYTES {
            bail!("repository archive exceeds safe extraction limits")
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&output)?;
        let copied = std::io::copy(&mut entry.by_ref().take(MAX_FILE_BYTES + 1), &mut file)?;
        if copied != size || copied > MAX_FILE_BYTES {
            bail!("repository archive entry size is invalid")
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o444))?;
        }
    }
    Ok(())
}

async fn installation_token(
    client: &reqwest::Client,
    config: &GitHubAppConfig,
    installation_id: u64,
    repository_id: u64,
) -> Result<String> {
    let response = client
        .post(format!(
            "{}/app/installations/{installation_id}/access_tokens",
            config.api_base
        ))
        .bearer_auth(config.app_jwt()?)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "rush-sre-agent")
        .json(&installation_token_request(repository_id))
        .send()
        .await?
        .error_for_status()
        .context("GitHub rejected the App installation token request")?;
    Ok(response.json::<InstallationToken>().await?.token)
}

fn installation_token_request(repository_id: u64) -> serde_json::Value {
    serde_json::json!({
        "repository_ids": [repository_id],
        "permissions": { "contents": "read" }
    })
}

async fn download_archive(
    client: &reqwest::Client,
    config: &GitHubAppConfig,
    token: &str,
    owner: &str,
    repository: &str,
    git_ref: &str,
) -> Result<Vec<u8>> {
    let mut url = reqwest::Url::parse(&config.api_base)?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid GitHub API URL"))?
        .extend(["repos", owner, repository, "tarball", git_ref]);
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "rush-sre-agent")
        .send()
        .await?
        .error_for_status()
        .context("GitHub repository archive download failed")?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_ARCHIVE_BYTES as u64)
    {
        bail!("repository archive is larger than the configured limit")
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > MAX_ARCHIVE_BYTES {
            bail!("repository archive is larger than the configured limit")
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn ensure_snapshot(
    tenant_id: &str,
    repository: &str,
    installation_id: u64,
    repository_id: u64,
    git_ref: &str,
) -> Result<Snapshot> {
    let config = GitHubAppConfig::from_env()?;
    // Authorization happens before looking at the cache so revoked grants take
    // effect immediately instead of exposing a previously downloaded snapshot.
    let canonical_repository = authorize_repository(
        &config.repository_policy,
        tenant_id,
        repository,
        installation_id,
        repository_id,
    )?;
    let (owner, name) = parse_repository(&canonical_repository)?;
    if git_ref.is_empty() || git_ref.len() > 200 || git_ref.chars().any(char::is_control) {
        bail!("repository ref is invalid")
    }
    let destination = config.cache_dir.join(cache_key(
        tenant_id,
        &canonical_repository,
        installation_id,
        repository_id,
        git_ref,
    ));
    if cache_is_fresh(&destination) {
        return Ok(Snapshot {
            root: destination,
            repository: canonical_repository,
            git_ref: git_ref.to_string(),
        });
    }

    let _guard = DOWNLOAD_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    if cache_is_fresh(&destination) {
        return Ok(Snapshot {
            root: destination,
            repository: canonical_repository,
            git_ref: git_ref.to_string(),
        });
    }
    tokio::fs::create_dir_all(&config.cache_dir).await?;
    let temporary = config
        .cache_dir
        .join(format!(".download-{}", uuid::Uuid::new_v4()));
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;
    let token = installation_token(&client, &config, installation_id, repository_id).await?;
    let archive = download_archive(&client, &config, &token, &owner, &name, git_ref).await?;
    let extract_to = temporary.clone();
    let extracted =
        tokio::task::spawn_blocking(move || extract_archive(archive, &extract_to)).await;
    match extracted {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = tokio::fs::remove_dir_all(&temporary).await;
            return Err(error);
        }
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&temporary).await;
            return Err(error.into());
        }
    }
    if destination.exists() {
        tokio::fs::remove_dir_all(&destination).await?;
    }
    tokio::fs::rename(&temporary, &destination).await?;
    Ok(Snapshot {
        root: destination,
        repository: canonical_repository,
        git_ref: git_ref.to_string(),
    })
}

/// Resolve a model-supplied relative path under a snapshot root.
pub fn resolve_under(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("path must be a relative repository path without '..'")
    }
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    #[test]
    fn repository_parser_accepts_owner_name_and_url() {
        assert_eq!(
            parse_repository("acme/api").unwrap(),
            ("acme".into(), "api".into())
        );
        assert_eq!(
            parse_repository("https://github.com/acme/api.git").unwrap(),
            ("acme".into(), "api".into())
        );
    }

    #[test]
    fn repository_parser_rejects_hosts_and_extra_segments() {
        assert!(parse_repository("https://evil.example/acme/api").is_err());
        assert!(parse_repository("acme/team/api").is_err());
    }

    #[test]
    fn repository_policy_binds_tenant_repository_and_stable_ids() {
        let policy = parse_repository_policy(
            r#"{
                "tenant-a":[{"repository":"Acme/API","installationId":42,"repositoryId":101}],
                "tenant-b":[{"repository":"acme/other","installationId":84,"repositoryId":202}]
            }"#,
        )
        .unwrap();
        assert_eq!(
            authorize_repository(&policy, "tenant-a", "acme/api", 42, 101).unwrap(),
            "acme/api"
        );
        assert!(authorize_repository(&policy, "tenant-b", "acme/api", 42, 101).is_err());
        assert!(authorize_repository(&policy, "tenant-a", "acme/api", 84, 101).is_err());
        assert!(authorize_repository(&policy, "tenant-a", "acme/api", 42, 202).is_err());
        assert!(authorize_repository(&policy, "tenant-a", "acme/missing", 42, 101).is_err());
    }

    #[test]
    fn repository_policy_rejects_malformed_zero_and_duplicate_grants() {
        assert!(parse_repository_policy("not-json").is_err());
        assert!(
            parse_repository_policy(
                r#"{"tenant-a":[{"repository":"acme/api","installationId":0,"repositoryId":1}]}"#
            )
            .is_err()
        );
        assert!(parse_repository_policy(
            r#"{"tenant-a":[{"repository":"acme/api","installationId":1,"repositoryId":1},{"repository":"ACME/API","installationId":2,"repositoryId":2}]}"#
        )
        .is_err());
    }

    #[test]
    fn cache_and_token_scope_use_stable_repository_ids() {
        assert_ne!(
            cache_key("tenant-a", "acme/api", 42, 101, "main"),
            cache_key("tenant-a", "acme/api", 43, 101, "main")
        );
        assert_ne!(
            cache_key("tenant-a", "acme/api", 42, 101, "main"),
            cache_key("tenant-a", "acme/api", 42, 102, "main")
        );
        assert_eq!(
            installation_token_request(101),
            serde_json::json!({
                "repository_ids": [101],
                "permissions": { "contents": "read" }
            })
        );
    }

    #[test]
    fn path_resolution_rejects_traversal_and_absolute_paths() {
        let root = Path::new("/tmp/repo");
        assert!(resolve_under(root, "src/main.rs").is_ok());
        assert!(resolve_under(root, "../secret").is_err());
        assert!(resolve_under(root, "/etc/passwd").is_err());
    }

    #[test]
    fn extraction_keeps_regular_files_and_drops_links() {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let source = b"fn main() {}\n";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(source.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "snapshot/src/main.rs", &source[..])
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mode(0o777);
        link_header.set_link_name("/etc/passwd").unwrap();
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "snapshot/src/escape", std::io::empty())
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let destination =
            std::env::temp_dir().join(format!("rush-repo-test-{}", uuid::Uuid::new_v4()));
        extract_archive(archive, &destination).unwrap();
        assert_eq!(
            std::fs::read_to_string(destination.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert!(!destination.join("src/escape").exists());
        std::fs::remove_dir_all(destination).unwrap();
    }
}
