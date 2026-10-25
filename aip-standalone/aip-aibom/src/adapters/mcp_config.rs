//! Discover tools from an MCP client configuration file.
//!
//! Reads the `mcpServers` object (Claude Desktop and most clients) or the
//! `servers` object (VS Code). Each entry is a tool the agent can reach.
//!
//! # What is recorded, and what is never recorded
//!
//! Recorded: the server name, the program it launches or the endpoint it
//! reaches (userinfo, query and fragment removed), and the *names* of its
//! environment variables.
//!
//! Never recorded: arguments, environment values, header values, URL
//! credentials. Those are where secrets live, and `ports::Discovery` has no
//! field to put one in. When one looks like a credential, the location is
//! reported as a [`crate::ports::SecretExposure`] — where, never what.
//!
//! # The detection is a heuristic, and says so
//!
//! A value is flagged when its name looks like a credential or it begins with
//! a recognisable provider token prefix. A secret under an innocuous name with
//! no known prefix is missed. A value that is a reference (`${VAR}`, `$VAR`)
//! is not a secret and is not flagged.

use crate::finding::{SecretIndicator, SecretLocation};
use crate::model::limits::{MAX_ID_LEN, MAX_INPUT_BYTES, MAX_ITEMS, MAX_TEXT_LEN};
use crate::ports::{
    DiscoveredServer, Discovery, DiscoveryError, DiscoverySource, SecretExposure, Transport,
};
use crate::standing::{SourceKind, SourceRef};
use aip_crypto::sha256;
use serde_json::{Map, Value};
use std::io::Read;
use std::path::PathBuf;

/// Substrings that mark a name as a credential's, compared case-insensitively.
const CREDENTIAL_NAME_MARKERS: [&str; 11] = [
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "auth",
    "cookie",
    "session",
    "bearer",
    "private",
];

/// Prefixes that identify a provider-issued token regardless of its name.
const KNOWN_TOKEN_PREFIXES: [&str; 7] = [
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
];

/// Placeholder recorded in place of a command that itself contains a token.
const WITHHELD: &str = "<withheld>";

/// An MCP client configuration file on disk.
#[derive(Debug, Clone)]
pub struct McpConfigFile {
    path: PathBuf,
}

impl McpConfigFile {
    /// A source at `path`. Nothing is read until [`DiscoverySource::discover`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl DiscoverySource for McpConfigFile {
    fn discover(&self) -> Result<Discovery, DiscoveryError> {
        let bytes = read_bounded(&self.path)?;
        parse(&bytes, &self.path.display().to_string())
    }
}

/// Read at most [`MAX_INPUT_BYTES`]; a larger file is refused, not truncated.
fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, DiscoveryError> {
    let file = std::fs::File::open(path).map_err(|e| DiscoveryError::Io(e.kind().to_string()))?;
    let mut buf = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| DiscoveryError::Io(e.kind().to_string()))?;
    if buf.len() as u64 > MAX_INPUT_BYTES {
        return Err(DiscoveryError::TooLarge {
            max: MAX_INPUT_BYTES,
        });
    }
    Ok(buf)
}

/// Parse configuration bytes. Pure: no IO, no clock.
pub fn parse(bytes: &[u8], path: &str) -> Result<Discovery, DiscoveryError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|e| DiscoveryError::NotJson(e.to_string()))?;
    let servers = root
        .get("mcpServers")
        .or_else(|| root.get("servers"))
        .and_then(Value::as_object)
        .ok_or(DiscoveryError::NotAnMcpConfig)?;
    if servers.len() > MAX_ITEMS {
        return Err(DiscoveryError::NotAnMcpConfig);
    }

    let mut found = Vec::new();
    let mut exposures = Vec::new();
    for (name, entry) in servers {
        check_name(name)?;
        let Some(entry) = entry.as_object() else {
            return Err(DiscoveryError::NotAnMcpConfig);
        };
        let transport = transport(name, entry, &mut exposures);
        let env_names = env(name, entry, &mut exposures);
        args(name, entry, &mut exposures);
        headers(name, entry, &mut exposures);
        found.push(DiscoveredServer {
            name: name.clone(),
            transport,
            env_names,
        });
    }
    found.sort();
    exposures.sort();
    Ok(Discovery {
        source: SourceRef {
            kind: SourceKind::McpClientConfig,
            path: path.to_string(),
            sha256: hex::encode(sha256(bytes)),
        },
        servers: found,
        exposures,
    })
}

fn check_name(name: &str) -> Result<(), DiscoveryError> {
    let ok = !name.is_empty() && name.len() <= MAX_ID_LEN && !name.chars().any(char::is_control);
    if ok {
        Ok(())
    } else {
        Err(DiscoveryError::InvalidServerName(
            name.chars()
                .filter(|c| !c.is_control())
                .take(MAX_ID_LEN)
                .collect(),
        ))
    }
}

/// Whether a name looks like a credential's.
fn credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_NAME_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether a value begins with a known provider token prefix.
fn token_prefixed(value: &str) -> bool {
    KNOWN_TOKEN_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// `${VAR}`, `${env:VAR}`, `Bearer ${TOKEN}` or `$VAR`: a value that points at
/// a secret rather than containing one.
fn is_reference(value: &str) -> bool {
    if value.contains("${") {
        return true;
    }
    match value.strip_prefix('$') {
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Classify an inline value under `name`. `None` when it does not look like a
/// credential, is empty, or is only a reference.
fn indicator(name: &str, value: &str) -> Option<SecretIndicator> {
    if value.is_empty() || is_reference(value) {
        return None;
    }
    if token_prefixed(value) {
        Some(SecretIndicator::KnownTokenPrefix)
    } else if credential_name(name) {
        Some(SecretIndicator::CredentialName)
    } else {
        None
    }
}

fn expose(
    out: &mut Vec<SecretExposure>,
    server: &str,
    location: SecretLocation,
    i: SecretIndicator,
) {
    out.push(SecretExposure {
        server: server.to_string(),
        location,
        indicator: i,
    });
}

fn transport(server: &str, e: &Map<String, Value>, out: &mut Vec<SecretExposure>) -> Transport {
    if let Some(cmd) = e.get("command").and_then(Value::as_str) {
        if token_prefixed(cmd) || cmd.split_whitespace().any(token_prefixed) {
            expose(
                out,
                server,
                SecretLocation::Command,
                SecretIndicator::KnownTokenPrefix,
            );
            return Transport::Stdio {
                command: WITHHELD.into(),
            };
        }
        let command: String = cmd
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_TEXT_LEN)
            .collect();
        return Transport::Stdio { command };
    }
    if let Some(url) = e.get("url").and_then(Value::as_str) {
        return Transport::Remote {
            endpoint: sanitise_url(server, url, out),
        };
    }
    Transport::Unknown
}

/// Strip userinfo, query and fragment from a URL, reporting any credential
/// found in them. Hand-written because the only operations needed are three
/// splits, and a URL parser would be a dependency for that.
fn sanitise_url(server: &str, url: &str, out: &mut Vec<SecretExposure>) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("", url),
    };
    let (before_fragment, _) = rest.split_once('#').unwrap_or((rest, ""));
    let (before_query, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    let (authority, path) = match before_query.find('/') {
        Some(i) => before_query.split_at(i),
        None => (before_query, ""),
    };
    let host = match authority.rsplit_once('@') {
        Some((_, h)) => {
            expose(
                out,
                server,
                SecretLocation::UrlUserinfo,
                SecretIndicator::UrlUserinfo,
            );
            h
        }
        None => authority,
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if let Some(i) = indicator(k, v) {
            expose(
                out,
                server,
                SecretLocation::UrlQuery { key: k.to_string() },
                i,
            );
        }
    }
    let joined = if scheme.is_empty() {
        format!("{host}{path}")
    } else {
        format!("{scheme}://{host}{path}")
    };
    joined
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT_LEN)
        .collect()
}

fn env(server: &str, e: &Map<String, Value>, out: &mut Vec<SecretExposure>) -> Vec<String> {
    let Some(vars) = e.get("env").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for (k, v) in vars {
        if let Some(value) = v.as_str() {
            if let Some(i) = indicator(k, value) {
                expose(out, server, SecretLocation::Env { name: k.clone() }, i);
            }
        }
        names.push(
            k.chars()
                .filter(|c| !c.is_control())
                .take(MAX_ID_LEN)
                .collect(),
        );
    }
    names.sort();
    names
}

/// Flag `--flag=value` and `--flag value` where the flag names a credential,
/// and any argument carrying a known token prefix.
fn args(server: &str, e: &Map<String, Value>, out: &mut Vec<SecretExposure>) {
    let Some(list) = e.get("args").and_then(Value::as_array) else {
        return;
    };
    let args: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
    for (i, a) in args.iter().enumerate() {
        if token_prefixed(a) {
            expose(
                out,
                server,
                SecretLocation::Arg { index: i },
                SecretIndicator::KnownTokenPrefix,
            );
            continue;
        }
        let Some(flag) = a.strip_prefix('-') else {
            continue;
        };
        match flag.split_once('=') {
            Some((name, value)) => {
                if let Some(ind) = indicator(name, value) {
                    expose(out, server, SecretLocation::Arg { index: i }, ind);
                }
            }
            None => {
                if credential_name(flag) {
                    if let Some(next) = args.get(i + 1) {
                        if let Some(ind) = indicator(flag, next) {
                            expose(out, server, SecretLocation::Arg { index: i + 1 }, ind);
                        }
                    }
                }
            }
        }
    }
}

fn headers(server: &str, e: &Map<String, Value>, out: &mut Vec<SecretExposure>) {
    let Some(hs) = e.get("headers").and_then(Value::as_object) else {
        return;
    };
    for (k, v) in hs {
        if let Some(value) = v.as_str() {
            if let Some(i) = indicator(k, value) {
                expose(out, server, SecretLocation::Header { name: k.clone() }, i);
            }
        }
    }
}
