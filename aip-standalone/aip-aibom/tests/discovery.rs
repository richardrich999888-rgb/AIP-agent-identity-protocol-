//! MCP client configuration discovery (A11). Where a credential is, never
//! what it is.

use aip_aibom::adapters::mcp_config::{parse, McpConfigFile};
use aip_aibom::finding::{SecretIndicator, SecretLocation};
use aip_aibom::ports::{DiscoveryError, DiscoverySource, Transport};
use serde_json::json;

const SECRETS: [&str; 6] = [
    "sk-live-4f9a8c2e71b3",
    "hunter2-db-password",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "s3cr3t-query-token",
    "Bearer xoxb-1234-abcd",
    "user:pa55word",
];

fn config() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "mcpServers": {
            "ledger": {
                "command": "npx",
                "args": ["-y", "@acme/ledger-mcp", "--api-key", SECRETS[0]],
                "env": { "DB_PASSWORD": SECRETS[1], "REGION": "eu-west-1", "GITHUB_PAT": "${env:GITHUB_PAT}" }
            },
            "github": {
                "command": "docker",
                "args": ["run", SECRETS[2]]
            },
            "payments": {
                "url": format!("https://{}@payments.internal/mcp?token={}&tenant=7#frag", SECRETS[5], SECRETS[3]),
                "headers": { "Authorization": SECRETS[4], "X-Trace": "on" }
            },
            "notes": {
                "command": "uvx",
                "env": { "API_KEY": "$NOTES_KEY" }
            }
        }
    }))
    .unwrap()
}

#[test]
fn servers_are_discovered_with_their_transport() {
    let d = parse(&config(), "mcp.json").unwrap();
    let names: Vec<&str> = d.servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["github", "ledger", "notes", "payments"]);
    let payments = d.servers.iter().find(|s| s.name == "payments").unwrap();
    assert_eq!(
        payments.transport,
        Transport::Remote {
            endpoint: "https://payments.internal/mcp".into()
        }
    );
    let ledger = d.servers.iter().find(|s| s.name == "ledger").unwrap();
    assert_eq!(
        ledger.transport,
        Transport::Stdio {
            command: "npx".into()
        }
    );
    assert_eq!(ledger.env_names, ["DB_PASSWORD", "GITHUB_PAT", "REGION"]);
    assert_eq!(d.source.sha256.len(), 64);
}

#[test]
fn inline_credentials_are_located() {
    let d = parse(&config(), "mcp.json").unwrap();
    let at = |server: &str, loc: SecretLocation| {
        d.exposures
            .iter()
            .any(|x| x.server == server && x.location == loc)
    };
    assert!(at("ledger", SecretLocation::Arg { index: 3 }));
    assert!(at(
        "ledger",
        SecretLocation::Env {
            name: "DB_PASSWORD".into()
        }
    ));
    assert!(at("github", SecretLocation::Arg { index: 1 }));
    assert!(at("payments", SecretLocation::UrlUserinfo));
    assert!(at(
        "payments",
        SecretLocation::UrlQuery {
            key: "token".into()
        }
    ));
    assert!(at(
        "payments",
        SecretLocation::Header {
            name: "Authorization".into()
        }
    ));
    let github = d.exposures.iter().find(|x| x.server == "github").unwrap();
    assert_eq!(github.indicator, SecretIndicator::KnownTokenPrefix);
}

/// A reference to a secret is not a secret.
#[test]
fn references_are_not_flagged() {
    let d = parse(&config(), "mcp.json").unwrap();
    assert!(!d.exposures.iter().any(|x| x.location
        == SecretLocation::Env {
            name: "GITHUB_PAT".into()
        }));
    assert!(!d.exposures.iter().any(|x| x.server == "notes"));
    assert!(!d.exposures.iter().any(|x| x.location
        == SecretLocation::Env {
            name: "REGION".into()
        }));
    assert!(!d.exposures.iter().any(|x| x.location
        == SecretLocation::UrlQuery {
            key: "tenant".into()
        }));
}

/// **A11.** No secret value survives into anything the discovery produces.
#[test]
fn no_secret_value_reaches_the_output() {
    let d = parse(&config(), "mcp.json").unwrap();
    let out = serde_json::to_string(&d).unwrap() + &format!("{d:?}");
    for s in SECRETS {
        for fragment in s.split([':', ' ']).filter(|f| f.len() > 4) {
            assert!(
                !out.contains(fragment),
                "secret fragment {fragment:?} leaked"
            );
        }
    }
}

/// A file that is not an MCP config is refused rather than read as "no tools"
/// — which would be an absence claim drawn from the wrong file.
#[test]
fn a_file_that_is_not_an_mcp_config_is_refused() {
    assert_eq!(
        parse(b"{\"name\": \"package\"}", "x").unwrap_err(),
        DiscoveryError::NotAnMcpConfig
    );
    assert!(matches!(
        parse(b"not json", "x").unwrap_err(),
        DiscoveryError::NotJson(_)
    ));
    assert_eq!(
        parse(b"{\"mcpServers\": {\"a\": 1}}", "x").unwrap_err(),
        DiscoveryError::NotAnMcpConfig
    );
}

#[test]
fn the_vscode_layout_is_read_too() {
    let d = parse(
        br#"{"servers": {"files": {"command": "node"}}}"#,
        ".vscode/mcp.json",
    )
    .unwrap();
    assert_eq!(d.servers[0].name, "files");
}

#[test]
fn a_control_character_in_a_server_name_is_refused() {
    let bytes =
        serde_json::to_vec(&json!({"mcpServers": {"evil\u{1b}[2J": {"command": "x"}}})).unwrap();
    assert!(matches!(
        parse(&bytes, "x").unwrap_err(),
        DiscoveryError::InvalidServerName(_)
    ));
}

#[test]
fn a_command_carrying_a_token_is_withheld() {
    let d = parse(
        br#"{"mcpServers": {"x": {"command": "sk-abc123 run"}}}"#,
        "x",
    )
    .unwrap();
    assert_eq!(
        d.servers[0].transport,
        Transport::Stdio {
            command: "<withheld>".into()
        }
    );
    assert_eq!(d.exposures[0].location, SecretLocation::Command);
}

#[test]
fn an_oversized_file_is_refused_not_truncated() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("oversized-mcp.json");
    let big = vec![b' '; (aip_aibom::model::limits::MAX_INPUT_BYTES + 1) as usize];
    std::fs::write(&path, big).unwrap();
    assert!(matches!(
        McpConfigFile::new(&path).discover().unwrap_err(),
        DiscoveryError::TooLarge { .. }
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn discovery_is_deterministic() {
    assert_eq!(
        parse(&config(), "a").unwrap(),
        parse(&config(), "a").unwrap()
    );
}

/// A credential-named value that is only a template — `${env:VAR}`, or
/// `Bearer ${TOKEN}` in a header — points at a secret; it is not one.
///
/// Written for mutation AB-36, which survived the first matrix run: the
/// existing fixture's templates sat under names no credential marker matched.
#[test]
fn a_template_under_a_credential_name_is_not_flagged() {
    let d = parse(
        br#"{"mcpServers": {"t": {
            "url": "https://api.example/mcp",
            "env": {"LEDGER_TOKEN": "${env:LEDGER_TOKEN}"},
            "headers": {"Authorization": "Bearer ${TOKEN}"}
        }}}"#,
        "x",
    )
    .unwrap();
    assert!(d.exposures.is_empty(), "{:?}", d.exposures);
}

/// `--password hunter2`: the value after a credential flag is located even
/// when it carries no recognisable token prefix.
///
/// Written for mutation AB-39, which survived the first matrix run: the
/// existing fixture's flag value began with `sk-`, so the prefix rule caught
/// it and the flag rule was never exercised.
#[test]
fn a_prefixless_value_after_a_credential_flag_is_located() {
    let d = parse(br#"{"mcpServers": {"db": {"command": "pg-mcp", "args": ["--host", "db.internal", "--password", "hunter2"]}}}"#, "x").unwrap();
    assert_eq!(d.exposures.len(), 1, "{:?}", d.exposures);
    assert_eq!(d.exposures[0].location, SecretLocation::Arg { index: 3 });
    assert_eq!(d.exposures[0].indicator, SecretIndicator::CredentialName);
    assert!(!serde_json::to_string(&d).unwrap().contains("hunter2"));
}
