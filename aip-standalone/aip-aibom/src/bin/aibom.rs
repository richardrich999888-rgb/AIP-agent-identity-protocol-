//! `aibom` — assess, compare, discover and digest AI agent bills of materials.
//!
//! An interface and nothing else: it reads files, calls the library, and
//! writes what the library returns. No decision is made here.
//!
//! Exit status: `0` success; `1` an input could not be read or was refused;
//! `2` the assessment has a `Critical` finding, or the diff widens what the
//! agent may do — so the command can gate a pipeline.

use aip_aibom::adapters::mcp_config::McpConfigFile;
use aip_aibom::evidence::{AssessorContext, ContextFile, EvidenceBundle};
use aip_aibom::model::limits::MAX_INPUT_BYTES;
use aip_aibom::ports::DiscoverySource;
use aip_aibom::seal::Seal;
use aip_aibom::{assess, canonical, diff, report, Inputs, Manifest};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_INPUT: u8 = 1;
const EXIT_GATE: u8 = 2;

#[derive(Parser)]
#[command(
    name = "aibom",
    version,
    about = "AI Agent Bill of Materials: who vouches for each field"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum AssessFormat {
    Text,
    Json,
    FieldsCsv,
    FindingsCsv,
}

#[derive(Clone, Copy, ValueEnum)]
enum PlainFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Print a manifest's canonical SHA-256.
    Digest {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Assess a manifest against offered evidence and the assessor's context.
    Assess {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        seal: Option<PathBuf>,
        /// Evidence offered by the assessed party. Untrusted.
        #[arg(long)]
        evidence: Option<PathBuf>,
        /// The assessor's trust inputs. Without one, nothing verifies.
        #[arg(long)]
        context: Option<PathBuf>,
        /// MCP client configuration files to discover tools from. Repeatable.
        #[arg(long = "mcp-config")]
        mcp_configs: Vec<PathBuf>,
        /// The assessor's present time, Unix milliseconds. Required: the
        /// assessment reads no clock.
        #[arg(long)]
        now_ms: u64,
        #[arg(long, value_enum, default_value = "text")]
        format: AssessFormat,
    },
    /// Report what changed between two versions of a manifest.
    Diff {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: PlainFormat,
    },
    /// Discover tools from MCP client configuration files.
    Discover {
        #[arg(long = "mcp-config", required = true)]
        mcp_configs: Vec<PathBuf>,
    },
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("{}: {}", path.display(), e.kind()))?;
    let mut buf = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {}", path.display(), e.kind()))?;
    if buf.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{}: larger than {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    Ok(buf)
}

fn manifest(path: &Path) -> Result<Manifest, String> {
    Manifest::from_json(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Digest { manifest: p } => {
            println!("sha256:{}", canonical::manifest_digest_hex(&manifest(&p)?));
            Ok(EXIT_OK)
        }
        Command::Assess {
            manifest: mp,
            seal,
            evidence,
            context,
            mcp_configs,
            now_ms,
            format,
        } => {
            let m = manifest(&mp)?;
            let seal: Option<Seal> = match seal {
                Some(p) => Some(
                    serde_json::from_slice(&read(&p)?)
                        .map_err(|e| format!("{}: {e}", p.display()))?,
                ),
                None => None,
            };
            let bundle = match evidence {
                Some(p) => EvidenceBundle::from_json(&read(&p)?)
                    .map_err(|e| format!("{}: {e}", p.display()))?,
                None => EvidenceBundle::default(),
            };
            let ctx = match context {
                Some(p) => ContextFile::from_json(&read(&p)?)
                    .and_then(|c| c.into_context(now_ms))
                    .map_err(|e| format!("{}: {e}", p.display()))?,
                None => AssessorContext::trusting_nothing(now_ms),
            };
            let mut discoveries = Vec::new();
            for p in &mcp_configs {
                discoveries.push(
                    McpConfigFile::new(p)
                        .discover()
                        .map_err(|e| format!("{}: {e}", p.display()))?,
                );
            }
            let a = assess(&Inputs {
                manifest: &m,
                seal: seal.as_ref(),
                bundle: &bundle,
                context: &ctx,
                discoveries: &discoveries,
            });
            print!(
                "{}",
                match format {
                    AssessFormat::Text => report::assessment_text(&a),
                    AssessFormat::Json => report::assessment_json(&a),
                    AssessFormat::FieldsCsv => report::fields_csv(&a),
                    AssessFormat::FindingsCsv => report::findings_csv(&a),
                }
            );
            Ok(if a.has_critical() { EXIT_GATE } else { EXIT_OK })
        }
        Command::Diff { old, new, format } => {
            let changes = diff::diff(&manifest(&old)?, &manifest(&new)?);
            print!(
                "{}",
                match format {
                    PlainFormat::Text => report::changes_text(&changes),
                    PlainFormat::Json => report::changes_json(&changes),
                }
            );
            Ok(if diff::widens(&changes) {
                EXIT_GATE
            } else {
                EXIT_OK
            })
        }
        Command::Discover { mcp_configs } => {
            let mut all = Vec::new();
            for p in &mcp_configs {
                all.push(
                    McpConfigFile::new(p)
                        .discover()
                        .map_err(|e| format!("{}: {e}", p.display()))?,
                );
            }
            let mut s = serde_json::to_string_pretty(&all).expect("discoveries are plain data");
            s.push('\n');
            print!("{s}");
            Ok(EXIT_OK)
        }
    }
}

fn main() -> ExitCode {
    // clap exits 2 on a usage error, which is this tool's "gate tripped"
    // status. A mistyped flag must never read as a security finding, so usage
    // errors are mapped to the input-error status; help and version still
    // succeed.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { EXIT_INPUT } else { EXIT_OK });
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("aibom: {e}");
            ExitCode::from(EXIT_INPUT)
        }
    }
}
