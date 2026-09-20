//! Argument parsing, as a pure function over the argument vector.
//!
//! Hand-rolled on `std` rather than taken from a parser crate. The flag set
//! is small and fixed, and this is the binary whose whole claim is that an
//! auditor can verify evidence with the minimum they must trust; every
//! transitive dependency it pulls in is something else they would have to
//! account for. Sixty lines of `match` is the cheaper obligation.

use std::path::PathBuf;

/// Everything the verifier was asked to do. Construction is validated: an
/// `Options` that exists is one the verifier can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub observer_id: String,
    pub key_version: u32,
    /// The anchor, as 32 raw bytes. The institution holds this independently
    /// of the collector; see `observer.pub` beside the collector state.
    pub public_key: [u8; 32],
    pub batches: Option<PathBuf>,
    pub health: Option<PathBuf>,
    pub json: bool,
}

/// What the parser decided. `Help` and `Version` are outcomes, not errors,
/// so the caller does not have to infer intent from an error string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    Run(Box<Options>),
    Help,
    Version,
}

pub const USAGE: &str = "\
aip-observe-verify — offline verifier for the observer's evidence archives

USAGE:
    aip-observe-verify --observer-id <ID> --key-version <N> (--pubkey <HEX> | --pubkey-file <PATH>)
                       [--batches <PATH>] [--health <PATH>] [--json]

At least one of --batches or --health is required.

OPTIONS:
    --observer-id <ID>     The collector's observer id, as it appears in the records.
    --key-version <N>      Which of that observer's keys is anchored (u32).
    --pubkey <HEX>         The anchored Ed25519 public key, 64 hex characters.
    --pubkey-file <PATH>   Read the key from a file instead; the collector writes
                           `observer.pub` in its state directory at every start.
    --batches <PATH>       Attested-batch archive, JSONL (attested.archive.jsonl).
    --health <PATH>        Signed-health archive, JSONL (health.archive.jsonl).
    --json                 Emit the report as JSON instead of text.
    -h, --help             Print this and exit 0.
    -V, --version          Print the version and exit 0.

EXIT STATUS:
    0  every record verified and the chain links
    1  at least one finding; the report names each one
    2  the arguments could not be used

The verifier opens no socket, reads no environment, and contacts nothing. It
needs the archive files and the anchor, and nothing from the party that
produced them.
";

fn decode_key(hex_text: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_text.trim()).map_err(|e| format!("public key is not hex: {e}"))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| format!("public key must be 32 bytes, got {}", raw.len()))
}

/// Parse `args` (without the program name).
///
/// Every failure is a message the caller prints; there is no partial
/// `Options`. An unknown flag is refused rather than ignored — a verifier
/// that silently drops `--health` would report a clean pass over half the
/// evidence.
pub fn parse<I, S>(args: I) -> Result<Parse, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let argv: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut observer_id: Option<String> = None;
    let mut key_version: Option<u32> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut pubkey_file: Option<PathBuf> = None;
    let mut batches: Option<PathBuf> = None;
    let mut health: Option<PathBuf> = None;
    let mut json = false;

    let mut i = 0usize;
    // Each flag that takes a value consumes exactly one following argument;
    // a missing value is an error rather than a silently absorbed next flag.
    let value = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < argv.len() {
        match argv[i].as_str() {
            "-h" | "--help" => return Ok(Parse::Help),
            "-V" | "--version" => return Ok(Parse::Version),
            "--json" => json = true,
            "--observer-id" => observer_id = Some(value(&mut i, "--observer-id")?),
            "--key-version" => {
                let v = value(&mut i, "--key-version")?;
                key_version = Some(
                    v.trim()
                        .parse::<u32>()
                        .map_err(|e| format!("--key-version {v:?} is not a u32: {e}"))?,
                );
            }
            "--pubkey" => pubkey_hex = Some(value(&mut i, "--pubkey")?),
            "--pubkey-file" => pubkey_file = Some(PathBuf::from(value(&mut i, "--pubkey-file")?)),
            "--batches" => batches = Some(PathBuf::from(value(&mut i, "--batches")?)),
            "--health" => health = Some(PathBuf::from(value(&mut i, "--health")?)),
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += 1;
    }

    let observer_id = observer_id.ok_or("--observer-id is required")?;
    let key_version = key_version.ok_or("--key-version is required")?;
    if batches.is_none() && health.is_none() {
        return Err("at least one of --batches or --health is required".into());
    }
    let public_key = match (pubkey_hex, pubkey_file) {
        (Some(_), Some(_)) => {
            return Err("give --pubkey or --pubkey-file, not both".into());
        }
        (Some(h), None) => decode_key(&h)?,
        (None, Some(p)) => {
            let text = std::fs::read_to_string(&p)
                .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            decode_key(&text)?
        }
        (None, None) => return Err("--pubkey or --pubkey-file is required".into()),
    };

    Ok(Parse::Run(Box::new(Options {
        observer_id,
        key_version,
        public_key,
        batches,
        health,
        json,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn run(args: &[&str]) -> Result<Options, String> {
        match parse(args)? {
            Parse::Run(o) => Ok(*o),
            other => Err(format!("expected Run, got {other:?}")),
        }
    }

    #[test]
    fn parses_a_complete_invocation() {
        let o = run(&[
            "--observer-id",
            "collector.pilot",
            "--key-version",
            "1",
            "--pubkey",
            KEY,
            "--batches",
            "a.jsonl",
            "--health",
            "b.jsonl",
            "--json",
        ])
        .unwrap();
        assert_eq!(o.observer_id, "collector.pilot");
        assert_eq!(o.key_version, 1);
        assert_eq!(o.public_key, [0x11u8; 32]);
        assert_eq!(o.batches, Some(PathBuf::from("a.jsonl")));
        assert_eq!(o.health, Some(PathBuf::from("b.jsonl")));
        assert!(o.json);
    }

    #[test]
    fn help_and_version_are_outcomes_not_errors() {
        assert_eq!(parse(["--help"]).unwrap(), Parse::Help);
        assert_eq!(parse(["-V"]).unwrap(), Parse::Version);
    }

    // An unknown flag must not be ignored: the failure mode being guarded
    // against is a typo'd --health producing a clean pass over the batches
    // alone.
    #[test]
    fn an_unknown_flag_is_refused() {
        let e = run(&[
            "--observer-id",
            "o",
            "--key-version",
            "1",
            "--pubkey",
            KEY,
            "--batches",
            "a",
            "--helth",
            "b",
        ])
        .unwrap_err();
        assert!(e.contains("unknown argument"), "{e}");
    }

    #[test]
    fn nothing_to_verify_is_a_usage_error() {
        let e = run(&["--observer-id", "o", "--key-version", "1", "--pubkey", KEY]).unwrap_err();
        assert!(e.contains("at least one of"), "{e}");
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let e = run(&[
            "--observer-id",
            "o",
            "--key-version",
            "1",
            "--pubkey",
            "1122",
            "--batches",
            "a",
        ])
        .unwrap_err();
        assert!(e.contains("32 bytes"), "{e}");
    }

    #[test]
    fn a_non_hex_key_is_refused() {
        let e = run(&[
            "--observer-id",
            "o",
            "--key-version",
            "1",
            "--pubkey",
            "zz",
            "--batches",
            "a",
        ])
        .unwrap_err();
        assert!(e.contains("not hex"), "{e}");
    }

    #[test]
    fn a_flag_without_its_value_is_refused() {
        let e = parse(["--observer-id"]).unwrap_err();
        assert!(e.contains("needs a value"), "{e}");
    }

    #[test]
    fn two_sources_for_one_key_are_refused() {
        let e = run(&[
            "--observer-id",
            "o",
            "--key-version",
            "1",
            "--pubkey",
            KEY,
            "--pubkey-file",
            "k.pub",
            "--batches",
            "a",
        ])
        .unwrap_err();
        assert!(e.contains("not both"), "{e}");
    }

    #[test]
    fn a_key_version_that_is_not_a_number_is_refused() {
        let e = run(&[
            "--observer-id",
            "o",
            "--key-version",
            "one",
            "--pubkey",
            KEY,
            "--batches",
            "a",
        ])
        .unwrap_err();
        assert!(e.contains("not a u32"), "{e}");
    }
}
