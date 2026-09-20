//! How a deployment names its module, token and key, and where the PIN
//! comes from.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::HsmError;

/// Where the user PIN is read from.
///
/// Never a command-line argument: those are visible to every process on
/// the host through `/proc/<pid>/cmdline`, and stay in shell history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    /// An environment variable, read once at open. The conventional choice
    /// under a process supervisor that injects secrets.
    Env(String),
    /// A file readable only by its owner. Trailing newline stripped.
    File(PathBuf),
}

impl PinSource {
    /// Read the PIN. The buffer is zeroed on drop.
    pub fn read(&self) -> Result<Zeroizing<String>, HsmError> {
        match self {
            Self::Env(name) => {
                let v = std::env::var(name).map_err(|_| {
                    HsmError::Pin(format!("environment variable `{name}` is not set"))
                })?;
                if v.is_empty() {
                    return Err(HsmError::Pin(format!(
                        "environment variable `{name}` is empty"
                    )));
                }
                Ok(Zeroizing::new(v))
            }
            Self::File(path) => read_owner_only_file(path),
        }
    }
}

/// Read a file that must be readable by its owner alone.
///
/// A PIN in a file other users can read is a PIN those users have. The
/// mode check is on Unix only; elsewhere the file is read as-is, and the
/// deployment is responsible for what its filesystem can enforce.
fn read_owner_only_file(path: &Path) -> Result<Zeroizing<String>, HsmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| HsmError::Pin(format!("{}: {e}", path.display())))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(HsmError::Pin(format!(
                "{} is mode {mode:o}; a PIN file must not be readable by group or others \
                 (chmod 600)",
                path.display()
            )));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| HsmError::Pin(format!("{}: {e}", path.display())))?;
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(HsmError::Pin(format!("{} is empty", path.display())));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

/// Everything needed to find one key in one token behind one module.
#[derive(Clone, PartialEq, Eq)]
pub struct Pkcs11Config {
    /// Path to the vendor's PKCS#11 shared library.
    pub module: PathBuf,
    /// The token's `CKA_LABEL`. Tokens are found by label rather than by
    /// slot number, because slot numbers change across restarts and
    /// firmware updates and a label does not.
    pub token_label: String,
    /// The key pair's `CKA_LABEL`. Both halves carry it.
    pub key_label: String,
    pub pin: PinSource,
}

impl std::fmt::Debug for Pkcs11Config {
    /// The PIN source is named, never its contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module", &self.module)
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field(
                "pin",
                &match &self.pin {
                    PinSource::Env(n) => format!("env:{n}"),
                    PinSource::File(p) => format!("file:{}", p.display()),
                },
            )
            .finish()
    }
}

impl Pkcs11Config {
    /// Reject what cannot work before the module is touched.
    pub fn validate(&self) -> Result<(), HsmError> {
        if self.module.as_os_str().is_empty() {
            return Err(HsmError::Config("module path is empty".into()));
        }
        if self.token_label.trim().is_empty() {
            return Err(HsmError::Config("token label is empty".into()));
        }
        if self.key_label.trim().is_empty() {
            return Err(HsmError::Config("key label is empty".into()));
        }
        // PKCS#11 token labels are 32 bytes, space-padded. A longer label
        // can never match anything.
        if self.token_label.len() > 32 {
            return Err(HsmError::Config(format!(
                "token label `{}` is {} bytes; PKCS#11 token labels are at most 32",
                self.token_label,
                self.token_label.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Pkcs11Config {
        Pkcs11Config {
            module: PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
            token_label: "aip".into(),
            key_label: "reconciler-1".into(),
            pin: PinSource::Env("AIP_PKCS11_PIN".into()),
        }
    }

    #[test]
    fn a_well_formed_config_validates() {
        cfg().validate().unwrap();
    }

    #[test]
    fn empty_fields_are_refused_before_the_module_is_touched() {
        let mut c = cfg();
        c.token_label = "  ".into();
        assert!(matches!(c.validate(), Err(HsmError::Config(_))));
        let mut c = cfg();
        c.key_label = String::new();
        assert!(matches!(c.validate(), Err(HsmError::Config(_))));
        let mut c = cfg();
        c.module = PathBuf::new();
        assert!(matches!(c.validate(), Err(HsmError::Config(_))));
    }

    #[test]
    fn a_token_label_longer_than_pkcs11_allows_is_refused() {
        let mut c = cfg();
        c.token_label = "x".repeat(33);
        assert!(matches!(c.validate(), Err(HsmError::Config(_))));
    }

    /// The Debug output is what ends up in a log line.
    #[test]
    fn debug_names_the_pin_source_and_never_a_pin() {
        std::env::set_var("AIP_HSM_TEST_PIN_DEBUG", "s3cret-pin");
        let mut c = cfg();
        c.pin = PinSource::Env("AIP_HSM_TEST_PIN_DEBUG".into());
        let d = format!("{c:?}");
        assert!(d.contains("env:AIP_HSM_TEST_PIN_DEBUG"), "{d}");
        assert!(!d.contains("s3cret"), "{d}");
    }

    #[test]
    fn an_unset_or_empty_env_pin_is_refused() {
        std::env::remove_var("AIP_HSM_TEST_PIN_UNSET");
        assert!(matches!(
            PinSource::Env("AIP_HSM_TEST_PIN_UNSET".into()).read(),
            Err(HsmError::Pin(_))
        ));
        std::env::set_var("AIP_HSM_TEST_PIN_EMPTY", "");
        assert!(matches!(
            PinSource::Env("AIP_HSM_TEST_PIN_EMPTY".into()).read(),
            Err(HsmError::Pin(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_pin_file_readable_by_others_is_refused_and_an_owner_only_one_is_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aip-hsm-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let loose = dir.join("loose");
        std::fs::write(&loose, "1234\n").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = PinSource::File(loose.clone()).read().unwrap_err();
        assert!(err.to_string().contains("chmod 600"), "{err}");

        let tight = dir.join("tight");
        std::fs::write(&tight, "1234\n").unwrap();
        std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(PinSource::File(tight).read().unwrap().as_str(), "1234");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
