//! Process-wide module registry.
//!
//! A PKCS#11 library is initialised at most once per process, and finalised
//! when the last handle to it drops. `cryptoki::Pkcs11` finalises on drop.
//! If two custodians each loaded the module independently, dropping one
//! would call `C_Finalize` under the other, and the survivor's next
//! operation would fail with `CKR_CRYPTOKI_NOT_INITIALIZED` — or, on a
//! vendor library that does not check, do something worse.
//!
//! So a module is loaded once per canonical path and shared. It is never
//! finalised before process exit, which is the right lifetime for a
//! daemon and harmless for a command-line tool.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};

use crate::error::HsmError;

static MODULES: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();

/// Load and initialise the module at `path`, or return the handle already
/// held for it.
pub fn load(path: &Path) -> Result<Pkcs11, HsmError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| HsmError::Module {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let registry = MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().map_err(|_| HsmError::SessionPoisoned)?;
    if let Some(existing) = map.get(&canonical) {
        return Ok(existing.clone());
    }

    let module = Pkcs11::new(&canonical).map_err(|e| HsmError::Module {
        path: canonical.display().to_string(),
        detail: e.to_string(),
    })?;
    // `OS_LOCKING_OK`: the module may use the OS's locking primitives to
    // make itself safe for concurrent calls from several threads. This is
    // the setting every multi-threaded application needs, and SoftHSM and
    // every hardware vendor library accept it.
    match module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        // Something else in this process already initialised the same
        // library (another binding, a vendor tool linked in). Sharing it
        // is correct; failing would be the bug.
        Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => {
            return Err(HsmError::Module {
                path: canonical.display().to_string(),
                detail: e.to_string(),
            })
        }
    }
    map.insert(canonical, module.clone());
    Ok(module)
}
