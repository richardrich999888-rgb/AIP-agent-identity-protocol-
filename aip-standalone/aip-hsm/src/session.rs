//! Finding a token and logging a session in — shared by the custodian and
//! by provisioning so the two cannot disagree about either.

use cryptoki::context::Pkcs11;
use cryptoki::error::{Error, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::config::Pkcs11Config;
use crate::error::HsmError;
use crate::module;

/// The slot whose token carries `label`. Labels are matched after trimming
/// the space padding PKCS#11 stores them with.
pub(crate) fn find_token(pkcs11: &Pkcs11, label: &str) -> Result<Slot, HsmError> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| HsmError::from_cryptoki("C_GetSlotList", e))?;
    let mut present = Vec::with_capacity(slots.len());
    for slot in slots {
        let info = pkcs11
            .get_token_info(slot)
            .map_err(|e| HsmError::from_cryptoki("C_GetTokenInfo", e))?;
        let found = info.label().trim_end().to_string();
        if found == label {
            return Ok(slot);
        }
        present.push(found);
    }
    Err(HsmError::TokenNotFound {
        label: label.to_string(),
        present,
    })
}

/// Log the session in as the token user.
///
/// # `CKR_USER_ALREADY_LOGGED_IN` is success
///
/// PKCS#11 login state belongs to the **token, per application**, not to
/// the session: once any session in this process is logged in, every other
/// session on the same token is too, and a further `C_Login` returns
/// `CKR_USER_ALREADY_LOGGED_IN`. A daemon holding two custodians on one
/// token — two key labels, one module — reaches this on its second open.
/// The session is in the state we need, so it is treated as success.
///
/// The consequence is stated rather than hidden: a second custodian's PIN
/// is not checked when the first has already logged in. That is the
/// standard's model of a PIN — it opens the token to the application — and
/// not something a custodian can tighten from the application side.
pub(crate) fn login_user(session: &Session, config: &Pkcs11Config) -> Result<(), HsmError> {
    let pin = config.pin.read()?;
    match session.login(UserType::User, Some(&AuthPin::from(pin.as_str()))) {
        Ok(()) => Ok(()),
        Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(e) => Err(HsmError::Login(e.to_string())),
    }
}

/// Which kind of session to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Enough to sign. Least privilege for the custodian.
    ReadOnly,
    /// Required to create token objects. Provisioning only.
    ReadWrite,
}

/// Load the module, find the token, open a session, log in.
pub(crate) fn open_logged_in(config: &Pkcs11Config, access: Access) -> Result<Session, HsmError> {
    config.validate()?;
    let pkcs11 = module::load(&config.module)?;
    let slot = find_token(&pkcs11, &config.token_label)?;
    let session = match access {
        Access::ReadOnly => pkcs11.open_ro_session(slot),
        Access::ReadWrite => pkcs11.open_rw_session(slot),
    }
    .map_err(|e| HsmError::from_cryptoki("C_OpenSession", e))?;
    login_user(&session, config)?;
    Ok(session)
}
