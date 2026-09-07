//! Construction failures. Every variant is a refusal.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// A registration window that applies at no instant.
    EmptyRegistrationWindow,
    /// Two registrations for one host-boot would apply at the same instant.
    /// Refused rather than resolved by precedence: guessing which was meant is
    /// how a hardware replacement gets attributed to the wrong platform.
    OverlappingRegistration,
    /// A structure carried a version this build does not implement.
    UnsupportedVersion { found: u16, supported: u16 },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::EmptyRegistrationWindow => write!(
                f,
                "registration window is empty or inverted; a registration that \
                 applies at no instant is not a registration"
            ),
            PlatformError::OverlappingRegistration => write!(
                f,
                "another registration for this host-boot already applies over \
                 the same interval; close the existing entry before opening a \
                 new one"
            ),
            PlatformError::UnsupportedVersion { found, supported } => write!(
                f,
                "platform-binding structure version {found} is not implemented \
                 by this build (supported: {supported}); refusing rather than \
                 guessing what the fields mean"
            ),
        }
    }
}

impl std::error::Error for PlatformError {}
