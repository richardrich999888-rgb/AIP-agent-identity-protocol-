//! Agent tool execution under AIP authority.
//!
//! - [`tool`]: tool manifests and the canonical parameter set that AIP signs.
//! - [`evidence`]: the runner-signed run record and its offline verifier.
//! - [`replay`]: one-shot consumption of decisions.
//!
//! The model never appears in this module. Whether a tool runs is decided by
//! the AIP decision point over a signed authority chain; a model's statement
//! that something is authorized has no input path here.

pub mod evidence;
pub mod replay;
pub mod tool;
