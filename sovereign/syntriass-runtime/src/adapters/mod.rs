//! IO adapters (sidecar process, scoped llama-server client, supervisor,
//! capability store, /proc meter).
pub mod llama_scoped;
pub mod meter;
pub mod pool;
pub mod sidecar;
pub mod store;
pub mod supervisor;
