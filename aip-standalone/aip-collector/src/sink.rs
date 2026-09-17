//! The evidence layer behind the transport: deserialize an authenticated
//! batch, bind it to the authenticated probe id, attest it under the wrapped
//! evidence key, and persist the new chain position.

use std::sync::{Arc, Mutex};

use aip_observe::{CollectorRuntime, ObservationBatch};
use aip_transport::{BatchAckData, BatchSink, SinkError};

/// Bridges [`aip_transport`]'s [`BatchSink`] to a shared [`CollectorRuntime`].
/// The lock is held only for the attest+persist of one batch, so concurrent
/// probe connections serialize per batch rather than per connection.
pub struct RuntimeSink {
    runtime: Arc<Mutex<CollectorRuntime>>,
}

impl RuntimeSink {
    pub fn new(runtime: Arc<Mutex<CollectorRuntime>>) -> Self {
        Self { runtime }
    }
}

impl BatchSink for RuntimeSink {
    fn accept_batch(
        &mut self,
        probe_id: &str,
        _seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError> {
        let batch: ObservationBatch = serde_json::from_slice(batch_bytes)
            .map_err(|e| SinkError(format!("batch is not a valid ObservationBatch: {e}")))?;

        // Bind the transport-authenticated identity to the batch's own claim: a
        // probe that authenticated as X may not submit a batch labelled Y. The
        // collector's registry further bounds which mechanisms probe X may
        // claim; this closes the identity half of that binding.
        if batch.probe_id != probe_id {
            return Err(SinkError(format!(
                "batch probe_id {:?} does not match the authenticated probe {:?}",
                batch.probe_id, probe_id
            )));
        }

        let mut rt = self
            .runtime
            .lock()
            .map_err(|_| SinkError("collector runtime lock poisoned".into()))?;
        let attested = rt
            .attest(batch)
            .map_err(|e| SinkError(format!("attest refused: {e:?}")))?;
        let head = rt.snapshot().head.unwrap_or([0u8; 32]);
        Ok(BatchAckData {
            attested_sequence: attested.sequence,
            head,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{CollectorKey, CollectorStore, ContinuityPolicy, ProcfsProbe, Started};

    fn dev_runtime(observer_id: &str, tag: &str) -> Arc<Mutex<CollectorRuntime>> {
        let dir = std::env::temp_dir().join(format!(
            "aip-sink-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CollectorStore::open(&dir).unwrap();
        let custodian = CollectorKey::development().into_custodian();
        let started = CollectorRuntime::start_with_custodian(
            store,
            observer_id,
            1,
            custodian,
            ContinuityPolicy::Strict,
        )
        .unwrap();
        match started {
            Started::Running(rt, _) => Arc::new(Mutex::new(rt)),
            Started::Refused(brk) => panic!("fresh dev runtime refused: {brk:?}"),
        }
    }

    fn batch_bytes(probe_id: &str) -> Vec<u8> {
        let mut probe = ProcfsProbe::new(probe_id);
        serde_json::to_vec(&probe.batch([1u8; 16], 100, 200, vec![])).unwrap()
    }

    #[test]
    fn accepts_a_batch_whose_probe_id_matches_the_authenticated_probe() {
        let mut sink = RuntimeSink::new(dev_runtime("obs", "match"));
        let bytes = batch_bytes("probe-1");
        assert!(sink.accept_batch("probe-1", 1, &bytes).is_ok());
    }

    #[test]
    fn refuses_a_batch_labelled_with_a_different_probe_id() {
        // Authenticated as "probe-authed" but the batch claims "probe-other":
        // the transport identity is bound to the batch's own claim.
        let mut sink = RuntimeSink::new(dev_runtime("obs", "mismatch"));
        let bytes = batch_bytes("probe-other");
        let err = sink
            .accept_batch("probe-authed", 1, &bytes)
            .expect_err("a probe_id mismatch must be refused");
        assert!(err.0.contains("does not match"), "{}", err.0);
    }

    #[test]
    fn refuses_bytes_that_are_not_an_observation_batch() {
        let mut sink = RuntimeSink::new(dev_runtime("obs", "garbage"));
        let err = sink
            .accept_batch("probe-1", 1, b"not json")
            .expect_err("garbage must be refused");
        assert!(err.0.contains("not a valid ObservationBatch"), "{}", err.0);
    }
}
