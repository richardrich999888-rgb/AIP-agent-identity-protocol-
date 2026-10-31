//! [`ModelProvider`] over supervised llama-server processes.
//!
//! Resident profiles keep the server between requests; non-resident
//! (memory) profiles start it for the request and stop it afterwards, so
//! idle memory is only the runtime and the sidecar. The measured load time
//! is returned per call and charged to that request's cost.

use std::cell::RefCell;
use std::path::PathBuf;

use vanian_sovereign::ports::PortError;

use super::meter::ProcMeter;
use super::supervisor::{ModelServer, Profile};
use crate::app::ModelProvider;
use crate::controller::Tier;
use crate::ports::ScopedGenerator;

/// One configured tier.
pub struct TierSlot {
    pub profile: Profile,
    pub port: u16,
    server: RefCell<Option<ModelServer>>,
}

impl TierSlot {
    pub fn new(profile: Profile, port: u16) -> Self {
        Self {
            profile,
            port,
            server: RefCell::new(None),
        }
    }
}

/// Supervised models for the small (C) and optional large (D) tiers.
pub struct Pool<'m> {
    pub binary: PathBuf,
    pub workdir: PathBuf,
    pub small: Option<TierSlot>,
    pub large: Option<TierSlot>,
    pub meter: &'m ProcMeter,
}

impl Pool<'_> {
    fn slot(&self, t: Tier) -> Option<&TierSlot> {
        match t {
            Tier::Small => self.small.as_ref(),
            Tier::Large => self.large.as_ref(),
        }
    }

    /// Stop every server (end of a batch).
    pub fn shutdown(&self) -> Result<(), PortError> {
        for (name, s) in [("llama-small", &self.small), ("llama-large", &self.large)] {
            if let Some(s) = s {
                if let Some(srv) = s.server.borrow_mut().take() {
                    self.meter.untrack(name);
                    srv.stop()?;
                }
            }
        }
        Ok(())
    }
}

impl ModelProvider for Pool<'_> {
    fn configured(&self, tier: Tier) -> bool {
        self.slot(tier).is_some()
    }

    fn model_sha256(&self, tier: Tier) -> Option<String> {
        self.slot(tier).map(|s| s.profile.model_sha256.clone())
    }

    fn with<'a>(
        &'a self,
        tier: Tier,
        f: &mut dyn FnMut(&dyn ScopedGenerator) -> Result<(), PortError>,
    ) -> Result<f64, PortError> {
        let slot = self.slot(tier).ok_or_else(|| {
            PortError::new(
                vanian_sovereign::ports::PortErrorKind::Inference,
                "tier not configured",
            )
        })?;
        let name = if tier == Tier::Small {
            "llama-small"
        } else {
            "llama-large"
        };
        let mut load_ms = 0.0;
        if slot.server.borrow().is_none() {
            let srv = ModelServer::start(&self.binary, &slot.profile, slot.port, &self.workdir)?;
            load_ms = srv.load_ms + srv.verify_ms;
            self.meter.track(name, srv.pid());
            *slot.server.borrow_mut() = Some(srv);
        }
        let r = {
            let guard = slot.server.borrow();
            let srv = guard.as_ref().ok_or_else(|| {
                PortError::new(
                    vanian_sovereign::ports::PortErrorKind::Inference,
                    "server missing",
                )
            })?;
            f(&srv.client)
        };
        if !slot.profile.resident {
            if let Some(srv) = slot.server.borrow_mut().take() {
                self.meter.untrack(name);
                srv.stop()?;
            }
        }
        r.map(|_| load_ms)
    }
}
