# Two-host independent qualification — BLOCKED

No independently administered Host A/Host B pair or external reviewer was
provided. No two-host acceptance experiment was run. The local container and a
GitHub VM are two environments used at different times; they are not the
requested simultaneous, independently administered deployment.

The existing `aip-probe`, authenticated transport, collector and offline verifier
are the starting point. Host A must run synthetic workloads and the authorised
sensor with no verifier/collector private signing material. Host B's administrator
must provision collector keys, trust anchors and durable checkpoints outside A's
administrative control. Both administrators must record their access boundaries.

Required evidence: authenticated collector registration; actual key-access
denials; exact binary/config/source hashes; signed originals and loss/clock/health
records; independent checkpoints; offline verdict reproduction; replay/tamper,
wrong-tenant/anchor, interruption and recovery tests; signed reviewer disposition.
Capture permitted file/process/network actions and preserve unattributed events.

Even with Host B independent, a sensor inside Host A still trusts A's kernel.
Call this remote collection/verification unless independent observation is
separately demonstrated. Distinct keys, UIDs, containers or VM names do not
establish administrative separation. No engineering script can self-approve this
external gate. Budget/credentials/host approval are not assumed.
