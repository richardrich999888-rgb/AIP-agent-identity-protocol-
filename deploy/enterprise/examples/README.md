# Configuration examples

Reuse the daemon's actual configuration contracts:

- `deploy/pilot/probe.env.example` — approved host identity, collector endpoint,
  pinned Noise key, selected sensors, batch interval and transport-key path.
- `deploy/pilot/collector.env.example` — observer identity, wrapped-key path,
  strict continuity, state, probe allow-list, Noise key and clock discipline.
- `deploy/docker/docker-compose.yml` — existing evidence API/PostgreSQL
  topology; retain institution-controlled secrets and TLS ingress.

Copy a template, replace all placeholders and validate it with
`linux/package.py preflight --config-only`. No real credentials or plausible
invented banking records are provided. The live banking workflow and API
examples are documented in `docs/enterprise/BANK_INTEGRATION_GUIDE.md`.

For probe scope, the implemented sensor daemon observes host kernel events;
it has **no per-workload filter**. Fanotify is mount scoped and AF_PACKET can
be interface scoped. Decide permitted hosts/mounts/interfaces and privacy
boundaries before collection. Do not interpret a configured probe ID as
independent proof of a business agent's identity or complete task attribution.
