# Operations runbook — AIP Ghost pilot (R15)

For the team on call. It assumes the pilot topology in `README.md`: probes
on the agent hosts, a collector off-host holding the evidence key, the
service holding evidence, verdicts and ledgers, and a witness
(`ANCHOR_WITNESS.md`) on a system the platform team does not administer.

Every instruction below is something a person can carry out at 03:00
without reading the source.

---

## 0. The one thing to understand before anything else

This system's outputs are three-valued: a thing proven, a thing disproven,
and **the absence of evidence**, which is never converted into either.

`CANNOT_PROVE` is not "clean". It means the evidence was insufficient to
classify the execution. A dashboard tile that renders it green is
misconfigured, and an analyst who treats it as an all-clear has drawn the
one conclusion this system is built to prevent.

The same applies to the anchor audit (`NotEvaluated` is not `Consistent`)
and to an incident bundle's coverage (empty `gaps` means the batches claim
the window, not that nothing happened).

---

## 1. Signals

### 1.1 Metrics

`GET /metrics` on the service, Prometheus text format, **authenticated** —
the scraper sends a bearer token like any other client. Counters are
aggregate: there are no tenant, agent or document labels, deliberately, so
a shared scrape is not a cross-tenant disclosure channel.

| Metric | Alert when | Why |
|---|---|---|
| `aip_verdicts_rejected_total` | rate > 0 | Something is submitting verdicts the service will not stand behind. Nothing is stored, so this counter is the **only** place the refusal is visible. |
| `aip_ledgers_rejected_total` | rate > 0 | As above, for access ledgers. |
| `aip_siem_exports_refused_total` | any increase | A verdict could not be rendered unambiguously and **did not reach the SIEM**. An adverse finding may be sitting in the store with nobody looking at it. |
| `aip_auth_failures_total` | sustained rise | Credential problem, or someone probing. |
| `aip_evidence_stored_total` | **rate falls to zero** | The absence of an alert is not the same as nothing happening. A pipeline that stopped looks identical to a quiet day. |

The last row is the one teams forget. Alert on silence.

### 1.2 What has no metric, on purpose

No request-latency histogram (bucket choice is a deployment decision and
nothing requires it), and no per-tenant series. If a tenant needs its own
volume, serve it from that tenant's own authenticated view, not from a
shared scrape.

### 1.3 SIEM

Verdicts reach the SIEM as CEF over RFC 5424 syslog. Route on `cs1`
(`AipResult`), not on the CEF severity: severity is a routing hint this
exporter supplies because the format makes it mandatory, and it is not
part of anything the reconciler signed.

| `cs1` | Meaning |
|---|---|
| `IDENTITY_DIVERGENCE` | The instance observed differs from the one authorized. **Page.** |
| `SENSOR_INTEGRITY_FAILURE` | The observation cannot be relied on for that window. **Page** — this is the one an attacker causes on purpose. |
| `UNATTRIBUTED_EFFECT` | An attested effect with an attested absence of authorization. **Page.** |
| `PHANTOM_CLAIM` | Authorized, never observed, under full kernel coverage. Investigate. |
| `CONTINUITY_FAILURE` | The observer attests a break. Investigate the host. |
| `LINEAGE_VIOLATION` | Observed ancestry contradicts the authority chain. Investigate. |
| `CANNOT_PROVE` | **Not clean.** Triage in bulk: a rising proportion means coverage is degrading. |
| `VERIFIED_EXECUTION` | Nothing to do. |

`cs4` is the verdict digest. Use it to pull the document
(`GET /v1/verdicts/{id}`) and verify it yourself rather than trusting the
log line.

---

## 2. Procedures

### 2.1 `SENSOR_INTEGRITY_FAILURE` or a rising `CANNOT_PROVE` rate

Symptom: verdicts for a host stop being classifiable, or the observer
reports a per-mechanism integrity finding.

1. Identify the host from the evidence references in the verdict.
2. On that host, check whether the probe is running and which mechanisms
   it currently has: `systemctl status aip-probe`, then its log for the
   per-mechanism integrity line.
3. A foreign-eBPF finding means another program attached to the same
   tracepoints. That is either an EDR agent that was installed, or an
   attacker. **Establish which before deciding it is benign.** The change
   ticket for the EDR rollout is the evidence; its absence is not proof of
   an attack but is the point at which this stops being routine.
4. Do not restart the probe to "clear" the finding. The finding is the
   product. Restarting loses the window that would have shown when it
   started.
5. Record the window in the incident record. Verdicts over that window are
   not evidence of absence.

### 2.2 The pipeline went quiet

Symptom: `aip_evidence_stored_total` flat, no alerts.

1. Probe → collector: is the probe running, and is the collector
   accepting? Check the collector's health endpoint.
2. Collector → service: are batches being filed?
3. If the probe is running and the collector is not receiving, treat the
   gap as uncovered from the last attested batch. It is not a quiet
   period.
4. When service is restored, do **not** backfill the gap. There is nothing
   to backfill: the observations were never made. The gap is a fact and an
   incident bundle over that window will state it.

### 2.3 CERT-In: a reportable incident, six-hour clock

1. Decide the window and the agent.
2. Assemble the bundle:

   ```
   aip-incident export --agent <agent-id> --from <ms> --to <ms> \
     --exporter <id>:<ver> --key "$EXPORTER_KEY_HEX" \
     --batch batch1.json --batch batch2.json \
     --verdict verdict1.json --ledger ledger.json --health health.json \
     --out incident-<ref>.json
   ```

   It reads only files. It does not call the collector or the service —
   an incident is the wrong moment to discover a network path is down.

3. **Read the coverage line it prints before you read anything else.** If
   it says `INCOMPLETE`, the report must say so too. Every gap is printed
   with its bounds.
4. Check the bundle before sending it:
   `aip-incident verify incident-<ref>.json --trust <id>:<ver>=<pubkey>`.
   This recomputes coverage from the enclosed evidence; a bundle whose
   stated gaps do not match its evidence fails here.
5. `aip-incident summary incident-<ref>.json` produces the narrative,
   leading with what is missing.
6. Filing — to whom, on which form, within which clock — is the entity's
   process. This produces the evidence it attaches.

### 2.4 Anchor audit before any regulatory submission

Run the audit against the live log and attach the result. A submission
resting on a log whose history was never witnessed rests on the operator's
word.

```
aip-anchor verify --receipts receipts.jsonl \
  --trust-witness <id>:<ver>=<pubkey_hex>
```

`NotEvaluated` is not a pass. If there are no receipts, say so in the
submission rather than omitting the question.

### 2.5 A missed anchoring window

Symptom: no receipt for longer than the agreed cadence.

Records committed since the last receipt are the records a rewrite could
still remove undetected. Restore anchoring first, then note the exposed
interval — it is the blast radius, and it is a fact about the evidence,
not an operational blemish to be smoothed over.

---

## 3. What is not automated, and will not be

| Thing | Whose |
|---|---|
| Deciding a foreign eBPF program is the EDR and not an attacker | The security team's, with the change record |
| Filing to CERT-In within six hours | The entity's incident process |
| Placing the witness on a system the platform team does not administer | The entity's, and no code can check it |
| Backup, DR and a tested restore of the evidence store | Open — see matrix row E5 |
| Acting on a verdict (containment, kill-switch) | The entity's orchestration. Containment is advisory in pilot. |

---

## 4. Escalation

An `IDENTITY_DIVERGENCE`, `UNATTRIBUTED_EFFECT` or
`SENSOR_INTEGRITY_FAILURE` on a transaction-critical resource is a
security incident from the moment it is seen, not after triage. Pull the
verdict by digest, verify it, and escalate with the document — not with
the log line.
