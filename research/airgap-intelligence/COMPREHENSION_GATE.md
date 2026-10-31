# Comprehension gate — answers

F = fact from this repository or a cited source. H = hypothesis.

1. **Air-gapped economy.** Organisations whose data may not reach external AI
   providers (policy) or whose networks are physically disconnected. Distinct
   because every runtime dependency — inference, auth, updates, telemetry,
   frontend assets — must be local, and updates cross the gap by a human
   procedure. (F: requirements; market size not measured.)
2. **Why local LLMs are not enough.** Hosting a model does not provide access
   control inside retrieval, offline updates, evidence of what the AI did, or
   affordable hardware sizing. (F for what the slice adds; customer demand is H.)
3. **Why SLMs.** Cost: 1.5B Q4 runs on 2 vCPU in 1.8 GB. But measured: they do
   not reliably compare numbers or decide; they interpret narrow text. SLMs are
   proposed for interpretation and routing, not as frontier substitutes. (F)
4. **Jev-style decisions vs generation.** A typed answer (choice/score/yes-no)
   read in one pass instead of free text. Measured here: single-token decisions
   matched JSON decisions on accuracy at 4–7.6× throughput — but both near chance
   at 1.5B. Faster classification is not reasoning. (F)
5. **What iteration 1 established.** (F) Deterministic parts reproduce bit-for-
   bit. Decision-by-model ≈ chance at 0.5/1.5B. Model-extracts + code-decides
   scored 0.977 on test_para. **But** (iteration 2 P0) a (equipment, unit) rule
   scores 1.000 on the same split, so iteration 1 did not demonstrate
   paraphrase understanding. Prefix caching cut p95 7×. Multi-reading
   extraction was poor (0.107 exact match).
6. **Why keep intelligence outside the weights.** Policies change, must be
   exact, versioned and auditable; retraining per customer is costly and
   untraceable. Executable rules are exact where the vocabulary matches. (F/H)
7. **What we borrow from BitTorrent.** Content-addressed chunks verified against
   a signed hash list, served by peers that already verified them. Already
   implemented by Dragonfly (CNCF). (F)
8. **Files vs tasks vs one model's inference.** Files: same bytes to many
   nodes. Tasks: different work to different nodes. Partitioning: one forward
   pass split across nodes, paying network latency per token and exposing
   inputs to early partitions (Petals). (F)
9. **Workstations as a private intelligence system.** Plausible for embarrassingly
   parallel, small, independent tasks (batch extraction over many documents) on
   nodes cleared for that data. Bad idea for interactive generation across
   machines, for data whose clearance the node lacks, or when one server is
   cheaper to operate. (H; nothing built)
10. **Authorisation and classification in scheduling.** A node may receive a
    task only if it is cleared for every datum the task carries; peer identity
    proves who the node is, not what it may see. Intermediate results inherit
    the classification of their inputs unless shown otherwise. (H, design rule)
11. **Updates into disconnected environments.** Built on a connected staging
    host, hashed, approved out of band, carried by the customer's procedure,
    verified before install. No signed release bundle is produced yet. (F gap)
12. **Reusable AIP / Sniffer Dog.** aip-authorize (decision point,
    ExpectedExecution), aip-core (identities, tokens, execution binding) are
    used by the slice now. aip-probe/collector/observe-verify/reconcile build
    here and tracefs mounts, so independent observation is feasible but not
    integrated; reconciler's ceiling is CANNOT_PROVE with identity match. (F)
13. **Possible novelty and its threats.** Narrow: one offline-verifiable record
    binding interpretation uncertainty, a signed policy version, evidence
    references and AIP authorisation/reconciliation. Threats: function calling,
    semantic parsing, GLiNER, in-toto/Sigstore provenance, Dragonfly. Unsearched. (H)
14. **Buildable and demonstrable now.** Offline grounded Q&A with access control
    and withheld unsupported answers; AIP-authorised sandboxed tool with offline
    verification and honest CannotProve; the extraction-plus-policy comparison
    from iteration 2. (F)
15. **Single most valuable experiment.** Whether a cheap interpreter + exact
    policy matches LLM extraction on inputs rules cannot solve — iteration 2.
16. **What would make us abandon P2P.** A measured LAN test where one internal
    artifact server (or off-the-shelf Dragonfly) meets the fleet's update
    window — then a custom P2P layer adds risk without value.
17. **Customer problem per component.** Exact layer → correctness and audit;
    small interpreters → hardware cost; retrieval with ACL → confidentiality;
    escalation → quality where needed; AIP → accountability for actions; signed
    manifests → supply-chain integrity; P2P → fleet update bandwidth (only for
    large fleets).

## Internal inconsistencies in the brief, stated not resolved

- "Global enterprise intelligence comparable to leading assistants" vs "small
  models on limited CPUs": measured evidence supports narrow interpretation,
  not general reasoning, at this size.
- "P2P mesh" as a core layer vs "single-node must work without it": treat the
  mesh as optional; the product must stand without it.
- Product rename to SYNTRIASS vs VANIAN-attributed code and patents: ownership
  is unresolved and must be settled by the founder with documentation.
