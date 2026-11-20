"use client";
import { useEffect, useRef, useState } from "react";
import "./native-research.css";
import { startReplay } from "./startReplay";

import { ProofFingerprint } from "../visual/ProofFingerprint";
import "../visual/instrument.css";
type Sample = "t09" | "t15" | "same-run" | "same-run-interruption";
type Check = "original" | "tampered" | "wrong-key" | "missing-receipt";
type EventRow = {
  kind: string;
  monotonicNs: string | null;
  processId: number | null;
  parentPid: number | null;
  childPid: number | null;
  logicalAgentAttribution: string;
};
type Outcome = {
  accepted: boolean;
  verification?: string;
  verdict?: string | null;
  reason?: string | null;
  verifiedAt: string;
  sourceCommit: string;
  observerId?: string;
  agentId?: string;
  gatewayReceiptVerified?: boolean;
  authorizationVerified?: boolean;
  events?: EventRow[];
  findings?: { kind: string }[];
  scope?: {
    health: string[];
    finalHead?: string;
    withCoverage: number;
    droppedEvents: number;
    clockUnstated: number;
    collectorAttestedAt: string;
  };
};
const samples: Record<Sample, string> = {
  t09: "Process lifecycle capture",
  t15: "Sensor loss capture",
  "same-run": "Authorized tool request",
  "same-run-interruption": "Interrupted observation",
};
const checks: Record<Check, string> = {
  original: "Original evidence",
  tampered: "One changed byte",
  "wrong-key": "Different trust anchor",
  "missing-receipt": "Receipt removed",
};

export function NativeResearchPanel({
  initialSample = "t09",
}: {
  initialSample?: Sample;
}) {
  const [sample, setSample] = useState<Sample>(initialSample),
    [check, setCheck] = useState<Check>("original");
  const [result, setResult] = useState<Outcome | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const current = useRef<AbortController | null>(null);
  useEffect(() => () => current.current?.abort(), []);
  const observer = sample === "t09" || sample === "t15";
  const reset = () => {
    current.current?.abort();
    current.current = null;
    setResult(null);
    setError("");
    setBusy(false);
  };
  async function verify() {
    reset();
    const request = new AbortController();
    current.current = request;
    setBusy(true);
    try {
      const value = await startReplay<Outcome>(sample, check, request.signal);
      if (!request.signal.aborted) setResult(value);
    } catch (e) {
      if (!request.signal.aborted)
        setError(e instanceof Error ? e.message : "Verification failed.");
    } finally {
      if (current.current === request) setBusy(false);
    }
  }
  const checkState = busy
    ? "checking"
    : result
      ? result.accepted
        ? "accepted"
        : "rejected"
      : "waiting";
  return (
    <section
      className="native-research"
      aria-label="Research archive verification"
    >
      <header className="proof-bench" data-check-state={checkState}>
        <div className="proof-bench-copy">
          <span className="proof-source">Archived lab evidence</span>
          <h3>Research archive verification</h3>
          <p>
            Inspect a signed Sniffer Dog or AIP capture with the original
            verifier.
          </p>
          <div className="proof-bench-status" role="status">
            <i aria-hidden="true" />
            {busy
              ? "Verifier running"
              : result
                ? result.accepted
                  ? "Signature accepted"
                  : "Check rejected"
                : "Awaiting verification"}
          </div>
        </div>
        <div className="proof-bench-figure">
          <ProofFingerprint
            state={checkState}
            observer={observer}
            digest={result?.scope?.finalHead}
            verdict={result?.verdict}
          />
        </div>
      </header>
      <p className="proof-lab-date">Lab capture date · 14 November 2026</p>
      <div className="native-inputs">
        <label>
          Capture
          <select
            value={sample}
            onChange={(e) => {
              reset();
              setSample(e.target.value as Sample);
              setCheck("original");
            }}
          >
            {Object.entries(samples).map(([k, v]) => (
              <option value={k} key={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label>
          Integrity check
          <select
            value={check}
            onChange={(e) => {
              reset();
              setCheck(e.target.value as Check);
            }}
          >
            {(
              [
                "original",
                observer ? "tampered" : "missing-receipt",
                "wrong-key",
              ] as Check[]
            ).map((k) => (
              <option value={k} key={k}>
                {checks[k]}
              </option>
            ))}
          </select>
        </label>
        <button type="button" disabled={busy} onClick={verify}>
          {busy ? "Verifying…" : "Run upstream verifier"}
        </button>
      </div>
      <div aria-live="polite">
        {error && <p role="alert">{error}</p>}
        {result && (
          <div className="native-result">
            <div className="native-result-title">
              <b>{samples[sample]}</b>
              <span className={result.accepted ? "native-ok" : "native-fail"}>
                {result.accepted
                  ? observer
                    ? "Signature verified"
                    : "Reconciliation signature verified"
                  : "Evidence rejected"}
              </span>
            </div>
            {observer && result.scope && (
              <dl>
                <div>
                  <dt>Verified kernel events</dt>
                  <dd>{result.events?.length}</dd>
                </div>
                <div>
                  <dt>Signed sensor health</dt>
                  <dd>{result.scope.health.join(", ")}</dd>
                </div>
                <div>
                  <dt>Coverage assertions</dt>
                  <dd>{result.scope.withCoverage}</dd>
                </div>
                <div>
                  <dt>Dropped events</dt>
                  <dd>{result.scope.droppedEvents}</dd>
                </div>
                <div>
                  <dt>Logical agent binding</dt>
                  <dd>Unresolved</dd>
                </div>
                <div>
                  <dt>Collector attested at</dt>
                  <dd>{result.scope.collectorAttestedAt}</dd>
                </div>
              </dl>
            )}
            {!observer && result.verdict && (
              <dl>
                <div>
                  <dt>Action verdict</dt>
                  <dd>{result.verdict}</dd>
                </div>
                <div>
                  <dt>Reason</dt>
                  <dd>{result.reason}</dd>
                </div>
                <div>
                  <dt>Authorization</dt>
                  <dd>
                    {result.authorizationVerified ? "Verified" : "Unverified"}
                  </dd>
                </div>
                <div>
                  <dt>Gateway receipt</dt>
                  <dd>
                    {result.gatewayReceiptVerified
                      ? "Verified"
                      : "Unverified or absent"}
                  </dd>
                </div>
              </dl>
            )}
            {!result.accepted && (
              <p>
                {result.findings?.map((x) => x.kind).join(" · ") ||
                  result.reason ||
                  "The evidence did not pass verification."}
              </p>
            )}
            <p>
              Verified {new Date(result.verifiedAt).toLocaleString()} · Public
              lab trust anchors · Source {result.sourceCommit.slice(0, 8)}
            </p>
            <details>
              <summary>Inspect verifier output</summary>
              <code>{JSON.stringify(result, null, 2)}</code>
            </details>
          </div>
        )}
      </div>
    </section>
  );
}
export default NativeResearchPanel;
