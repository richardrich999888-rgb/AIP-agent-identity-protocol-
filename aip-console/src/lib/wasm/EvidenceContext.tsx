"use client";

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  ReactNode,
} from "react";
import type {
  VerificationReport,
  BundleVerificationResult,
  AccountabilityGraph,
  LoadedEvidence,
} from "./types";
import { useAipVerifier } from "./useAipVerifier";
import { SAMPLE_FIXTURES } from "./fixtures";

export interface EvidenceContextValue {
  evidence: LoadedEvidence | null;
  report: VerificationReport | null;
  graph: AccountabilityGraph | null;
  bundleResult: BundleVerificationResult | null;
  contextJson: string;
  isVerifying: boolean;
  error: string | null;

  loadPacket: (packetJson: string, fileName?: string, contextOverride?: string) => Promise<void>;
  loadBundle: (zipBytes: Uint8Array, fileName?: string, contextOverride?: string) => Promise<void>;
  loadFixture: (fixtureId: string) => Promise<void>;
  updateContext: (newContextJson: string) => void;
  reverify: () => Promise<void>;
  clearEvidence: () => void;
}

const EvidenceContext = createContext<EvidenceContextValue | null>(null);

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const verifier = useAipVerifier();
  const [evidence, setEvidence] = useState<LoadedEvidence | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [graph, setGraph] = useState<AccountabilityGraph | null>(null);
  const [bundleResult, setBundleResult] = useState<BundleVerificationResult | null>(null);
  const [contextJson, setContextJson] = useState<string>("{}");
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPacket = useCallback(
    async (packetJson: string, fileName = "evidence.json", contextOverride?: string) => {
      setIsVerifying(true);
      setError(null);
      try {
        const activeContext = contextOverride ?? contextJson;
        const rep = verifier.verifyPacket(packetJson, activeContext);
        let gr: AccountabilityGraph | null = null;
        try {
          gr = verifier.getAccountabilityGraph(packetJson, JSON.stringify(rep));
        } catch (graphErr) {
          console.warn("Could not compute accountability graph:", graphErr);
        }

        setReport(rep);
        setGraph(gr);
        setBundleResult(null);
        if (contextOverride !== undefined) {
          setContextJson(contextOverride);
        }
        setEvidence({
          fileName,
          fileType: "json",
          packetJson,
          contextJson: activeContext,
          report: rep,
          graph: gr || undefined,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg || "Verification failed");
      } finally {
        setIsVerifying(false);
      }
    },
    [verifier, contextJson]
  );

  const loadBundle = useCallback(
    async (zipBytes: Uint8Array, fileName = "audit_bundle.zip", contextOverride?: string) => {
      setIsVerifying(true);
      setError(null);
      try {
        const activeContext = contextOverride ?? contextJson;
        const bResult = verifier.verifyBundleZip(zipBytes, activeContext);
        const extracted = verifier.extractBundle(zipBytes);

        let rep: VerificationReport | null = null;
        let gr: AccountabilityGraph | null = null;
        let packetJson = "";

        if (extracted["evidence.json"]) {
          packetJson = extracted["evidence.json"];
          try {
            rep = verifier.verifyPacket(packetJson, activeContext);
            gr = verifier.getAccountabilityGraph(packetJson, JSON.stringify(rep));
          } catch (packetErr) {
            console.warn("Could not verify inner evidence packet:", packetErr);
          }
        }

        setBundleResult(bResult);
        setReport(rep);
        setGraph(gr);
        if (contextOverride !== undefined) {
          setContextJson(contextOverride);
        }
        setEvidence({
          fileName,
          fileType: "zip",
          packetJson,
          contextJson: activeContext,
          rawBytes: zipBytes,
          report: rep || undefined,
          bundleResult: bResult,
          graph: gr || undefined,
          extractedFiles: extracted,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg || "Bundle verification failed");
      } finally {
        setIsVerifying(false);
      }
    },
    [verifier, contextJson]
  );

  const loadFixture = useCallback(
    async (fixtureId: string) => {
      const fixture = SAMPLE_FIXTURES.find((f) => f.id === fixtureId);
      if (!fixture) throw new Error(`Unknown fixture: ${fixtureId}`);

      let ctx = "{}";
      if (fixture.context_filename) {
        try {
          ctx = verifier.getSample(fixture.context_filename);
        } catch {
          const res = await fetch(`/fixtures/${fixture.context_filename}`);
          if (res.ok) ctx = await res.text();
        }
      }

      if (fixture.format === "zip") {
        const res = await fetch(`/fixtures/${fixture.filename}`);
        if (!res.ok) throw new Error(`Failed to fetch ${fixture.filename}`);
        const buf = await res.arrayBuffer();
        await loadBundle(new Uint8Array(buf), fixture.filename, ctx);
      } else {
        let packet = "";
        try {
          packet = verifier.getSample(fixture.id);
        } catch {
          const res = await fetch(`/fixtures/${fixture.filename}`);
          if (!res.ok) throw new Error(`Failed to fetch ${fixture.filename}`);
          packet = await res.text();
        }
        await loadPacket(packet, fixture.filename, ctx);
      }
    },
    [verifier, loadBundle, loadPacket]
  );

  const reverify = useCallback(async () => {
    if (!evidence) return;
    if (evidence.fileType === "zip" && evidence.rawBytes) {
      await loadBundle(evidence.rawBytes, evidence.fileName, contextJson);
    } else if (evidence.packetJson) {
      await loadPacket(evidence.packetJson, evidence.fileName, contextJson);
    }
  }, [evidence, contextJson, loadBundle, loadPacket]);

  const updateContext = useCallback((newContextJson: string) => {
    setContextJson(newContextJson);
  }, []);

  const clearEvidence = useCallback(() => {
    setEvidence(null);
    setReport(null);
    setGraph(null);
    setBundleResult(null);
    setError(null);
  }, []);

  return (
    <EvidenceContext.Provider
      value={{
        evidence,
        report,
        graph,
        bundleResult,
        contextJson,
        isVerifying,
        error,
        loadPacket,
        loadBundle,
        loadFixture,
        updateContext,
        reverify,
        clearEvidence,
      }}
    >
      {children}
    </EvidenceContext.Provider>
  );
}

export function useEvidence(): EvidenceContextValue {
  const context = useContext(EvidenceContext);
  if (!context) {
    throw new Error("useEvidence must be used within an EvidenceProvider");
  }
  return context;
}
