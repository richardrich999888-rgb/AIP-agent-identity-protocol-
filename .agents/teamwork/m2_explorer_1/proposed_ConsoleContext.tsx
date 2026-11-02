"use client";

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  ReactNode,
} from "react";
import type {
  ConsoleTab,
  EvidencePacket,
  VerificationReport,
  VerificationContext,
} from "@/lib/types";

export interface ConsoleContextValue {
  activeTab: ConsoleTab;
  setActiveTab: (tab: ConsoleTab) => void;
  loadedPacket: EvidencePacket | null;
  rawPacketJson: string | null;
  contextJson: string | null;
  verificationReport: VerificationReport | null;
  loadedFilename: string | null;
  isOfflineMode: boolean;
  setIsOfflineMode: (offline: boolean) => void;
  isWasmReady: boolean;
  wasmError: string | null;
  setLoadedEvidence: (
    packetJson: string,
    filename?: string,
    contextJson?: string,
    report?: VerificationReport
  ) => void;
  loadFixture: (fixtureId: string) => Promise<void>;
  resetEvidence: () => void;
}

const ConsoleContext = createContext<ConsoleContextValue | undefined>(undefined);

export interface ConsoleProviderProps {
  children: ReactNode;
}

export const ConsoleProvider: React.FC<ConsoleProviderProps> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<ConsoleTab>("ingestion");
  const [loadedPacket, setLoadedPacket] = useState<EvidencePacket | null>(null);
  const [rawPacketJson, setRawPacketJson] = useState<string | null>(null);
  const [contextJson, setContextJson] = useState<string | null>(null);
  const [verificationReport, setVerificationReport] =
    useState<VerificationReport | null>(null);
  const [loadedFilename, setLoadedFilename] = useState<string | null>(null);
  const [isOfflineMode, setIsOfflineMode] = useState<boolean>(true);
  const [isWasmReady, setIsWasmReady] = useState<boolean>(false);
  const [wasmError, setWasmError] = useState<string | null>(null);

  // Initialize WebAssembly engine on mount
  useEffect(() => {
    let mounted = true;
    async function initEngine() {
      try {
        // Dynamically import WASM loader to ensure browser execution
        const wasmModule = await import("@/public/wasm/aip_wasm.js");
        if (typeof wasmModule.default === "function") {
          await wasmModule.default("/wasm/aip_wasm_bg.wasm");
        }
        if (typeof wasmModule.wasm_init === "function") {
          wasmModule.wasm_init();
        }
        if (mounted) {
          setIsWasmReady(true);
          setWasmError(null);
        }
      } catch (err: unknown) {
        console.warn("WASM Initialization Note:", err);
        if (mounted) {
          // If public wasm fetch failed or running in non-static environment,
          // record error message while allowing UI to render
          setIsWasmReady(false);
          setWasmError(err instanceof Error ? err.message : String(err));
        }
      }
    }

    initEngine();
    return () => {
      mounted = false;
    };
  }, []);

  const setLoadedEvidence = useCallback(
    (
      packetJson: string,
      filename: string = "evidence_packet.json",
      ctxJson?: string,
      report?: VerificationReport
    ) => {
      try {
        const parsed = JSON.parse(packetJson) as EvidencePacket;
        setLoadedPacket(parsed);
        setRawPacketJson(packetJson);
        setLoadedFilename(filename);
        if (ctxJson) {
          setContextJson(ctxJson);
        }
        if (report) {
          setVerificationReport(report);
        }
      } catch (err) {
        console.error("Failed to parse evidence packet JSON:", err);
      }
    },
    []
  );

  const resetEvidence = useCallback(() => {
    setLoadedPacket(null);
    setRawPacketJson(null);
    setContextJson(null);
    setVerificationReport(null);
    setLoadedFilename(null);
  }, []);

  const loadFixture = useCallback(
    async (fixtureId: string) => {
      try {
        // Fetch fixture JSON from /fixtures/
        const res = await fetch(`/fixtures/${fixtureId}.json`);
        if (!res.ok) throw new Error(`Fixture ${fixtureId} not found`);
        const text = await res.text();

        // Check if context file exists
        let ctxText: string | undefined;
        try {
          const ctxRes = await fetch(`/fixtures/${fixtureId}.context.json`);
          if (ctxRes.ok) {
            ctxText = await ctxRes.text();
          }
        } catch {
          // Context is optional
        }

        // Verify with WASM if available
        let report: VerificationReport | undefined;
        if (isWasmReady) {
          try {
            const wasm = await import("@/public/wasm/aip_wasm.js");
            const reportStr = wasm.verify_evidence_packet(text, ctxText ?? null);
            report = JSON.parse(reportStr) as VerificationReport;
          } catch (verifyErr) {
            console.error("Fixture verification error:", verifyErr);
          }
        }

        setLoadedEvidence(text, `${fixtureId}.json`, ctxText, report);
      } catch (err) {
        console.error(`Failed to load fixture ${fixtureId}:`, err);
      }
    },
    [isWasmReady, setLoadedEvidence]
  );

  return (
    <ConsoleContext.Provider
      value={{
        activeTab,
        setActiveTab,
        loadedPacket,
        rawPacketJson,
        contextJson,
        verificationReport,
        loadedFilename,
        isOfflineMode,
        setIsOfflineMode,
        isWasmReady,
        wasmError,
        setLoadedEvidence,
        loadFixture,
        resetEvidence,
      }}
    >
      {children}
    </ConsoleContext.Provider>
  );
};

export function useConsole(): ConsoleContextValue {
  const context = useContext(ConsoleContext);
  if (!context) {
    throw new Error("useConsole must be used within a ConsoleProvider");
  }
  return context;
}
