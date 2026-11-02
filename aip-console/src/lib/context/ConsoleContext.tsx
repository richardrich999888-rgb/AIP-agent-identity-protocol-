"use client";

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  ReactNode,
} from "react";
import type {
  ConsoleTab,
  EvidencePacket,
  VerificationReport,
} from "@/lib/types";
import { useEvidence } from "@/lib/wasm/EvidenceContext";
import { useAipVerifier } from "@/lib/wasm/useAipVerifier";

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
  const [isOfflineMode, setIsOfflineMode] = useState<boolean>(true);

  const verifier = useAipVerifier();
  const evidenceContext = useEvidence();

  const loadedPacket: EvidencePacket | null = React.useMemo(() => {
    if (!evidenceContext.evidence?.packetJson) return null;
    try {
      return JSON.parse(evidenceContext.evidence.packetJson) as EvidencePacket;
    } catch {
      return null;
    }
  }, [evidenceContext.evidence?.packetJson]);

  const setLoadedEvidence = useCallback(
    (
      packetJson: string,
      filename: string = "evidence_packet.json",
      ctxJson?: string
    ) => {
      evidenceContext.loadPacket(packetJson, filename, ctxJson);
    },
    [evidenceContext]
  );

  return (
    <ConsoleContext.Provider
      value={{
        activeTab,
        setActiveTab,
        loadedPacket,
        rawPacketJson: evidenceContext.evidence?.packetJson ?? null,
        contextJson: evidenceContext.contextJson,
        verificationReport: evidenceContext.report,
        loadedFilename: evidenceContext.evidence?.fileName ?? null,
        isOfflineMode,
        setIsOfflineMode,
        isWasmReady: verifier.isReady,
        wasmError: verifier.error,
        setLoadedEvidence,
        loadFixture: evidenceContext.loadFixture,
        resetEvidence: evidenceContext.clearEvidence,
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
