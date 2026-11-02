"use client";

import React, { ReactNode } from "react";
import { AipVerifierProvider } from "@/lib/wasm/useAipVerifier";
import { EvidenceProvider } from "@/lib/wasm/EvidenceContext";
import { ConsoleProvider } from "@/lib/context/ConsoleContext";

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <AipVerifierProvider>
      <EvidenceProvider>
        <ConsoleProvider>{children}</ConsoleProvider>
      </EvidenceProvider>
    </AipVerifierProvider>
  );
}
