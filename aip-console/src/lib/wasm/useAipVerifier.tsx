"use client";

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useRef,
  useCallback,
  ReactNode,
} from "react";
import type {
  AipVerifierContextValue,
  VerificationReport,
  BundleVerificationResult,
  AccountabilityGraph,
  KeypairResult,
} from "./types";

let wasmModulePromise: Promise<unknown> | null = null;
let wasmModuleInstance: unknown = null;

async function loadWasm(): Promise<any> {
  if (wasmModuleInstance) return wasmModuleInstance;
  if (wasmModulePromise) return wasmModulePromise;

  wasmModulePromise = (async () => {
    if (typeof window === "undefined") {
      throw new Error("AIP WebAssembly verifier must run in a client browser environment.");
    }

    try {
      // Dynamic import with webpackIgnore prevents Next.js bundler from attempting SSR bundling
      // @ts-ignore - dynamic runtime browser import from public/wasm/
      const wasm = await import(/* webpackIgnore: true */ "/wasm/aip_wasm.js");
      if (typeof wasm.default === "function") {
        await wasm.default("/wasm/aip_wasm_bg.wasm");
      }

      if (typeof wasm.wasm_init === "function") {
        try {
          wasm.wasm_init();
        } catch {
          // Hook already registered
        }
      }

      wasmModuleInstance = wasm;
      return wasm;
    } catch (err: unknown) {
      wasmModulePromise = null;
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to initialize AIP WebAssembly verifier: ${msg}`);
    }
  })();

  return wasmModulePromise;
}

const AipVerifierContext = createContext<AipVerifierContextValue | null>(null);

export function AipVerifierProvider({ children }: { children: ReactNode }) {
  const [isReady, setIsReady] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const wasmRef = useRef<any>(null);

  const initVerifier = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const wasm = await loadWasm();
      wasmRef.current = wasm;
      setIsReady(true);
      setIsLoading(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || "Failed to initialize WebAssembly");
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    initVerifier();
  }, [initVerifier]);

  const verifyPacket = useCallback(
    (packetJson: string, contextJson?: string): VerificationReport => {
      if (!wasmRef.current) {
        throw new Error("AIP WebAssembly verifier is not initialized.");
      }
      const raw = wasmRef.current.verify_evidence_packet(
        packetJson,
        contextJson && contextJson.trim().length > 0 ? contextJson : null
      );
      return JSON.parse(raw) as VerificationReport;
    },
    []
  );

  const verifyBundleZip = useCallback(
    (zipBytes: Uint8Array, contextJson?: string): BundleVerificationResult => {
      if (!wasmRef.current) {
        throw new Error("AIP WebAssembly verifier is not initialized.");
      }
      const raw = wasmRef.current.verify_bundle_zip(
        zipBytes,
        contextJson && contextJson.trim().length > 0 ? contextJson : null
      );
      return JSON.parse(raw) as BundleVerificationResult;
    },
    []
  );

  const getAccountabilityGraph = useCallback(
    (packetJson: string, reportJson?: string): AccountabilityGraph => {
      if (!wasmRef.current) {
        throw new Error("AIP WebAssembly verifier is not initialized.");
      }
      const raw = wasmRef.current.get_accountability_graph(
        packetJson,
        reportJson && reportJson.trim().length > 0 ? reportJson : null
      );
      return JSON.parse(raw) as AccountabilityGraph;
    },
    []
  );

  const recomputeHash = useCallback((packetJson: string): string => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    return wasmRef.current.recompute_packet_hash(packetJson);
  }, []);

  const getCanonicalBytesHex = useCallback((packetJson: string): string => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    return wasmRef.current.get_canonical_bytes_hex(packetJson);
  }, []);

  const checkScope = useCallback((scopeJson: string, actionJson: string): boolean => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    return wasmRef.current.check_scope_permits(scopeJson, actionJson);
  }, []);

  const meetScopes = useCallback((parentJson: string, childJson: string): string => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    return wasmRef.current.meet_capability_scopes(parentJson, childJson);
  }, []);

  const extractBundle = useCallback((zipBytes: Uint8Array): Record<string, string> => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    const raw = wasmRef.current.extract_bundle_files(zipBytes);
    return JSON.parse(raw) as Record<string, string>;
  }, []);

  const getSample = useCallback((sampleType: string): string => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    return wasmRef.current.get_sample_packet(sampleType);
  }, []);

  const generateKeypair = useCallback((): KeypairResult => {
    if (!wasmRef.current) {
      throw new Error("AIP WebAssembly verifier is not initialized.");
    }
    const raw = wasmRef.current.generate_keypair();
    return JSON.parse(raw) as KeypairResult;
  }, []);

  const value: AipVerifierContextValue = {
    isReady,
    isLoading,
    error,
    verifyPacket,
    verifyBundleZip,
    getAccountabilityGraph,
    recomputeHash,
    getCanonicalBytesHex,
    checkScope,
    meetScopes,
    extractBundle,
    getSample,
    generateKeypair,
    initVerifier,
  };

  return <AipVerifierContext.Provider value={value}>{children}</AipVerifierContext.Provider>;
}

export function useAipVerifier(): AipVerifierContextValue {
  const context = useContext(AipVerifierContext);
  if (!context) {
    throw new Error("useAipVerifier must be used within an AipVerifierProvider");
  }
  return context;
}
