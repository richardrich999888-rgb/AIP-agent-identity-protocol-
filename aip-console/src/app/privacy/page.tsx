import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/LegalPage";

export const metadata: Metadata = {
  title: "Privacy | SYNTRIASS AIP Console",
};

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacy Policy"
      updated="2026-11-02"
      sections={[
        {
          heading: "Data Processed",
          body: "The SYNTRIASS AIP Console processes AIP EvidencePacket files exclusively within your browser. No file contents, cryptographic payloads, or verification results are transmitted to any external server. All verification is performed locally by the embedded WebAssembly engine.",
        },
        {
          heading: "Local Storage and Session Data",
          body: "Loaded evidence packets and verification results are held in browser memory for the duration of your session only. No data is persisted to localStorage, IndexedDB, or any server-side store. Closing or refreshing the browser tab clears all session data.",
        },
        {
          heading: "Cookies and Tracking",
          body: "This console does not set any tracking cookies, analytics beacons, or third-party scripts. No user telemetry, behavioural analytics, or usage data is collected.",
        },
        {
          heading: "Contact",
          body: "For privacy-related enquiries, contact the SYNTRIASS security team at the address listed in your enterprise service agreement. This placeholder must be replaced with verified contact details before production use.",
        },
      ]}
    />
  );
}
