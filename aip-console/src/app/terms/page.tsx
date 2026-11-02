import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/LegalPage";

export const metadata: Metadata = {
  title: "Terms | SYNTRIASS AIP Console",
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Terms of Use"
      updated="2026-11-02"
      sections={[
        {
          heading: "Permitted Use",
          body: "The AIP Enterprise Accountability Console is licensed for internal enterprise use only. You may use the console to inspect, verify, and audit AIP EvidencePackets that your organisation has authority to access. Redistribution, resale, or public hosting of this console is prohibited without a written licence from SYNTRIASS.",
        },
        {
          heading: "No Warranty",
          body: "The console is provided 'as is', without warranty of any kind, express or implied. Verification results produced by the WebAssembly engine are advisory; they do not constitute legal, regulatory, or compliance certification. SYNTRIASS makes no guarantee of the accuracy, completeness, or fitness for purpose of verification outputs.",
        },
        {
          heading: "Limitation of Liability",
          body: "To the maximum extent permitted by applicable law, SYNTRIASS and its licensors shall not be liable for any indirect, incidental, special, or consequential damages arising from use of this console, including but not limited to loss of data, loss of business, or regulatory penalties.",
        },
        {
          heading: "Governing Law",
          body: "These terms are governed by and construed in accordance with the laws of the jurisdiction specified in your enterprise service agreement. This placeholder must be replaced with verified legal language before production use.",
        },
      ]}
    />
  );
}
