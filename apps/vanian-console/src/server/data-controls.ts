import { z } from "zod";
export const dataSamples = {
  "Customer contact": "Send the approved statement to analyst@example.invalid.",
  "Financial record":
    "Internal demo account DEMO-ACCOUNT-0042 has an approved statement.",
  "Service token": "The fixture credential is demo_secret_AABBCC448877.",
  "Public summary": "The public policy summary is ready.",
};
const patterns: [string, RegExp][] = [
  ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
  ["Financial identifier", /\bDEMO-ACCOUNT-\d{4}\b/g],
  ["Secret", /\bdemo_secret_[A-Za-z0-9]+\b/g],
];
export async function testDataControl(input: unknown) {
  const v = z
    .object({
      sample: z.enum([
        "Customer contact",
        "Financial record",
        "Service token",
        "Public summary",
      ]),
      treatment: z.enum(["Mask", "Redact", "Tokenize"]),
    })
    .parse(input);
  const source = dataSamples[v.sample];
  let output = source;
  const findings: string[] = [];
  const tokens = new Map<string, string>();
  for (const [kind, pattern] of patterns) {
    output = output.replace(pattern, (value) => {
      findings.push(kind);
      if (v.treatment === "Redact") return "[REDACTED]";
      if (v.treatment === "Mask")
        return value.slice(0, 1) + "••••••" + value.slice(-1);
      if (!tokens.has(value))
        tokens.set(value, "demo_tok_" + crypto.randomUUID().slice(0, 8));
      return tokens.get(value)!;
    });
  }
  return {
    mode: "demo",
    source: "Synthetic DLP test catalog",
    processedAt: new Date().toISOString(),
    status: "Processed",
    sample: v.sample,
    findings,
    output,
    treatment: v.treatment,
  };
}
