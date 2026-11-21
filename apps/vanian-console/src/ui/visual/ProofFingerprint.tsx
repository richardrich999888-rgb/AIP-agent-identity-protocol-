"use client";
import { I } from "../primitives";

type State = "waiting" | "checking" | "accepted" | "rejected";

export function ProofFingerprint({
  state,
  digest,
  observer,
  verdict,
}: {
  state: State;
  digest?: string;
  observer: boolean;
  verdict?: string | null;
}) {
  const valid =
    state === "accepted" &&
    typeof digest === "string" &&
    /^[a-f0-9]{64}$/i.test(digest);
  return (
    <div
      className="fingerprint-panel"
      role="group"
      aria-label="Verifier output summary"
    >
      <div className="fingerprint-caption">
        <I n={observer ? "fingerprint" : "key"} size={15} />
        {observer ? "Signed chain head" : "Action verdict"}
      </div>
      {valid ? (
        <>
          <div className="fingerprint-bytes" aria-hidden="true">
            {digest!.match(/../g)!.map((byte, i) => (
              <i
                key={i}
                style={{ opacity: 0.14 + (parseInt(byte, 16) / 255) * 0.86 }}
              />
            ))}
          </div>
          <samp>{digest!.match(/.{8}/g)?.join(" ")}</samp>
        </>
      ) : (
        <p>
          {state === "checking"
            ? "Verification in progress…"
            : state === "rejected"
              ? "Evidence rejected by the verifier"
              : !observer && verdict
                ? verdict
                : state === "accepted"
                  ? "Chain head unavailable"
                  : "Awaiting verifier output"}
        </p>
      )}
    </div>
  );
}
