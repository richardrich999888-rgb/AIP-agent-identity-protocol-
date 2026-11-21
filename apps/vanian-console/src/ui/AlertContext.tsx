"use client";
import type { Entry } from "../types";
import { Badge, DataPairs, I } from "./primitives";

export function AlertContext({ record }: { record: Entry }) {
  const fields = record.fields;
  const value = (key: string) => String(fields[key] ?? "Unspecified");
  return (
    <section className="alert-context">
      <h3>Record context</h3>
      <div
        className="case-route"
        aria-label="Source and destination"
        role="group"
      >
        <div>
          <small>Source identity</small>
          <strong>{value("actor")}</strong>
          <code>{value("workload")}</code>
        </div>
        <I n="right" size={17} />
        <div>
          <small>Destination</small>
          <strong>{value("app")}</strong>
          <code>{value("model")}</code>
        </div>
      </div>
      <div className="case-outcome">
        <div>
          <small>Policy decision</small>
          <Badge>{value("decision")}</Badge>
        </div>
        <div>
          <small>Enforcement</small>
          <b>{value("enforcement")}</b>
        </div>
        <div>
          <small>Attribution confidence</small>
          <b>
            {typeof fields.confidence === "number"
              ? fields.confidence + "%"
              : "Unspecified"}
          </b>
        </div>
      </div>
      <DataPairs
        items={[
          [
            "Matched policy",
            value("policy") +
              (fields.policyVersion ? " · " + fields.policyVersion : ""),
          ],
          ["Guardrail", value("guardrail")],
          ["Classified intent", value("intent")],
          ["Correlation", value("correlation")],
        ]}
      />
      <details className="case-identifiers">
        <summary>Identities and evidence</summary>
        <DataPairs
          items={[
            ["Observation source", record.source],
            ["Group", record.group],
            ["Agent ID", value("agent")],
            ["Parent agent", value("parent")],
            ["Human owner", value("owner")],
            ["Tool", value("tool")],
            ["Sensor", value("sensor")],
            ["Trace", value("trace")],
            ["Evidence batch", value("batch")],
          ]}
        />
      </details>
    </section>
  );
}
