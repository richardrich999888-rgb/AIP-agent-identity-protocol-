"use client";
import type { Entry, Provenance } from "../../types";
import { useDesk } from "../context";
import { I, stamp } from "../primitives";
import "./instrument.css";

export function RuntimeMasthead({ compact = false }: { compact?: boolean }) {
  const d = useDesk();
  const bundle = d.data;
  if (!bundle) return null;
  const inCommandCenter = d.page.slug === "sniffer-dog";
  return (
    <SensorCoverage
      compact={compact}
      meta={bundle.meta}
      sensors={bundle.sensors ?? []}
      onOpen={inCommandCenter ? undefined : () => d.go("sniffer-dog")}
      onEvidence={() => d.go("evidence-audit")}
      onSensor={(id) =>
        inCommandCenter
          ? d.set({ sensor: id, page: null })
          : d.go("sniffer-dog?sensor=" + encodeURIComponent(id))
      }
    />
  );
}

export function SensorCoverage({
  compact = false,
  meta,
  sensors,
  onOpen,
  onSensor,
  onEvidence,
}: {
  compact?: boolean;
  meta: Pick<Provenance, "mode" | "asOf" | "source">;
  sensors: Entry[];
  onOpen?: () => void;
  onSensor: (id: string) => void;
  onEvidence: () => void;
}) {
  const archive = meta.mode === "live";
  const groups = [...new Set(sensors.map((sensor) => sensor.group))];
  const healthy = sensors.filter((sensor) => sensor.state === "Healthy").length;
  const delayed = sensors.filter((sensor) => sensor.state === "Delayed").length;

  return (
    <section
      className={"card fleet-card" + (compact ? " fleet-compact" : "")}
      data-tour="sensor"
      aria-label={
        archive ? "Observer archive coverage" : "Sniffer Dog sensor coverage"
      }
    >
      <div className="fleet-head">
        <div>
          <h2>{archive ? "Observer archive coverage" : "Sensor coverage"}</h2>
          <p>
            {archive
              ? meta.source
              : "Sniffer Dog · independent runtime sensors"}
          </p>
        </div>
        {onOpen && (
          <button type="button" className="text-btn" onClick={onOpen}>
            Inspect <I n="right" size={14} />
          </button>
        )}
      </div>
      {sensors.length > 0 ? (
        <>
          <div
            className="fleet-legend"
            role="group"
            aria-label="Reported sensor health"
          >
            <span>
              <i data-state="Healthy" />
              <b>{healthy}</b> healthy
            </span>
            {delayed > 0 && (
              <span>
                <i data-state="Delayed" />
                <b>{delayed}</b> delayed
              </span>
            )}
            {sensors.length > healthy + delayed && (
              <span>
                <i />
                <b>{sensors.length - healthy - delayed}</b> other
              </span>
            )}
          </div>
          <div
            className="fleet-matrix"
            role="group"
            aria-label="Sensors by organization group"
          >
            <div className="fleet-labels" aria-hidden="true">
              <span>Group</span>
              <span>Sensor · latest heartbeat</span>
            </div>
            {groups.map((group) => (
              <div key={group} className="fleet-row">
                <strong>{group}</strong>
                <div className="fleet-hosts">
                  {sensors
                    .filter((sensor) => sensor.group === group)
                    .map((sensor) => (
                      <button
                        type="button"
                        key={sensor.id}
                        data-state={sensor.state}
                        onClick={() => onSensor(sensor.id)}
                        title={
                          sensor.name +
                          " · " +
                          sensor.state +
                          " · " +
                          stamp(sensor.at, true)
                        }
                        aria-label={
                          "Inspect " +
                          sensor.name +
                          ", " +
                          sensor.state +
                          ", " +
                          sensor.group
                        }
                      >
                        <i data-state={sensor.state} aria-hidden="true" />
                        {sensor.name}
                      </button>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="fleet-empty">
          <I n="radio" size={20} />
          <p>
            {archive
              ? "This source supplies signed observations. Fleet-wide sensor health is unavailable."
              : "No sensor heartbeats in the selected scope."}
          </p>
          {archive && (
            <button type="button" className="text-btn" onClick={onEvidence}>
              Inspect archive evidence <I n="right" size={13} />
            </button>
          )}
        </div>
      )}
      <div className="fleet-foot">
        <span>
          {archive ? "Archive attestation" : "Synthetic heartbeat snapshot"}
        </span>
        <time dateTime={meta.asOf}>{stamp(meta.asOf, true)}</time>
      </div>
    </section>
  );
}
