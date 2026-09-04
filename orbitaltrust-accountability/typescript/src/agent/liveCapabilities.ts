// Binds the TacticalCapabilities interface to the live console: main's
// TacticalContext (Cesium viewer + TacticalEntityManager + LOD/layer
// state) and the ot-api backend client.
//
// This is the only file in src/agent that imports Cesium or knows about
// the console's internals; tactical-tools.ts stays pure and testable.
//
// Layer mapping: the copilot's domain-flavoured layer ids map onto the
// console's own LodLayer set, so a voice toggle and the LayerDeck drive
// exactly the same state. Infrastructure layers (cables/dams/
// datacenters) have no LodLayer counterpart and are owned by InfraLayers.

import {
  BoundingSphere,
  Cartesian3,
  Cartographic,
  Color,
  EasingFunction,
  HeadingPitchRange,
  Math as CesiumMath,
} from "cesium";
import { fetchConjunction, fetchSatellites, planAvoidance } from "../api/client";
import type { TacticalContext } from "../components/globe/TacticalGlobe";
import type { InfraLayers, InfraLayerId } from "../components/globe/effects/infraLayers";
import type { LodLayer } from "../core/LodController";
import type { SensorMode } from "../shaders/postProcessing";
import type {
  AvoidanceResult,
  BoundingBoxArgs,
  ConjunctionThreat,
  DataLayerId,
  FlyToArgs,
  NearbyContact,
  OrbitArgs,
  ShaderMode,
  TacticalCapabilities,
  ViewportContext,
} from "./capabilities";
import { resolveQuery } from "./capabilities";

const SHADER_TO_SENSOR: Record<ShaderMode, SensorMode> = {
  default: "visible",
  flir: "ironbow", // FLIR thermal maps to the Ironbow LUT pass
  ironbow: "ironbow",
  nvg: "nvg",
  crt: "crt",
};

const SENSOR_TO_SHADER: Record<SensorMode, ShaderMode> = {
  visible: "default",
  ironbow: "ironbow",
  nvg: "nvg",
  crt: "crt",
};

/** Copilot layer id → the console's own LOD layer. */
const LAYER_TO_LOD: Partial<Record<DataLayerId, LodLayer>> = {
  flights: "air",
  military_flights: "air", // the console does not separate military air yet
  vessels: "sea",
  satellites: "space",
  cctv: "cctv",
  fires: "thermal",
};

const INFRA_IDS: InfraLayerId[] = ["cables", "dams", "datacenters"];

function isInfra(layer: DataLayerId): layer is InfraLayerId {
  return (INFRA_IDS as string[]).includes(layer);
}

/** Great-circle range (km) and initial bearing (deg) between two points. */
function rangeBearing(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): { rangeKm: number; bearingDeg: number } {
  const R = 6371;
  const phi1 = CesiumMath.toRadians(lat1);
  const phi2 = CesiumMath.toRadians(lat2);
  const dPhi = CesiumMath.toRadians(lat2 - lat1);
  const dLam = CesiumMath.toRadians(lon2 - lon1);
  const a =
    Math.sin(dPhi / 2) ** 2 + Math.cos(phi1) * Math.cos(phi2) * Math.sin(dLam / 2) ** 2;
  const rangeKm = 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
  const y = Math.sin(dLam) * Math.cos(phi2);
  const x = Math.cos(phi1) * Math.sin(phi2) - Math.sin(phi1) * Math.cos(phi2) * Math.cos(dLam);
  const bearingDeg = (CesiumMath.toDegrees(Math.atan2(y, x)) + 360) % 360;
  return { rangeKm, bearingDeg };
}

export interface CapabilityDeps {
  ctx: TacticalContext;
  /** Infrastructure overlay owner (cables / dams / datacenters). */
  infra: InfraLayers;
  /** App's shader setter, so the HUD pills stay in sync. */
  setShaderMode: (mode: SensorMode) => void;
  /** Current shader mode, read from App state. */
  currentShaderMode: () => SensorMode;
  /** App's layer toggle — the same one the LayerDeck drives. */
  toggleLodLayer: (layer: LodLayer, on: boolean) => void;
  /** Currently enabled LOD layers, from App state. */
  enabledLodLayers: () => Set<LodLayer>;
  /** App's selection lock (entity id, and whether to fly the camera). */
  lockTarget: (entityId: string | null, fly: boolean) => void;
  /** Currently selected entity id, from App state. */
  selectedEntityId: () => string | null;
}

export function createCapabilities(deps: CapabilityDeps): TacticalCapabilities {
  const { ctx, infra } = deps;
  const viewer = ctx.handles.viewer;
  const entities = ctx.entities;

  /** Geodetic position of a console entity at the current clock time. */
  const entityLatLon = (
    entityId: string,
  ): { lat: number; lon: number; altM: number; position: Cartesian3 } | null => {
    const entity = entities.getEntity(entityId);
    const position = entity?.position?.getValue(viewer.clock.currentTime);
    if (!position) return null;
    const carto = Cartographic.fromCartesian(position);
    if (!carto) return null;
    return {
      lat: CesiumMath.toDegrees(carto.latitude),
      lon: CesiumMath.toDegrees(carto.longitude),
      altM: carto.height,
      position,
    };
  };

  return {
    async flyToLocation(args: FlyToArgs): Promise<string> {
      let lat = args.lat;
      let lon = args.lon;
      let altitude = args.altitude ?? 250_000;
      let label = "those coordinates";
      if ((lat === undefined || lon === undefined) && args.query) {
        const resolved = resolveQuery(args.query);
        if (!resolved) return `I don't have coordinates for "${args.query}".`;
        lat = resolved.lat;
        lon = resolved.lon;
        altitude = args.altitude ?? resolved.altitude;
        label = args.query;
      }
      if (lat === undefined || lon === undefined) {
        return "Fly-to needs a place name or coordinates.";
      }
      viewer.camera.flyTo({
        destination: Cartesian3.fromDegrees(lon, lat, altitude),
        orientation: {
          heading: CesiumMath.toRadians(args.heading ?? 0),
          pitch: CesiumMath.toRadians(args.pitch ?? -45),
          roll: 0,
        },
        duration: 2.2,
        easingFunction: EasingFunction.EXPONENTIAL_OUT,
      });
      return `Flying to ${label}.`;
    },

    async orbitEntity(args: OrbitArgs): Promise<string> {
      let center: Cartesian3 | null = null;
      let label = "target";
      if (args.entityId) {
        const fix = entityLatLon(args.entityId);
        if (fix) {
          center = fix.position;
          label = entities.metaOf(args.entityId) ? args.entityId : "the target";
        }
      }
      if (!center && args.targetCoords) {
        center = Cartesian3.fromDegrees(args.targetCoords.lon, args.targetCoords.lat, 0);
        label = "the marked coordinate";
      }
      if (!center) return "I couldn't find that entity to orbit.";
      const distanceM = (args.distanceKm ?? 40) * 1000;
      viewer.camera.flyToBoundingSphere(new BoundingSphere(center, distanceM), {
        duration: 2.0,
        easingFunction: EasingFunction.EXPONENTIAL_OUT,
        offset: new HeadingPitchRange(0, CesiumMath.toRadians(-30), distanceM * 3),
      });
      return `Orbiting ${label}.`;
    },

    async cockpitMode(entityId: string, enable: boolean): Promise<string> {
      if (!enable) {
        viewer.trackedEntity = undefined;
        deps.lockTarget(null, false);
        return "Cockpit lock released.";
      }
      const entity = entities.getEntity(entityId);
      if (!entity) return `I couldn't find entity ${entityId} to lock onto.`;
      deps.lockTarget(entityId, false);
      viewer.trackedEntity = entity;
      return `Cockpit locked to ${entityId}.`;
    },

    setShaderMode(mode: ShaderMode): string {
      deps.setShaderMode(SHADER_TO_SENSOR[mode]);
      return `Sensor mode ${mode.toUpperCase()}.`;
    },

    toggleDataLayer(layer: DataLayerId, state: boolean): string {
      if (isInfra(layer)) {
        void infra.setVisible(layer, state);
        return `${state ? "Enabled" : "Disabled"} the ${layer} layer.`;
      }
      const lod = LAYER_TO_LOD[layer];
      if (!lod) return `I don't have a "${layer}" layer.`;
      deps.toggleLodLayer(lod, state);
      const note =
        layer === "military_flights"
          ? " (the console does not separate military air, so this toggles all air tracks)"
          : "";
      return `${state ? "Enabled" : "Disabled"} the ${layer.replace("_", " ")} layer${note}.`;
    },

    annotateBoundingBox(args: BoundingBoxArgs): string {
      const color = Color.fromCssColorString(args.color ?? "#00f0ff");
      const positions = args.coordinates.map((c) => Cartesian3.fromDegrees(c.lon, c.lat, 0));
      viewer.entities.add({
        id: `annotation-${args.label}-${Date.now()}`,
        polygon: {
          hierarchy: positions,
          material: color.withAlpha(0.12),
          outline: true,
          outlineColor: color.withAlpha(0.9),
          height: 0,
        },
        position: positions[0],
        label: {
          text: args.label,
          font: "13px 'JetBrains Mono', monospace",
          fillColor: color,
        },
      });
      viewer.scene.requestRender();
      return `Marked "${args.label}".`;
    },

    async getNearbyContacts(
      centerLat: number,
      centerLon: number,
      radiusKm: number,
    ): Promise<NearbyContact[]> {
      const out: NearbyContact[] = [];
      for (const row of entities.roster()) {
        const fix = entityLatLon(row.id);
        if (!fix) continue;
        const { rangeKm, bearingDeg } = rangeBearing(centerLat, centerLon, fix.lat, fix.lon);
        if (rangeKm > radiusKm) continue;
        out.push({
          id: row.id,
          // The console calls the orbital domain "space"; the copilot's
          // vocabulary calls it "orbit".
          kind: row.domain === "space" ? "orbit" : row.domain,
          name: row.name,
          rangeKm,
          bearingDeg,
        });
      }
      return out.sort((a, b) => a.rangeKm - b.rangeKm);
    },

    async screenConjunctionThreats(
      thresholdPc: number,
      horizonHours: number,
    ): Promise<ConjunctionThreat[]> {
      void thresholdPc; // the backend screens on geometry; Pc is reported per pair
      const catalog = await fetchSatellites();
      const subset = catalog.slice(0, 6); // bounded so a voice turn stays responsive
      const threats: ConjunctionThreat[] = [];
      for (let i = 0; i < subset.length; i++) {
        for (let j = i + 1; j < subset.length; j++) {
          try {
            const result = await fetchConjunction(
              subset[i].norad_id,
              subset[j].norad_id,
              horizonHours,
            );
            if (result.found && result.geometry) {
              threats.push({
                primary: String(subset[i].norad_id),
                secondary: String(subset[j].norad_id),
                missDistanceKm: result.geometry.miss_distance_m / 1000,
                tcaIso: "",
                relativeSpeedKmS: result.geometry.relative_speed_m_s / 1000,
              });
            }
          } catch {
            // One bad pair never aborts the sweep.
          }
        }
      }
      return threats.sort((a, b) => a.missDistanceKm - b.missDistanceKm);
    },

    async computeAvoidanceManeuver(
      satelliteId: string,
      missDistanceKm: number,
    ): Promise<AvoidanceResult> {
      void missDistanceKm; // the backend planner targets Pc, not a raw miss
      const id = Number(satelliteId.replace(/^sat-/, ""));
      const catalog = await fetchSatellites();
      const other = catalog.find((s) => s.norad_id !== id) ?? catalog[0];
      const response = await planAvoidance(id, other.norad_id, 24);
      const s = response.solution;
      return {
        satelliteId,
        deltaVMS: s?.delta_v_magnitude_m_s ?? 0,
        pcBefore: s?.pc_before ?? 0,
        pcAfter: s?.pc_after ?? 0,
        achievesTarget: s?.achieves_target ?? false,
      };
    },

    snapshotContext(): ViewportContext {
      const camera = viewer.camera;
      const carto = camera.positionCartographic;
      const counts = entities.counts();
      const selectedId = deps.selectedEntityId();
      const selectedRow = selectedId
        ? entities.roster().find((r) => r.id === selectedId)
        : undefined;
      const fix = selectedId ? entityLatLon(selectedId) : null;

      const enabled = deps.enabledLodLayers();
      const layerIds: DataLayerId[] = [];
      for (const [id, lod] of Object.entries(LAYER_TO_LOD) as [DataLayerId, LodLayer][]) {
        if (enabled.has(lod) && id !== "military_flights") layerIds.push(id);
      }
      for (const id of INFRA_IDS) {
        if (infra.isVisible(id)) layerIds.push(id);
      }

      return {
        camera: {
          latitudeDeg: CesiumMath.toDegrees(carto.latitude),
          longitudeDeg: CesiumMath.toDegrees(carto.longitude),
          altitudeKm: carto.height / 1000,
          headingDeg: CesiumMath.toDegrees(camera.heading),
          pitchDeg: CesiumMath.toDegrees(camera.pitch),
        },
        selected: selectedRow
          ? {
              id: selectedRow.id,
              kind: selectedRow.domain,
              name: selectedRow.name,
              altitudeM: fix?.altM,
            }
          : null,
        enabledLayers: layerIds,
        shaderMode: SENSOR_TO_SHADER[deps.currentShaderMode()],
        counts: {
          air: counts.air,
          sea: counts.sea,
          orbit: counts.space,
          alertCells: counts.ew,
        },
      };
    },
  };
}
