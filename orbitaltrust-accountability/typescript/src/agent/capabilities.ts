// The capability surface the voice copilot drives.
//
// This interface is the seam between the tool dispatcher (pure, testable)
// and the live Cesium scene / ot-api backend (side-effectful). The
// dispatcher in tactical-tools.ts only ever calls these methods, so the
// whole command grammar can be unit-tested in Node against a mock
// capabilities object — no GPU, no viewer, no network.

export type ShaderMode = "default" | "flir" | "nvg" | "ironbow" | "crt";

export type DataLayerId =
  | "flights"
  | "military_flights"
  | "vessels"
  | "satellites"
  | "cctv"
  | "fires"
  | "cables"
  | "dams"
  | "datacenters";

export interface FlyToArgs {
  query?: string;
  lat?: number;
  lon?: number;
  altitude?: number;
  pitch?: number;
  heading?: number;
}

export interface OrbitArgs {
  entityId?: string;
  targetCoords?: { lat: number; lon: number };
  speed?: number;
  distanceKm?: number;
}

export interface BoundingBoxArgs {
  coordinates: { lat: number; lon: number }[];
  label: string;
  color?: string;
}

export interface NearbyContact {
  id: string;
  kind: "air" | "sea" | "orbit";
  name: string;
  rangeKm: number;
  bearingDeg: number;
}

export interface ConjunctionThreat {
  primary: string;
  secondary: string;
  missDistanceKm: number;
  tcaIso: string;
  relativeSpeedKmS: number;
}

export interface AvoidanceResult {
  satelliteId: string;
  deltaVMS: number;
  pcBefore: number;
  pcAfter: number;
  achievesTarget: boolean;
}

/**
 * Everything the copilot can do. Implemented by createCapabilities()
 * against GlobeHandles + the ot-api client; mocked in tests.
 */
export interface TacticalCapabilities {
  // ── Camera & flight ──────────────────────────────────────────────
  flyToLocation(args: FlyToArgs): Promise<string>;
  orbitEntity(args: OrbitArgs): Promise<string>;
  cockpitMode(entityId: string, enable: boolean): Promise<string>;

  // ── Layers & sensors ─────────────────────────────────────────────
  setShaderMode(mode: ShaderMode): string;
  toggleDataLayer(layer: DataLayerId, state: boolean): string;
  annotateBoundingBox(args: BoundingBoxArgs): string;

  // ── Backend SDA/decision tools ───────────────────────────────────
  getNearbyContacts(centerLat: number, centerLon: number, radiusKm: number): Promise<NearbyContact[]>;
  screenConjunctionThreats(thresholdPc: number, horizonHours: number): Promise<ConjunctionThreat[]>;
  computeAvoidanceManeuver(satelliteId: string, missDistanceKm: number): Promise<AvoidanceResult>;

  // ── Live context for prompt injection ────────────────────────────
  snapshotContext(): ViewportContext;
}

/** Live viewport state injected into the model before every turn. */
export interface ViewportContext {
  camera: {
    latitudeDeg: number;
    longitudeDeg: number;
    altitudeKm: number;
    headingDeg: number;
    pitchDeg: number;
  };
  selected: {
    id: string;
    kind: string;
    name: string;
    speedMS?: number;
    altitudeM?: number;
  } | null;
  enabledLayers: DataLayerId[];
  shaderMode: ShaderMode;
  counts: { air: number; sea: number; orbit: number; alertCells: number };
}

/** Geopolitical/asset gazetteer for `fly_to_location({ query })`. */
export const GAZETTEER: Record<
  string,
  { lat: number; lon: number; altitude: number }
> = {
  "strait of hormuz": { lat: 26.57, lon: 56.25, altitude: 320_000 },
  "bay of bengal": { lat: 12.5, lon: 88.0, altitude: 1_500_000 },
  "malacca strait": { lat: 2.8, lon: 100.5, altitude: 450_000 },
  "south china sea": { lat: 13.0, lon: 114.0, altitude: 2_000_000 },
  taiwan: { lat: 23.7, lon: 121.0, altitude: 600_000 },
  "persian gulf": { lat: 26.9, lon: 51.5, altitude: 900_000 },
  gibraltar: { lat: 36.0, lon: -5.35, altitude: 120_000 },
  "suez canal": { lat: 30.5, lon: 32.35, altitude: 200_000 },
  "panama canal": { lat: 9.1, lon: -79.7, altitude: 200_000 },
  bengaluru: { lat: 13.035, lon: 77.512, altitude: 60_000 },
  "sriharikota": { lat: 13.72, lon: 80.23, altitude: 80_000 },
};

/** Resolves a free-text place query to coordinates, or null if unknown. */
export function resolveQuery(
  query: string,
): { lat: number; lon: number; altitude: number } | null {
  const key = query.trim().toLowerCase();
  if (GAZETTEER[key]) return GAZETTEER[key];
  // Loose contains-match so "fly to the Strait of Hormuz now" still hits.
  for (const [name, coords] of Object.entries(GAZETTEER)) {
    if (key.includes(name)) return coords;
  }
  return null;
}
