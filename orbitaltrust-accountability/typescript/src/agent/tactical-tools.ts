// Tool-calling dispatch engine.
//
// TOOL_SCHEMAS is the declarative suite handed to the LLM (OpenAI Realtime
// function definitions and the Groq/OpenAI chat `tools` array share this
// JSON-Schema shape). dispatchTool() is a pure async router from a tool
// name + parsed arguments to a TacticalCapabilities call, returning a
// short spoken-confirmation string. Because it only touches the
// capabilities interface, the entire grammar is unit-testable in Node.

import type {
  DataLayerId,
  ShaderMode,
  TacticalCapabilities,
} from "./capabilities";

/** JSON-Schema tool definitions (provider-agnostic). */
export const TOOL_SCHEMAS = [
  {
    type: "function",
    name: "fly_to_location",
    description:
      "Smoothly fly the tactical camera to coordinates or a named geopolitical entity / asset. Provide either query OR lat+lon.",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", description: "Place or asset name, e.g. 'Strait of Hormuz'." },
        lat: { type: "number" },
        lon: { type: "number" },
        altitude: { type: "number", description: "Camera altitude in metres." },
        pitch: { type: "number", description: "Camera pitch in degrees (negative looks down)." },
        heading: { type: "number", description: "Camera heading in degrees." },
      },
    },
  },
  {
    type: "function",
    name: "orbit_entity",
    description: "Smoothly orbit the camera around a tracked entity or a coordinate.",
    parameters: {
      type: "object",
      properties: {
        entityId: { type: "string" },
        targetCoords: {
          type: "object",
          properties: { lat: { type: "number" }, lon: { type: "number" } },
        },
        speed: { type: "number", description: "Angular rate multiplier, 0.2–4." },
        distanceKm: { type: "number" },
      },
    },
  },
  {
    type: "function",
    name: "cockpit_mode",
    description:
      "Lock the camera to the velocity vector of a live aircraft, vessel, or satellite (chase view). Set enable=false to release.",
    parameters: {
      type: "object",
      properties: {
        entityId: { type: "string" },
        enable: { type: "boolean" },
      },
      required: ["entityId", "enable"],
    },
  },
  {
    type: "function",
    name: "set_shader_mode",
    description: "Swap the tactical sensor post-processing shader.",
    parameters: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["default", "flir", "nvg", "ironbow", "crt"] },
      },
      required: ["mode"],
    },
  },
  {
    type: "function",
    name: "toggle_data_layer",
    description: "Show or hide a multi-domain data layer.",
    parameters: {
      type: "object",
      properties: {
        layer: {
          type: "string",
          enum: [
            "flights",
            "military_flights",
            "vessels",
            "satellites",
            "cctv",
            "fires",
            "cables",
            "dams",
            "datacenters",
          ],
        },
        state: { type: "boolean" },
      },
      required: ["layer", "state"],
    },
  },
  {
    type: "function",
    name: "annotate_bounding_box",
    description: "Draw a labelled polygon/bounding footprint over an area of interest.",
    parameters: {
      type: "object",
      properties: {
        coordinates: {
          type: "array",
          items: {
            type: "object",
            properties: { lat: { type: "number" }, lon: { type: "number" } },
            required: ["lat", "lon"],
          },
        },
        label: { type: "string" },
        color: { type: "string", description: "CSS hex colour." },
      },
      required: ["coordinates", "label"],
    },
  },
  {
    type: "function",
    name: "get_nearby_contacts",
    description:
      "List all air, sea, and space contacts within a radius (km) of a centre coordinate.",
    parameters: {
      type: "object",
      properties: {
        centerLat: { type: "number" },
        centerLon: { type: "number" },
        radiusKm: { type: "number" },
      },
      required: ["centerLat", "centerLon", "radiusKm"],
    },
  },
  {
    type: "function",
    name: "screen_conjunction_threats",
    description:
      "Interrogate the ot-api backend for orbital close encounters above a collision-probability threshold within a horizon (hours).",
    parameters: {
      type: "object",
      properties: {
        thresholdPc: { type: "number" },
        horizonHours: { type: "number" },
      },
    },
  },
  {
    type: "function",
    name: "compute_avoidance_maneuver",
    description:
      "Run the backend dual-convergence collision-avoidance burn solver for a satellite to a target miss distance (km).",
    parameters: {
      type: "object",
      properties: {
        satelliteId: { type: "string" },
        missDistanceKm: { type: "number" },
      },
      required: ["satelliteId"],
    },
  },
] as const;

export type ToolName = (typeof TOOL_SCHEMAS)[number]["name"];

/** A single tool call as emitted by the model. */
export interface ToolCall {
  name: string;
  /** Parsed argument object (already JSON.parsed from the model). */
  args: Record<string, unknown>;
}

/** Outcome of executing a tool call. */
export interface ToolResult {
  ok: boolean;
  /** Short human/spoken confirmation. */
  summary: string;
  /** Structured payload returned to the model for follow-up reasoning. */
  data?: unknown;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/**
 * Executes one tool call against the live capabilities. Never throws:
 * argument problems and backend failures come back as `ok: false` with an
 * operator-legible reason (the model narrates it instead of stalling).
 */
export async function dispatchTool(
  call: ToolCall,
  caps: TacticalCapabilities,
): Promise<ToolResult> {
  try {
    switch (call.name) {
      case "fly_to_location": {
        const summary = await caps.flyToLocation({
          query: typeof call.args.query === "string" ? call.args.query : undefined,
          lat: num(call.args.lat),
          lon: num(call.args.lon),
          altitude: num(call.args.altitude),
          pitch: num(call.args.pitch),
          heading: num(call.args.heading),
        });
        return { ok: true, summary };
      }
      case "orbit_entity": {
        const coords = call.args.targetCoords as { lat?: unknown; lon?: unknown } | undefined;
        const summary = await caps.orbitEntity({
          entityId: typeof call.args.entityId === "string" ? call.args.entityId : undefined,
          targetCoords:
            coords && num(coords.lat) !== undefined && num(coords.lon) !== undefined
              ? { lat: num(coords.lat)!, lon: num(coords.lon)! }
              : undefined,
          speed: num(call.args.speed),
          distanceKm: num(call.args.distanceKm),
        });
        return { ok: true, summary };
      }
      case "cockpit_mode": {
        const entityId = String(call.args.entityId ?? "");
        if (!entityId) return { ok: false, summary: "Cockpit mode needs an entity id." };
        const summary = await caps.cockpitMode(entityId, call.args.enable !== false);
        return { ok: true, summary };
      }
      case "set_shader_mode": {
        const mode = String(call.args.mode ?? "") as ShaderMode;
        if (!["default", "flir", "nvg", "ironbow", "crt"].includes(mode)) {
          return { ok: false, summary: `Unknown shader mode '${mode}'.` };
        }
        return { ok: true, summary: caps.setShaderMode(mode) };
      }
      case "toggle_data_layer": {
        const layer = String(call.args.layer ?? "") as DataLayerId;
        const summary = caps.toggleDataLayer(layer, call.args.state !== false);
        return { ok: true, summary };
      }
      case "annotate_bounding_box": {
        const raw = Array.isArray(call.args.coordinates) ? call.args.coordinates : [];
        const coordinates = raw
          .map((c) => {
            const o = c as { lat?: unknown; lon?: unknown };
            const lat = num(o.lat);
            const lon = num(o.lon);
            return lat !== undefined && lon !== undefined ? { lat, lon } : null;
          })
          .filter((c): c is { lat: number; lon: number } => c !== null);
        if (coordinates.length < 3) {
          return { ok: false, summary: "A bounding box needs at least three coordinates." };
        }
        const summary = caps.annotateBoundingBox({
          coordinates,
          label: String(call.args.label ?? "AOI"),
          color: typeof call.args.color === "string" ? call.args.color : undefined,
        });
        return { ok: true, summary };
      }
      case "get_nearby_contacts": {
        const lat = num(call.args.centerLat);
        const lon = num(call.args.centerLon);
        const radius = num(call.args.radiusKm) ?? 250;
        if (lat === undefined || lon === undefined) {
          return { ok: false, summary: "Nearby-contacts needs a centre coordinate." };
        }
        const contacts = await caps.getNearbyContacts(lat, lon, radius);
        const by = { air: 0, sea: 0, orbit: 0 };
        for (const c of contacts) by[c.kind] += 1;
        return {
          ok: true,
          summary: `${contacts.length} contacts within ${radius} km: ${by.air} air, ${by.sea} sea, ${by.orbit} space.`,
          data: contacts,
        };
      }
      case "screen_conjunction_threats": {
        const threats = await caps.screenConjunctionThreats(
          num(call.args.thresholdPc) ?? 1e-4,
          num(call.args.horizonHours) ?? 24,
        );
        return {
          ok: true,
          summary: threats.length
            ? `${threats.length} conjunction threat(s); closest miss ${Math.min(
                ...threats.map((t) => t.missDistanceKm),
              ).toFixed(2)} km.`
            : "No conjunction threats above threshold.",
          data: threats,
        };
      }
      case "compute_avoidance_maneuver": {
        const satelliteId = String(call.args.satelliteId ?? "");
        if (!satelliteId) return { ok: false, summary: "Avoidance needs a satellite id." };
        const result = await caps.computeAvoidanceManeuver(
          satelliteId,
          num(call.args.missDistanceKm) ?? 5,
        );
        return {
          ok: true,
          summary: result.achievesTarget
            ? `Burn solved: ${result.deltaVMS.toFixed(2)} m/s drops Pc from ${result.pcBefore.toExponential(1)} to ${result.pcAfter.toExponential(1)}.`
            : `No burn within budget reaches the target miss distance.`,
          data: result,
        };
      }
      default:
        return { ok: false, summary: `Unknown tool '${call.name}'.` };
    }
  } catch (error) {
    return { ok: false, summary: `Tool '${call.name}' failed: ${String(error)}` };
  }
}

/** Chat-completions tool shape (Groq / OpenAI): wraps each schema in {function}. */
export function chatToolDefinitions() {
  return TOOL_SCHEMAS.map((schema) => ({
    type: "function" as const,
    function: {
      name: schema.name,
      description: schema.description,
      parameters: schema.parameters,
    },
  }));
}
