// Pure unit tests for the voice-copilot tool dispatch engine. No Cesium,
// no browser, no network — the dispatcher only touches a mock
// TacticalCapabilities, which is the whole point of the seam.

import { describe, expect, it, vi } from "vitest";
import type { TacticalCapabilities, ViewportContext } from "./capabilities";
import { resolveQuery } from "./capabilities";
import { chatToolDefinitions, dispatchTool, TOOL_SCHEMAS } from "./tactical-tools";
import { renderContextBlock } from "./context";

function mockCaps(overrides: Partial<TacticalCapabilities> = {}): TacticalCapabilities {
  const base: TacticalCapabilities = {
    flyToLocation: vi.fn(async () => "Flying."),
    orbitEntity: vi.fn(async () => "Orbiting."),
    cockpitMode: vi.fn(async () => "Locked."),
    setShaderMode: vi.fn(() => "Thermal."),
    toggleDataLayer: vi.fn(() => "Toggled."),
    annotateBoundingBox: vi.fn(() => "Marked."),
    getNearbyContacts: vi.fn(async () => [
      { id: "A1", kind: "air" as const, name: "AF1", rangeKm: 12, bearingDeg: 90 },
      { id: "S1", kind: "sea" as const, name: "Tanker", rangeKm: 40, bearingDeg: 180 },
    ]),
    screenConjunctionThreats: vi.fn(async () => [
      { primary: "1", secondary: "2", missDistanceKm: 3.2, tcaIso: "", relativeSpeedKmS: 10 },
    ]),
    computeAvoidanceManeuver: vi.fn(async () => ({
      satelliteId: "1",
      deltaVMS: 0.42,
      pcBefore: 1e-3,
      pcAfter: 1e-8,
      achievesTarget: true,
    })),
    snapshotContext: vi.fn(() => ({}) as ViewportContext),
  };
  return { ...base, ...overrides };
}

describe("tool schemas", () => {
  it("exposes exactly the nine tactical verbs", () => {
    const names = TOOL_SCHEMAS.map((t) => t.name);
    expect(names).toEqual([
      "fly_to_location",
      "orbit_entity",
      "cockpit_mode",
      "set_shader_mode",
      "toggle_data_layer",
      "annotate_bounding_box",
      "get_nearby_contacts",
      "screen_conjunction_threats",
      "compute_avoidance_maneuver",
    ]);
  });

  it("wraps schemas for chat-completions tool-calling", () => {
    const defs = chatToolDefinitions();
    expect(defs).toHaveLength(TOOL_SCHEMAS.length);
    expect(defs[0]).toMatchObject({ type: "function", function: { name: "fly_to_location" } });
  });
});

describe("dispatchTool", () => {
  it("routes fly_to_location with a query", async () => {
    const caps = mockCaps();
    const result = await dispatchTool(
      { name: "fly_to_location", args: { query: "Strait of Hormuz" } },
      caps,
    );
    expect(result.ok).toBe(true);
    expect(caps.flyToLocation).toHaveBeenCalledWith(
      expect.objectContaining({ query: "Strait of Hormuz" }),
    );
  });

  it("rejects an unknown shader mode without calling the scene", async () => {
    const caps = mockCaps();
    const result = await dispatchTool(
      { name: "set_shader_mode", args: { mode: "xray" } },
      caps,
    );
    expect(result.ok).toBe(false);
    expect(caps.setShaderMode).not.toHaveBeenCalled();
  });

  it("accepts every real shader mode", async () => {
    for (const mode of ["default", "flir", "nvg", "ironbow", "crt"]) {
      const result = await dispatchTool({ name: "set_shader_mode", args: { mode } }, mockCaps());
      expect(result.ok).toBe(true);
    }
  });

  it("summarises nearby contacts by domain", async () => {
    const result = await dispatchTool(
      { name: "get_nearby_contacts", args: { centerLat: 25, centerLon: 56, radiusKm: 250 } },
      mockCaps(),
    );
    expect(result.ok).toBe(true);
    expect(result.summary).toContain("1 air");
    expect(result.summary).toContain("1 sea");
    expect(Array.isArray(result.data)).toBe(true);
  });

  it("requires a centre for nearby contacts", async () => {
    const result = await dispatchTool(
      { name: "get_nearby_contacts", args: { radiusKm: 250 } },
      mockCaps(),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a bounding box with fewer than three vertices", async () => {
    const result = await dispatchTool(
      {
        name: "annotate_bounding_box",
        args: { coordinates: [{ lat: 1, lon: 1 }], label: "X" },
      },
      mockCaps(),
    );
    expect(result.ok).toBe(false);
  });

  it("reports a solved avoidance burn", async () => {
    const result = await dispatchTool(
      { name: "compute_avoidance_maneuver", args: { satelliteId: "25544" } },
      mockCaps(),
    );
    expect(result.ok).toBe(true);
    expect(result.summary).toMatch(/Burn solved/);
  });

  it("never throws on a capability failure — returns ok:false", async () => {
    const caps = mockCaps({
      flyToLocation: vi.fn(async () => {
        throw new Error("scene destroyed");
      }),
    });
    const result = await dispatchTool({ name: "fly_to_location", args: { query: "x" } }, caps);
    expect(result.ok).toBe(false);
    expect(result.summary).toContain("failed");
  });

  it("rejects an unknown tool name", async () => {
    const result = await dispatchTool({ name: "self_destruct", args: {} }, mockCaps());
    expect(result.ok).toBe(false);
  });
});

describe("gazetteer resolution", () => {
  it("resolves an exact place name", () => {
    expect(resolveQuery("Strait of Hormuz")).toMatchObject({ lat: 26.57, lon: 56.25 });
  });
  it("resolves a place embedded in a sentence", () => {
    expect(resolveQuery("take me to the Malacca Strait now")).not.toBeNull();
  });
  it("returns null for an unknown place", () => {
    expect(resolveQuery("Atlantis")).toBeNull();
  });
});

describe("context injection", () => {
  it("renders a compact live-state block", () => {
    const block = renderContextBlock({
      camera: { latitudeDeg: 25.1, longitudeDeg: 56.2, altitudeKm: 320, headingDeg: 10, pitchDeg: -45 },
      selected: { id: "A1", kind: "air", name: "AF1", speedMS: 250, altitudeM: 10000 },
      enabledLayers: ["flights", "vessels"],
      shaderMode: "flir",
      counts: { air: 42, sea: 8, orbit: 6, alertCells: 2 },
    });
    expect(block).toContain("[LIVE CONSOLE STATE]");
    expect(block).toContain("selected: air AF1");
    expect(block).toContain("shader: flir");
    expect(block).toContain("42 air");
  });
});
