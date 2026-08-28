// Live viewport-context injection.
//
// buildSystemPrompt() renders the copilot's standing instructions;
// renderContextBlock() snapshots the current camera, selection, layers,
// and counts into a compact text block prepended before every user turn.
// This is what lets "what are those helicopters doing?" or "switch that
// to thermal" resolve against the asset and camera actually in focus.

import type { TacticalCapabilities, ViewportContext } from "./capabilities";

export const SYSTEM_PROMPT = [
  "You are ORBITALTRUST COPILOT, a hands-free tactical controller for a CesiumJS",
  "common-operational-picture console. You physically operate the console by calling",
  "the provided tools — you do not merely describe actions.",
  "",
  "Rules:",
  "- Call a tool for any control, navigation, sensor, layer, or backend-query request.",
  "  For ordinary questions, answer briefly in speech without a tool.",
  "- Never invent tool names or arguments. Resolve 'this'/'that'/'those' against the",
  "  SELECTED asset and CAMERA context in the injected state block.",
  "- 'Switch to thermal' → set_shader_mode{mode:'flir'}. 'Night vision' → 'nvg'.",
  "- 'What's near me' / 'nearby contacts' → get_nearby_contacts around the camera",
  "  centre (or the selected asset) with a 250 km default radius.",
  "- 'Any collision risks' / 'screen for conjunctions' → screen_conjunction_threats.",
  "- 'Plan a dodge/avoidance burn for <sat>' → compute_avoidance_maneuver.",
  "- Confirm each action in one short spoken sentence describing the RESULT",
  "  ('Flying to the Strait of Hormuz', 'Thermal mode', 'Enabled the cables layer').",
  "- Keep spoken replies under 2 sentences unless asked to elaborate.",
].join("\n");

export function buildSystemPrompt(): string {
  return SYSTEM_PROMPT;
}

/** Compact, model-friendly rendering of the current viewport state. */
export function renderContextBlock(ctx: ViewportContext): string {
  const c = ctx.camera;
  const lines = [
    "[LIVE CONSOLE STATE]",
    `camera: ${c.latitudeDeg.toFixed(3)},${c.longitudeDeg.toFixed(3)} ` +
      `alt=${c.altitudeKm.toFixed(0)}km hdg=${c.headingDeg.toFixed(0)} pitch=${c.pitchDeg.toFixed(0)}`,
    ctx.selected
      ? `selected: ${ctx.selected.kind} ${ctx.selected.name} (id ${ctx.selected.id})` +
        (ctx.selected.speedMS !== undefined
          ? ` spd=${(ctx.selected.speedMS / 0.514444).toFixed(0)}kt`
          : "") +
        (ctx.selected.altitudeM !== undefined
          ? ` alt=${Math.round(ctx.selected.altitudeM)}m`
          : "")
      : "selected: none",
    `layers on: ${ctx.enabledLayers.join(", ") || "none"}`,
    `shader: ${ctx.shaderMode}`,
    `tracks: ${ctx.counts.air} air / ${ctx.counts.sea} sea / ${ctx.counts.orbit} space, ` +
      `${ctx.counts.alertCells} EW cells`,
  ];
  return lines.join("\n");
}

/** Convenience: snapshot + render in one call. */
export function currentContextBlock(caps: TacticalCapabilities): string {
  return renderContextBlock(caps.snapshotContext());
}
