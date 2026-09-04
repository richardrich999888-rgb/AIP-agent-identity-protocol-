/**
 * The copilot's conversation protocol, as executable claims.
 *
 * These cover the two failures an operator reports as "it does not
 * understand me" and "it does not do my work":
 *
 * - a follow-up turn ("now do that here") must carry the turns before it,
 *   or every utterance is a cold start and no command can refer to the last;
 * - a tool's actual result must go back to the model, or it can neither
 *   answer a question the tool answered nor notice that a call failed;
 * - two utterances arriving together must not interleave.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TacticalCapabilities, ViewportContext } from "../src/agent/capabilities";
import { VoiceCopilot } from "../src/agent/voice-copilot";
import type { GovernanceDeps } from "../src/agent/governed-dispatch";
import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { CONSOLE_TOOL_MANIFEST } from "../src/telemetry/governance";

const VIEWPORT: ViewportContext = {
  camera: {
    latitudeDeg: 20.5,
    longitudeDeg: 78.9,
    altitudeKm: 12000,
    headingDeg: 0,
    pitchDeg: -90,
  },
  selected: { id: "SPACE-25544", kind: "space", name: "ISS" },
  enabledLayers: [],
  shaderMode: "visible",
  counts: { air: 0, sea: 0, orbit: 1, alertCells: 0 },
};

function mockCaps(): TacticalCapabilities {
  return {
    flyToLocation: vi.fn(async () => "Flying."),
    orbitEntity: vi.fn(async () => "Orbiting."),
    cockpitMode: vi.fn(async () => "Locked."),
    setShaderMode: vi.fn(() => "Thermal."),
    toggleDataLayer: vi.fn(() => "Toggled."),
    annotateBoundingBox: vi.fn(() => "Marked."),
    getNearbyContacts: vi.fn(async () => []),
    screenConjunctionThreats: vi.fn(async () => []),
    computeAvoidanceManeuver: vi.fn(async () => ({
      satelliteId: "1",
      deltaVMS: 0.42,
      pcBefore: 1e-3,
      pcAfter: 1e-8,
      achievesTarget: true,
    })),
    snapshotContext: vi.fn(() => VIEWPORT),
  };
}

interface ChatBody {
  messages: Array<{
    role: string;
    content: string | null;
    tool_calls?: Array<{ id?: string; function?: { name?: string } }>;
    tool_call_id?: string;
  }>;
}

/** Captures every chat request, replying with a scripted assistant message. */
function scriptBroker(replies: Array<Record<string, unknown>>) {
  const sent: ChatBody[] = [];
  let turn = 0;
  const fetchMock = vi.fn(async (_url: string, init?: { body?: string }) => {
    sent.push(JSON.parse(init?.body ?? "{}") as ChatBody);
    const message = replies[Math.min(turn, replies.length - 1)];
    turn += 1;
    return {
      ok: true,
      json: async () => ({ choices: [{ message }] }),
    };
  });
  vi.stubGlobal("fetch", fetchMock);
  return sent;
}

let deps: GovernanceDeps;

beforeEach(() => {
  vi.unstubAllGlobals();
  deps = {
    registry: new IdentityRegistry("copilot-turn-secret", { persist: false }),
    service: new AccountabilityService(new MemoryLedgerStorage(), CONSOLE_TOOL_MANIFEST),
  };
});

describe("copilot conversation", () => {
  it("carries the previous turns, so a follow-up can refer to the last one", async () => {
    const sent = scriptBroker([
      { content: "The ISS is overhead." },
      { content: "Zooming in." },
    ]);
    const copilot = new VoiceCopilot(mockCaps(), {}, deps);

    await copilot.sendText("what is that satellite");
    await copilot.sendText("now zoom in on it");

    expect(sent).toHaveLength(2);
    // The second request must contain the first exchange, or "it" resolves
    // against nothing and the copilot answers a question nobody asked.
    const second = sent[1].messages.map((m) => `${m.role}:${m.content}`);
    expect(second).toContain("user:what is that satellite");
    expect(second).toContain("assistant:The ISS is overhead.");
    expect(second).toContain("user:now zoom in on it");
  });

  it("sends the tool's real result back to the model rather than a canned summary", async () => {
    const sent = scriptBroker([
      {
        content: null,
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: { name: "set_shader_mode", arguments: '{"mode":"flir"}' },
          },
        ],
      },
      { content: "Thermal imaging is on." },
    ]);
    const spoken: string[] = [];
    const copilot = new VoiceCopilot(
      mockCaps(),
      { onTranscript: (role, text) => role === "assistant" && spoken.push(text) },
      deps,
    );

    await copilot.sendText("switch to thermal");

    // Two round trips: the tool-calling one, then one that can see results.
    expect(sent).toHaveLength(2);
    const follow = sent[1].messages;
    const toolMessage = follow.find((m) => m.role === "tool");
    expect(toolMessage, "the tool result never reached the model").toBeDefined();
    expect(toolMessage?.tool_call_id).toBe("call-1");
    // The assistant turn carrying the tool_calls must precede it, or the API
    // rejects the orphaned tool message.
    const assistantIndex = follow.findIndex((m) => m.tool_calls !== undefined);
    expect(assistantIndex).toBeGreaterThanOrEqual(0);
    expect(assistantIndex).toBeLessThan(follow.indexOf(toolMessage!));

    // And the operator hears the model's sentence, not the tool's own label.
    expect(spoken).toContain("Thermal imaging is on.");
  });

  it("still reports the action when the follow-up call fails", async () => {
    // The tool already ran and is already sealed; reporting a failure for
    // work that succeeded would be worse than falling back to its summary.
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        call += 1;
        if (call === 1) {
          return {
            ok: true,
            json: async () => ({
              choices: [
                {
                  message: {
                    content: null,
                    tool_calls: [
                      {
                        id: "call-1",
                        function: { name: "set_shader_mode", arguments: '{"mode":"flir"}' },
                      },
                    ],
                  },
                },
              ],
            }),
          };
        }
        return { ok: false, status: 503, json: async () => ({}) };
      }),
    );

    const spoken: string[] = [];
    const statuses: string[] = [];
    const caps = mockCaps();
    const copilot = new VoiceCopilot(
      caps,
      {
        onTranscript: (role, text) => role === "assistant" && spoken.push(text),
        onStatus: (s) => statuses.push(s),
      },
      deps,
    );

    await copilot.sendText("switch to thermal");

    expect(caps.setShaderMode).toHaveBeenCalledOnce();
    expect(spoken.join(" ")).toContain("Thermal");
    expect(statuses).not.toContain("error");
  });

  it("serialises overlapping utterances instead of interleaving them", async () => {
    const order: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: { body?: string }) => {
        const body = JSON.parse(init?.body ?? "{}") as ChatBody;
        const last = body.messages[body.messages.length - 1];
        order.push(`start:${last.content}`);
        await new Promise((r) => setTimeout(r, 10));
        order.push(`end:${last.content}`);
        return { ok: true, json: async () => ({ choices: [{ message: { content: "ok" } }] }) };
      }),
    );

    const copilot = new VoiceCopilot(mockCaps(), {}, deps);
    await Promise.all([copilot.sendText("first"), copilot.sendText("second")]);

    // The first must fully complete before the second begins.
    expect(order).toEqual(["start:first", "end:first", "start:second", "end:second"]);
  });

  it("keeps the history a window the API will accept", async () => {
    // A trimmed window must never open on a tool message, or on an assistant
    // turn whose tool results were cut away — the API rejects both.
    const sent = scriptBroker([
      {
        content: null,
        tool_calls: [
          {
            id: "c1",
            function: { name: "set_shader_mode", arguments: '{"mode":"flir"}' },
          },
        ],
      },
      { content: "done" },
    ]);
    const copilot = new VoiceCopilot(mockCaps(), {}, deps);

    for (let i = 0; i < 6; i += 1) await copilot.sendText(`command ${i}`);

    for (const body of sent) {
      const afterSystem = body.messages.slice(1);
      if (afterSystem.length === 0) continue;
      expect(afterSystem[0].role).not.toBe("tool");
      expect(afterSystem[0].tool_calls).toBeUndefined();
    }
  });
});
