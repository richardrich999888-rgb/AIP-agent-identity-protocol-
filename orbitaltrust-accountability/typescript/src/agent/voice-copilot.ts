// Dual-engine voice copilot controller.
//
// Two interchangeable backends behind one VoiceCopilot facade:
//
//   * "realtime" — OpenAI Realtime API over WebRTC. The dev broker
//     (/copilot/realtime/token) mints an ephemeral client_secret; the
//     browser negotiates a peer connection directly with OpenAI, streams
//     mic audio, receives spoken audio, and dispatches function calls.
//
//   * "fast" — Groq chat-completions with tool-calling. Speech-to-text is
//     the browser's own SpeechRecognition (zero cost); the transcript +
//     injected context + tools go to /copilot/groq/chat; tool calls are
//     dispatched locally and spoken back with speechSynthesis.
//
// Both paths funnel every model tool call through the same
// dispatchTool() → TacticalCapabilities, so the executed behaviour is
// identical regardless of engine. The controller keeps NO React state;
// the widget subscribes to status/transcript/action events.

import type { TacticalCapabilities } from "./capabilities";
import { buildSystemPrompt, renderContextBlock } from "./context";
import {
  TOOL_SCHEMAS,
  chatToolDefinitions,
  type ToolResult,
} from "./tactical-tools";
import {
  ensureJarvisGoverned,
  governedDispatchTool,
  type GovernanceDeps,
} from "./governed-dispatch";

/** Where the browser's speech recogniser is told to expect speech from.
 *
 * This matters far more than it looks. Web Speech accuracy is strongly
 * accent-dependent, and a recogniser set to `en-US` transcribing a speaker
 * of another English variant produces exactly the failure an operator
 * describes as "it cannot understand me" — words come back wrong, so the
 * model is asked to act on a sentence nobody said. The default follows the
 * browser's own locale rather than a hardcoded `en-US`, because that is the
 * one place the operator has already stated which English they speak.
 */
export function defaultSpeechLanguage(): string {
  if (typeof navigator === "undefined") return "en-US";
  return navigator.language || "en-US";
}

/** How many messages of conversation to carry between turns.
 *
 * Bounded because every turn resends the whole history, so an unbounded one
 * grows the request until it is slow and then refused. Twelve keeps several
 * exchanges of "do that / now the other thing" — which is what follow-up
 * commands need — without the transcript becoming the dominant cost.
 */
const MAX_HISTORY_MESSAGES = 12;

/** One message in the chat-completions exchange. */
interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  tool_calls?: unknown[];
  tool_call_id?: string;
}

export type CopilotEngine = "realtime" | "fast";
export type CopilotStatus =
  | "idle"
  | "connecting"
  | "listening"
  | "thinking"
  | "executing"
  | "error";

export interface CopilotEvents {
  onStatus?: (status: CopilotStatus, detail?: string) => void;
  onTranscript?: (role: "user" | "assistant", text: string) => void;
  onAction?: (toolName: string, result: ToolResult) => void;
  /** Mic input level 0..1 for the waveform, ~30 Hz. */
  onLevel?: (level: number) => void;
}

interface BrokerStatus {
  openaiRealtime: boolean;
  groq: boolean;
  firms: boolean;
}

/** Which engines the broker can actually serve right now. */
export async function probeBroker(): Promise<BrokerStatus> {
  try {
    const response = await fetch("/copilot/status");
    if (!response.ok) return { openaiRealtime: false, groq: false, firms: false };
    return (await response.json()) as BrokerStatus;
  } catch {
    return { openaiRealtime: false, groq: false, firms: false };
  }
}

export class VoiceCopilot {
  private engine: CopilotEngine = "fast";
  private active = false;
  /** Last spoken user utterance — the audit ledger's rawPrompt, so the
   * evidence records what the operator said, not just what the model did. */
  private lastUserTranscript = "";

  // Realtime (WebRTC) handles.
  private pc: RTCPeerConnection | null = null;
  private dc: RTCDataChannel | null = null;
  private micStream: MediaStream | null = null;
  private audioEl: HTMLAudioElement | null = null;

  // Fast-mode handles.
  private recognition: unknown = null;
  private analyser: AnalyserNode | null = null;
  private audioCtx: AudioContext | null = null;
  private levelRaf: number | null = null;
  /** Locale handed to the browser recogniser. */
  private language = defaultSpeechLanguage();
  /** True once a fatal recogniser error has been seen, so `onend` stops
   * restarting a recogniser that can never succeed. */
  private speechFatal = false;
  /** Rolling conversation, so a follow-up like "now zoom in on that" has the
   * turns before it to resolve against. */
  private history: ChatMessage[] = [];
  /** Serialises turns: two utterances arriving together must not interleave
   * their tool calls, their status transitions, or their history writes. */
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private caps: TacticalCapabilities,
    private events: CopilotEvents = {},
    /** Injectable governance, matching the seam `governedDispatchTool`
     * already exposes; production passes nothing and gets the console
     * singletons. */
    private governance?: GovernanceDeps,
  ) {}

  currentEngine(): CopilotEngine {
    return this.engine;
  }

  isActive(): boolean {
    return this.active;
  }

  private setStatus(status: CopilotStatus, detail?: string): void {
    this.events.onStatus?.(status, detail);
  }

  /** Starts a session, preferring OpenAI Realtime when the broker has a key. */
  async start(preferred?: CopilotEngine): Promise<void> {
    if (this.active) return;
    // A new session is a new conversation; carrying the last one's turns
    // across would have the copilot resolving "that one" against an asset
    // from before the operator walked away.
    this.history = [];
    this.setStatus("connecting");
    const broker = await probeBroker();
    const engine: CopilotEngine =
      preferred ??
      (broker.openaiRealtime ? "realtime" : "fast");
    this.engine = engine;
    this.active = true;
    try {
      if (engine === "realtime" && broker.openaiRealtime) {
        await this.startRealtime();
      } else {
        await this.startFast();
      }
      // Onboard into the governance registry AND the NEXORA lifecycle the
      // moment the mic arms, so the badge, the anchor chain, and the
      // delegation exist before the first command rather than after it.
      await ensureJarvisGoverned(
        engine === "realtime" ? "openai-realtime" : "groq-fast",
      );
    } catch (error) {
      this.active = false;
      this.setStatus("error", String(error));
      throw error;
    }
  }

  async stop(): Promise<void> {
    this.active = false;
    this.teardownRealtime();
    this.teardownFast();
    this.setStatus("idle");
  }

  async toggle(): Promise<void> {
    if (this.active) await this.stop();
    else await this.start();
  }

  // ── OpenAI Realtime (WebRTC) ────────────────────────────────────────

  private async startRealtime(): Promise<void> {
    const tokenResponse = await fetch("/copilot/realtime/token", { method: "POST" });
    if (!tokenResponse.ok) throw new Error(`token broker ${tokenResponse.status}`);
    const session = await tokenResponse.json();
    const clientSecret: string | undefined =
      session?.client_secret?.value ?? session?.client_secret ?? session?.value;
    if (!clientSecret) throw new Error("broker returned no client_secret");

    const pc = new RTCPeerConnection();
    this.pc = pc;

    this.audioEl = document.createElement("audio");
    this.audioEl.autoplay = true;
    pc.ontrack = (event) => {
      if (this.audioEl) this.audioEl.srcObject = event.streams[0];
    };

    this.micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    for (const track of this.micStream.getTracks()) pc.addTrack(track, this.micStream);
    this.startLevelMeter(this.micStream);

    const dc = pc.createDataChannel("oai-events");
    this.dc = dc;
    dc.onopen = () => {
      this.configureRealtimeSession();
      this.setStatus("listening");
    };
    dc.onmessage = (event) => this.handleRealtimeEvent(event.data);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    const model = session?.model ?? "gpt-4o-realtime-preview-2024-12-17";
    const sdpResponse = await fetch(`https://api.openai.com/v1/realtime?model=${model}`, {
      method: "POST",
      body: offer.sdp,
      headers: {
        Authorization: `Bearer ${clientSecret}`,
        "Content-Type": "application/sdp",
      },
    });
    if (!sdpResponse.ok) throw new Error(`realtime SDP ${sdpResponse.status}`);
    await pc.setRemoteDescription({ type: "answer", sdp: await sdpResponse.text() });
  }

  /** Sends tool schemas + system prompt + live context into the session. */
  private configureRealtimeSession(): void {
    if (!this.dc || this.dc.readyState !== "open") return;
    const context = renderContextBlock(this.caps.snapshotContext());
    this.dc.send(
      JSON.stringify({
        type: "session.update",
        session: {
          instructions: `${buildSystemPrompt()}\n\n${context}`,
          tools: TOOL_SCHEMAS.map((t) => ({
            type: "function",
            name: t.name,
            description: t.description,
            parameters: t.parameters,
          })),
          tool_choice: "auto",
        },
      }),
    );
  }

  private async handleRealtimeEvent(raw: string): Promise<void> {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    switch (msg.type) {
      case "response.function_call_arguments.done": {
        const name = String(msg.name ?? "");
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(String(msg.arguments ?? "{}"));
        } catch {
          /* keep empty */
        }
        this.setStatus("executing", name);
        // Re-inject fresh context so consecutive commands see prior effects.
        this.configureRealtimeSession();
        const result = await governedDispatchTool(
          { name, args },
          this.caps,
          this.lastUserTranscript || `[realtime] ${name}`,
          "openai-realtime",
          this.governance,
        );
        this.events.onAction?.(name, result);
        // Return the tool result to the model and let it speak.
        this.dc?.send(
          JSON.stringify({
            type: "conversation.item.create",
            item: {
              type: "function_call_output",
              call_id: msg.call_id,
              output: JSON.stringify(result),
            },
          }),
        );
        this.dc?.send(JSON.stringify({ type: "response.create" }));
        this.setStatus("listening");
        break;
      }
      case "conversation.item.input_audio_transcription.completed":
        this.lastUserTranscript = String(msg.transcript ?? "");
        this.events.onTranscript?.("user", this.lastUserTranscript);
        break;
      case "response.audio_transcript.done":
        this.events.onTranscript?.("assistant", String(msg.transcript ?? ""));
        break;
      case "error":
        this.setStatus("error", JSON.stringify(msg.error ?? msg));
        break;
    }
  }

  private teardownRealtime(): void {
    this.dc?.close();
    this.dc = null;
    this.pc?.close();
    this.pc = null;
    this.micStream?.getTracks().forEach((t) => t.stop());
    this.micStream = null;
    if (this.audioEl) {
      this.audioEl.srcObject = null;
      this.audioEl = null;
    }
    this.stopLevelMeter();
  }

  // ── Fast mode (Web Speech STT + Groq tools + speechSynthesis) ───────

  private async startFast(): Promise<void> {
    const SpeechRecognition =
      (window as unknown as { SpeechRecognition?: unknown; webkitSpeechRecognition?: unknown })
        .SpeechRecognition ??
      (window as unknown as { webkitSpeechRecognition?: unknown }).webkitSpeechRecognition;
    if (!SpeechRecognition) {
      throw new Error("This browser has no SpeechRecognition; use OpenAI Realtime mode.");
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recognition: any = new (SpeechRecognition as any)();
    recognition.continuous = true;
    recognition.interimResults = false;
    recognition.lang = this.language;
    this.speechFatal = false;
    recognition.onresult = (event: {
      resultIndex: number;
      results: { [i: number]: { [j: number]: { transcript: string } } };
    }) => {
      const transcript = event.results[event.resultIndex][0].transcript.trim();
      if (transcript) void this.handleFastTranscript(transcript);
    };
    recognition.onerror = (event: { error?: string }) => {
      // Two very different things arrive on this handler, and treating them
      // alike is why a dead microphone used to look identical to a quiet
      // one. `no-speech`/`aborted`/`network` are transient: the recogniser
      // ends and `onend` restarts it. A permission or service refusal is
      // fatal — restarting forever produces an orb that reads LISTENING
      // while nothing is heard and nothing is reported, which is the worst
      // possible failure for a control surface.
      const error = event?.error ?? "unknown";
      if (error === "not-allowed" || error === "service-not-allowed") {
        this.speechFatal = true;
        this.setStatus(
          "error",
          `microphone ${error} — grant mic permission, or type the command instead`,
        );
      }
    };
    recognition.onend = () => {
      if (!this.active || this.engine !== "fast" || this.speechFatal) return;
      // Chrome throws InvalidStateError if start() lands while the recogniser
      // is already running. Uncaught here it kills the restart loop silently
      // and the session goes deaf without saying so.
      try {
        recognition.start();
      } catch {
        /* already running — the existing session keeps listening */
      }
    };
    recognition.start();
    this.recognition = recognition;

    try {
      this.micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.startLevelMeter(this.micStream);
    } catch {
      /* level meter is cosmetic; STT still works without it */
    }
    this.setStatus("listening");
  }

  /**
   * Submits a typed command, as though it had been spoken.
   *
   * Speech recognition is the flakiest part of this stack — a browser with no
   * `SpeechRecognition`, a denied microphone, a noisy room, or the `no-speech`
   * timeout all leave an operator with a copilot they cannot reach. Typing is
   * the fallback, and it deliberately joins the pipeline at the same place a
   * transcript does: same system prompt, same viewport context, same tool
   * definitions, and above all the same `governedDispatchTool`, so a typed
   * command is adjudicated and sealed into the ledger exactly like a spoken
   * one. A text box that bypassed governance would be a hole straight through
   * the accountability layer.
   *
   * Works whether or not a listening session is active, so text is a true
   * fallback rather than something that only functions once the microphone
   * already does.
   */
  async sendText(text: string): Promise<void> {
    const trimmed = text.trim();
    if (!trimmed) return;
    await this.handleFastTranscript(trimmed);
  }

  /** The locale the recogniser is listening in. */
  currentLanguage(): string {
    return this.language;
  }

  /**
   * Changes the speech locale, restarting the recogniser so it takes effect
   * immediately rather than at the next session.
   *
   * Exposed because the default — the browser's locale — is a good guess and
   * not always the right one: an operator whose browser says `en-GB` may
   * speak Indian English, and the resulting mis-transcription is invisible
   * as a bug and total as a failure. Being able to correct it in one control
   * beats debugging why the copilot "misheard".
   */
  setLanguage(language: string): void {
    if (!language || language === this.language) return;
    this.language = language;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recognition = this.recognition as any;
    if (!recognition) return;
    recognition.lang = language;
    // onend restarts it with the new locale; suppress the handler for this
    // one stop so the restart is ours and not a race with it.
    try {
      recognition.stop();
    } catch {
      /* not running; the next start uses the new language anyway */
    }
  }

  /** Forgets the conversation so far, without dropping the session. */
  clearHistory(): void {
    this.history = [];
  }

  /**
   * Runs one turn, with turns strictly serialised.
   *
   * Two utterances arriving close together used to run concurrently, which
   * interleaved their tool dispatches and their status transitions and let
   * the later one's history write clobber the earlier one's. Chaining onto
   * `queue` makes a second command wait for the first to finish, which is
   * also what an operator issuing "do this, then that" actually means.
   */
  private handleFastTranscript(transcript: string): Promise<void> {
    const run = this.queue.then(() => this.runTurn(transcript));
    // Keep the chain alive even when a turn rejects, or one failure would
    // wedge every command after it.
    this.queue = run.catch(() => {});
    return run;
  }

  private async runTurn(transcript: string): Promise<void> {
    this.events.onTranscript?.("user", transcript);
    this.setStatus("thinking");
    const context = renderContextBlock(this.caps.snapshotContext());
    // The system turn is rebuilt every time so the console state block is
    // current; the history carries only the exchange itself.
    const system: ChatMessage = {
      role: "system",
      content: `${buildSystemPrompt()}\n\n${context}`,
    };
    const turn: ChatMessage[] = [...this.history, { role: "user", content: transcript }];

    let failed = false;
    try {
      const message = await this.chat([system, ...turn]);
      const toolCalls = (message?.tool_calls ?? []) as Array<{
        id?: string;
        function?: { name?: string; arguments?: string };
      }>;

      if (toolCalls.length === 0) {
        const reply = message?.content ?? "";
        if (reply) {
          this.speak(reply);
          this.events.onTranscript?.("assistant", reply);
        }
        turn.push({ role: "assistant", content: reply });
        this.remember(turn);
        return;
      }

      this.setStatus("executing");
      turn.push({
        role: "assistant",
        content: message?.content ?? null,
        tool_calls: toolCalls,
      });

      const summaries: string[] = [];
      for (const call of toolCalls) {
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(call.function?.arguments ?? "{}");
        } catch {
          /* empty */
        }
        const name = call.function?.name ?? "";
        const result = await governedDispatchTool(
          { name, args },
          this.caps,
          transcript,
          "groq-fast",
          this.governance,
        );
        this.events.onAction?.(name, result);
        summaries.push(result.summary);
        // Hand the actual result back to the model. Without this the model
        // never learns whether its call worked, so it can neither correct a
        // failed one nor chain a second call off the first's output — and a
        // question answered by a tool came back as the tool's own canned
        // summary rather than an answer to what was asked.
        turn.push({
          role: "tool",
          tool_call_id: call.id ?? name,
          content: JSON.stringify(result),
        });
      }

      // Second pass: let the model speak from what the tools actually
      // returned. The console state block is re-rendered because the tools
      // just changed it.
      let spoken = summaries.join(" ");
      try {
        const followUp = await this.chat([
          {
            role: "system",
            content: `${buildSystemPrompt()}\n\n${renderContextBlock(
              this.caps.snapshotContext(),
            )}`,
          },
          ...turn,
        ]);
        if (followUp?.content) spoken = followUp.content;
      } catch {
        // The actions already ran and are already sealed; falling back to
        // the tool summaries keeps the operator informed rather than
        // reporting a failure for work that succeeded.
      }
      turn.push({ role: "assistant", content: spoken });
      this.speak(spoken);
      this.events.onTranscript?.("assistant", spoken);
      this.remember(turn);
    } catch (error) {
      failed = true;
      this.setStatus("error", String(error));
    } finally {
      // Back to listening while a session is live; back to standby when this
      // was a typed command with the microphone off, which would otherwise
      // leave the orb reading EXECUTING forever. A failure keeps its error
      // status — resetting it here would blank the only signal the operator
      // gets that the command did not run.
      if (!failed) this.setStatus(this.active ? "listening" : "idle");
    }
  }

  /** One chat-completions round trip, returning the assistant message. */
  private async chat(messages: ChatMessage[]): Promise<{
    content?: string;
    tool_calls?: unknown[];
  }> {
    const response = await fetch("/copilot/groq/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages,
        tools: chatToolDefinitions(),
        tool_choice: "auto",
        temperature: 0.2,
      }),
    });
    if (!response.ok) throw new Error(`groq ${response.status}`);
    const data = await response.json();
    return data?.choices?.[0]?.message ?? {};
  }

  /** Keeps the tail of a completed turn as context for the next one. */
  private remember(turn: ChatMessage[]): void {
    this.history = turn.slice(-MAX_HISTORY_MESSAGES);
    // A window that starts on a tool result is unusable: the API rejects a
    // `tool` message whose originating assistant tool_calls was trimmed
    // away. Walk forward to the first message that can legally open a
    // request rather than sending one that will 400.
    while (
      this.history.length > 0 &&
      (this.history[0].role === "tool" || this.history[0].tool_calls !== undefined)
    ) {
      this.history.shift();
    }
  }

  private speak(text: string): void {
    if (!text || typeof speechSynthesis === "undefined") return;
    const utter = new SpeechSynthesisUtterance(text);
    utter.rate = 1.05;
    speechSynthesis.speak(utter);
  }

  private teardownFast(): void {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recognition = this.recognition as any;
    if (recognition) {
      recognition.onend = null;
      try {
        recognition.stop();
      } catch {
        /* already stopped */
      }
    }
    this.recognition = null;
    if (typeof speechSynthesis !== "undefined") speechSynthesis.cancel();
    this.stopLevelMeter();
    this.micStream?.getTracks().forEach((t) => t.stop());
    this.micStream = null;
  }

  // ── Shared mic level meter for the waveform ─────────────────────────

  private startLevelMeter(stream: MediaStream): void {
    try {
      this.audioCtx = new AudioContext();
      const source = this.audioCtx.createMediaStreamSource(stream);
      this.analyser = this.audioCtx.createAnalyser();
      this.analyser.fftSize = 256;
      source.connect(this.analyser);
      const data = new Uint8Array(this.analyser.frequencyBinCount);
      const tick = () => {
        if (!this.analyser) return;
        this.analyser.getByteTimeDomainData(data);
        let sum = 0;
        for (const v of data) sum += (v - 128) ** 2;
        const level = Math.min(1, Math.sqrt(sum / data.length) / 40);
        this.events.onLevel?.(level);
        this.levelRaf = requestAnimationFrame(tick);
      };
      tick();
    } catch {
      /* AudioContext unavailable — waveform stays flat */
    }
  }

  private stopLevelMeter(): void {
    if (this.levelRaf !== null) cancelAnimationFrame(this.levelRaf);
    this.levelRaf = null;
    this.analyser = null;
    void this.audioCtx?.close();
    this.audioCtx = null;
    this.events.onLevel?.(0);
  }
}
