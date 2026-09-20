// J.A.R.V.I.S — the console's voice copilot, presented the way the
// gods-eye-view demo presents it: an arc-reactor orb over the open globe
// that breathes with the microphone, ringed by rotating instrument arcs,
// with the conversation and every governed action unfurling above it.
//
// Presentation only. All audio, engine selection and tool dispatch stay in
// the VoiceCopilot controller (src/agent/voice-copilot.ts), and every tool
// call still routes through governedDispatchTool — the orb is a new face on
// the same governed pipeline, not a bypass of it. Spacebar toggles the
// session (ignored while typing), exactly as the old mic widget did.

import { useCallback, useEffect, useRef, useState } from "react";
import { Mic, MicOff, Radio, ShieldCheck } from "lucide-react";

import { cn } from "../../lib/cn";
import { INK, SURFACE, TYPE } from "../../lib/design";
import type { TacticalCapabilities } from "../../agent/capabilities";
import {
  VoiceCopilot,
  defaultSpeechLanguage,
  probeBroker,
  type CopilotEngine,
  type CopilotStatus,
} from "../../agent/voice-copilot";
import type { ToolResult } from "../../agent/tactical-tools";

/** Where the operator's chosen speech locale is remembered. */
const SPEECH_LANG_KEY = "ot.jarvis.speechLang";

/** Locales offered in the picker.
 *
 * English variants first and deliberately several of them: Web Speech is
 * markedly more accurate when the variant matches the speaker, and a
 * mismatch presents as the copilot misunderstanding rather than as a
 * settings problem. The list is short on purpose — these are the ones worth
 * one click, not an exhaustive locale table.
 */
const SPEECH_LANGUAGES: Array<{ code: string; label: string }> = [
  { code: "en-IN", label: "English (India)" },
  { code: "en-US", label: "English (US)" },
  { code: "en-GB", label: "English (UK)" },
  { code: "en-AU", label: "English (Australia)" },
  { code: "hi-IN", label: "हिन्दी" },
  { code: "es-ES", label: "Español" },
  { code: "fr-FR", label: "Français" },
  { code: "de-DE", label: "Deutsch" },
];

export interface JarvisInterfaceProps {
  /** Null until the globe is ready; the orb stays disabled meanwhile. */
  getCapabilities: () => TacticalCapabilities | null;
  className?: string;
}

const STATUS_LABEL: Record<CopilotStatus, string> = {
  idle: "STANDBY",
  connecting: "LINKING",
  listening: "LISTENING",
  thinking: "PROCESSING",
  executing: "EXECUTING",
  error: "FAULT",
};

/** One ring/glow colour per status — the orb is readable at a glance. */
const STATUS_COLOR: Record<CopilotStatus, string> = {
  idle: "#0e7490", // cyan-700: dormant but findable over the dark globe
  connecting: "#f59e0b", // amber-500
  listening: "#34d399", // emerald-400
  thinking: "#22d3ee", // cyan-400
  executing: "#22d3ee",
  error: "#f87171", // red-400
};

interface Exchange {
  id: number;
  role: "user" | "assistant";
  text: string;
}

interface ActionFlash {
  id: number;
  tool: string;
  ok: boolean;
  summary: string;
}

const MAX_EXCHANGES = 8;

export default function JarvisInterface({ getCapabilities, className }: JarvisInterfaceProps) {
  const copilotRef = useRef<VoiceCopilot | null>(null);
  const levelRef = useRef(0);
  const coreRef = useRef<SVGCircleElement>(null);
  const haloRef = useRef<SVGCircleElement>(null);
  const seq = useRef(0);

  const [status, setStatus] = useState<CopilotStatus>("idle");
  const [engine, setEngine] = useState<CopilotEngine | null>(null);
  const [available, setAvailable] = useState<{
    realtime: boolean;
    fast: boolean;
    text: boolean;
  }>({ realtime: false, fast: false, text: false });
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [flashes, setFlashes] = useState<ActionFlash[]>([]);
  const [typed, setTyped] = useState("");
  const [sending, setSending] = useState(false);
  // Distinguishes "still probing the broker" from "probed and offline", so
  // the command line can say which — a disabled input with no reason reads
  // as broken UI rather than as a missing engine.
  const [probed, setProbed] = useState(false);
  const typedInputRef = useRef<HTMLInputElement>(null);
  // Speech locale. Remembered per operator, because the browser default is a
  // guess and the symptom of a wrong one — words transcribed incorrectly —
  // looks like the copilot being stupid rather than mishearing.
  const [language, setLanguage] = useState<string>(() => {
    try {
      return localStorage.getItem(SPEECH_LANG_KEY) ?? defaultSpeechLanguage();
    } catch {
      return defaultSpeechLanguage();
    }
  });

  // Probe which engines the broker can serve (badge + availability).
  useEffect(() => {
    let cancelled = false;
    probeBroker().then((broker) => {
      if (cancelled) return;
      const fastPossible =
        typeof window !== "undefined" &&
        ("SpeechRecognition" in window || "webkitSpeechRecognition" in window) &&
        broker.groq;
      setAvailable({
        realtime: broker.openaiRealtime,
        fast: fastPossible,
        // Typing needs the chat broker and nothing else — no microphone, and
        // no SpeechRecognition support. That is the whole point: the text
        // path has to work on the browsers and in the conditions where the
        // voice path cannot.
        text: broker.groq,
      });
      setProbed(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const pushFlash = useCallback((tool: string, result: ToolResult) => {
    const flash: ActionFlash = { id: seq.current++, tool, ok: result.ok, summary: result.summary };
    setFlashes((current) => [...current.slice(-3), flash]);
    window.setTimeout(() => {
      setFlashes((current) => current.filter((f) => f.id !== flash.id));
    }, 6000);
  }, []);

  // Core pulse: read the shared mic level at frame rate, write straight to
  // the SVG — never through React state.
  useEffect(() => {
    let raf = 0;
    const render = () => {
      const level = levelRef.current;
      if (coreRef.current) {
        coreRef.current.setAttribute("r", String(10 + level * 9));
      }
      if (haloRef.current) {
        haloRef.current.setAttribute("r", String(16 + level * 16));
        haloRef.current.setAttribute("opacity", String(0.12 + level * 0.5));
      }
      raf = requestAnimationFrame(render);
    };
    raf = requestAnimationFrame(render);
    return () => cancelAnimationFrame(raf);
  }, []);

  const ensureCopilot = useCallback((): VoiceCopilot | null => {
    if (copilotRef.current) return copilotRef.current;
    const caps = getCapabilities();
    if (!caps) return null;
    copilotRef.current = new VoiceCopilot(caps, {
      onStatus: (s) => setStatus(s),
      onTranscript: (role, text) =>
        setExchanges((current) => [...current.slice(-(MAX_EXCHANGES - 1)), { id: seq.current++, role, text }]),
      onAction: pushFlash,
      onLevel: (level) => {
        levelRef.current = level;
      },
    });
    copilotRef.current.setLanguage(language);
    return copilotRef.current;
  }, [getCapabilities, pushFlash, language]);

  /** Applies a locale change to a live session and remembers it. */
  const changeLanguage = useCallback((code: string) => {
    setLanguage(code);
    try {
      localStorage.setItem(SPEECH_LANG_KEY, code);
    } catch {
      /* private mode — the choice still applies to this session */
    }
    copilotRef.current?.setLanguage(code);
  }, []);

  const toggle = useCallback(async () => {
    const copilot = ensureCopilot();
    if (!copilot) return;
    await copilot.toggle();
    setEngine(copilot.isActive() ? copilot.currentEngine() : null);
  }, [ensureCopilot]);

  /** Sends a typed command down the same governed path a spoken one takes. */
  const submitTyped = useCallback(async () => {
    const text = typed.trim();
    if (!text || sending) return;
    const copilot = ensureCopilot();
    if (!copilot) return;
    // Cleared straight away so the operator can queue the next thought while
    // this one runs, and cannot double-submit by hitting Enter twice.
    setTyped("");
    setSending(true);
    try {
      await copilot.sendText(text);
    } finally {
      setSending(false);
    }
  }, [typed, sending, ensureCopilot]);

  // Spacebar push-to-talk / toggle, and "/" to jump to the command line —
  // both ignored while the operator is already typing somewhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) return;
      if (e.code === "Slash") {
        // Typing is a first-class way in, so it gets a first-class key. The
        // preventDefault stops the "/" from landing in the input it focuses.
        e.preventDefault();
        typedInputRef.current?.focus();
        return;
      }
      if (e.code !== "Space") return;
      e.preventDefault();
      void toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);

  useEffect(() => {
    return () => {
      void copilotRef.current?.stop();
    };
  }, []);

  const anyEngine = available.realtime || available.fast;
  const active = status !== "idle" && status !== "error";
  const color = STATUS_COLOR[status];
  // The panel is always present: typing is a first-class way to command the
  // console, not a fallback that appears once voice has failed. Even with
  // the chat broker offline the panel stays, because a visible, disabled
  // command line that says why beats an interface with no way in at all.
  const showPanel = true;

  return (
    <div className={cn("flex flex-col items-center gap-2 pointer-events-auto", className)}>
      {/* Conversation + governed-action panel, unfurled above the orb. */}
      {showPanel && (
        <div className={cn(SURFACE.raised, "rounded-md w-80 max-h-[38vh] flex flex-col font-mono")}>
          <div className="flex items-center gap-2 px-3 py-1.5 border-b border-cyan-500/15">
            <span className={cn(TYPE.label, INK.secondary)}>Copilot channel</span>
            <span
              className={cn(TYPE.caption, "ml-auto flex items-center gap-1")}
              title="Every tool call is adjudicated and sealed to the ledger before it runs"
            >
              <ShieldCheck className="w-3 h-3 text-emerald-300" />
              <span className="text-emerald-300">GOVERNED</span>
            </span>
          </div>
          <div className="overflow-y-auto px-3 py-2 space-y-1">
            {exchanges.length === 0 && (
              <div className={cn(TYPE.body, INK.muted)}>
                Speak (Space) or type a command below ( / ) — both are governed.
              </div>
            )}
            {exchanges.map((x) => (
              <div key={x.id} className={cn(TYPE.body, "flex gap-1.5")}>
                <span className={cn("shrink-0", x.role === "user" ? "text-cyan-500" : "text-emerald-400")}>
                  {x.role === "user" ? "OPR ▸" : "JVS ◂"}
                </span>
                <span className={cn(x.role === "user" ? INK.secondary : INK.primary, "break-words min-w-0")}>
                  {x.text}
                </span>
              </div>
            ))}
            {/* Governed tool results: word + colour, sealed note in the title. */}
            {flashes.map((flash) => (
              <div
                key={flash.id}
                className={cn(
                  TYPE.body,
                  "border-l-2 pl-1.5",
                  flash.ok ? "border-emerald-400 text-emerald-300" : "border-red-400 text-red-300",
                )}
                title={`${flash.tool} — adjudicated, executed, sealed to the accountability ledger`}
              >
                {flash.ok ? "✓" : "✕"} {flash.summary}
              </div>
            ))}
          </div>

          {/* Typed command entry: a first-class way in, peer to the
              microphone, not a fallback behind it. Same governed pipeline —
              see VoiceCopilot.sendText. Always rendered; when the chat
              broker cannot serve it, it stays visible but disabled and says
              why, because a command line that vanishes reads as a bug. */}
          <form
            className="flex items-center gap-1.5 px-2 py-1.5 border-t border-cyan-500/15"
            onSubmit={(e) => {
              e.preventDefault();
              void submitTyped();
            }}
          >
            <span className={cn(TYPE.caption, "text-cyan-500 shrink-0")}>OPR ▸</span>
            <input
              ref={typedInputRef}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={sending || !available.text}
              placeholder={
                !probed
                  ? "checking engines…"
                  : !available.text
                    ? "chat engine offline — set GROQ_API_KEY on the broker"
                    : sending
                      ? "sending…"
                      : "type a command…  ( / )"
              }
              aria-label="Type a command for the copilot"
              title="Typed commands go through the same governed, ledger-sealed pipeline as spoken ones. Press / to focus."
              className={cn(
                TYPE.body,
                "flex-1 min-w-0 bg-transparent outline-none",
                INK.primary,
                "placeholder:text-cyan-700 disabled:opacity-50",
              )}
            />
            <button
              type="submit"
              disabled={sending || !available.text || typed.trim().length === 0}
              title="Send (Enter)"
              className={cn(
                TYPE.caption,
                "shrink-0 rounded border border-cyan-500/30 px-1.5 py-0.5",
                "hover:border-cyan-400/60 hover:text-cyan-200 disabled:opacity-30",
                INK.secondary,
              )}
            >
              SEND
            </button>
          </form>

          {/* Speech locale. Only shown when this browser can actually listen —
              on a text-only fallback there is no recogniser to configure. */}
          {available.fast && (
            <div className="flex items-center gap-1.5 px-2 pb-1.5">
              <span className={cn(TYPE.caption, "text-cyan-600 shrink-0")}>HEARS</span>
              <select
                value={language}
                onChange={(e) => changeLanguage(e.target.value)}
                aria-label="Speech recognition language"
                title="Set this to the English you actually speak — a mismatch shows up as the copilot mishearing you"
                className={cn(
                  TYPE.caption,
                  "flex-1 min-w-0 bg-transparent outline-none cursor-pointer",
                  "border border-cyan-500/20 rounded px-1 py-0.5",
                  "hover:border-cyan-400/50",
                  INK.secondary,
                )}
              >
                {SPEECH_LANGUAGES.some((l) => l.code === language) ? null : (
                  <option value={language}>{language}</option>
                )}
                {SPEECH_LANGUAGES.map((l) => (
                  <option key={l.code} value={l.code} className="bg-slate-950">
                    {l.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      )}

      {/* The arc-reactor orb. */}
      <button
        type="button"
        onClick={() => void toggle()}
        disabled={!anyEngine}
        title={
          anyEngine
            ? "Toggle J.A.R.V.I.S voice copilot (Space)"
            : available.text
              ? "Speech recognition is unavailable in this browser — type a command instead"
              : "No engine configured — set OPENAI_API_KEY or GROQ_API_KEY on the broker"
        }
        className={cn(
          "relative w-24 h-24 rounded-full",
          !anyEngine && "opacity-40 cursor-not-allowed",
        )}
      >
        <svg viewBox="0 0 100 100" className="w-full h-full">
          {/* Breathing halo behind everything. */}
          <circle ref={haloRef} cx="50" cy="50" r="16" fill={color} opacity="0.12" />

          {/* Outer instrument arc: slow clockwise sweep. */}
          <g className="origin-center animate-[spin_14s_linear_infinite]">
            <circle
              cx="50"
              cy="50"
              r="46"
              fill="none"
              stroke={color}
              strokeWidth="1.5"
              strokeDasharray="40 18 8 18 40 165"
              opacity="0.8"
            />
          </g>
          {/* Middle arc: counter-rotating, faster when active. */}
          <g
            className="origin-center animate-[spin_9s_linear_infinite]"
            style={{ animationDirection: "reverse", animationDuration: active ? "4s" : "9s" }}
          >
            <circle
              cx="50"
              cy="50"
              r="38"
              fill="none"
              stroke={color}
              strokeWidth="2.5"
              strokeDasharray="26 10 4 10 26 163"
              opacity="0.6"
            />
          </g>
          {/* Tick ring: fixed graduation marks. */}
          <g opacity="0.45">
            {Array.from({ length: 24 }).map((_, i) => {
              const a = (i / 24) * 2 * Math.PI;
              const x1 = 50 + 30 * Math.cos(a);
              const y1 = 50 + 30 * Math.sin(a);
              const x2 = 50 + (i % 6 === 0 ? 26 : 28) * Math.cos(a);
              const y2 = 50 + (i % 6 === 0 ? 26 : 28) * Math.sin(a);
              return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={color} strokeWidth="1" />;
            })}
          </g>
          {/* The reactor core: radius rides the live mic level. */}
          <circle
            ref={coreRef}
            cx="50"
            cy="50"
            r="10"
            fill={color}
            className={cn(active && "animate-pulse")}
            opacity="0.9"
          />
          <circle cx="50" cy="50" r="21" fill="none" stroke={color} strokeWidth="1" opacity="0.7" />
        </svg>
        {/* Mic glyph in the core. */}
        <span className="absolute inset-0 flex items-center justify-center text-slate-950">
          {active ? <Mic className="w-4 h-4" /> : <MicOff className="w-4 h-4 text-cyan-200/80" />}
        </span>
      </button>

      {/* Wordmark + status readout. */}
      <div className={cn(SURFACE.base, "rounded-md px-3 py-1 flex items-center gap-2 font-mono")}>
        <span className={cn("tracking-[0.3em] text-[11px] font-semibold", INK.primary)}>
          J.A.R.V.I.S
        </span>
        <span
          className={cn(TYPE.caption, "tracking-[0.2em]")}
          style={{ color: STATUS_COLOR[status === "idle" ? "thinking" : status] }}
        >
          {STATUS_LABEL[status]}
        </span>
        {engine && (
          <span className={cn(TYPE.caption, INK.muted, "flex items-center gap-0.5")}>
            <Radio className="w-2.5 h-2.5" />
            {engine === "realtime" ? "OPENAI RT" : "GROQ FAST"}
          </span>
        )}
      </div>
    </div>
  );
}
