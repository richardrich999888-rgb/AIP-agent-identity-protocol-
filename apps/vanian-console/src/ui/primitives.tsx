"use client";
import { useEffect, useRef, useId, type ReactNode } from "react";
import {
  House,
  ShieldCheck,
  LayoutGrid,
  Bot,
  Network,
  ScanLine,
  Ghost,
  Layers,
  MessagesSquare,
  Activity,
  Radar,
  GitFork,
  Fingerprint,
  Bell,
  BriefcaseBusiness,
  ScrollText,
  SlidersHorizontal,
  LockKeyhole,
  Crosshair,
  Landmark,
  KeyRound,
  ClipboardCheck,
  FileCheck2,
  Users,
  ChartNoAxesCombined,
  Wallet,
  Plug,
  Settings,
  BookOpen,
  ListFilter,
  CircleCheck,
  History,
  Cpu,
  Server,
  Boxes,
  Globe,
  ChevronRight,
  ChevronDown,
  ChevronsUpDown,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Menu,
  X,
  TriangleAlert,
  Info,
  CircleHelp,
  Database,
  CalendarDays,
  Building2,
  Ellipsis,
  Download,
  Play,
  ChevronLeft,
  Plus,
  ArrowUpRight,
  TrendingUp,
  TrendingDown,
  Minus,
  RefreshCw,
  Eye,
  Check,
  Copy,
  Clock3,
  ShieldAlert,
  FileText,
  Waypoints,
  FlaskConical,
  RadioTower,
  Shield,
  Route,
  FileKey2,
  Command,
  Sun,
  Moon,
  Filter,
  ArrowDownUp,
  Maximize2,
  Pause,
  BookOpenCheck,
  UserRound,
  ArrowLeft,
  Mail,
  ExternalLink,
  ScanFace,
  Link2,
  GlobeLock,
  SquareTerminal,
  BookMarked,
  ReceiptText,
  ChartPie,
  CalendarClock,
  PanelTop,
  Dot,
  type LucideIcon,
} from "lucide-react";
import type { Entry, Provenance } from "../types";
const icons: Record<string, LucideIcon> = {
  home: House,
  shield: ShieldCheck,
  apps: LayoutGrid,
  bot: Bot,
  network: Network,
  scan: ScanLine,
  ghost: Ghost,
  inventory: Layers,
  message: MessagesSquare,
  activity: Activity,
  radar: Radar,
  lineage: GitFork,
  fingerprint: Fingerprint,
  bell: Bell,
  case: BriefcaseBusiness,
  policy: ScrollText,
  sliders: SlidersHorizontal,
  lock: LockKeyhole,
  target: Crosshair,
  landmark: Landmark,
  key: KeyRound,
  clipboard: ClipboardCheck,
  filecheck: FileCheck2,
  users: Users,
  chart: ChartNoAxesCombined,
  wallet: Wallet,
  plug: Plug,
  settings: Settings,
  book: BookOpen,
  list: ListFilter,
  checkcircle: CircleCheck,
  history: History,
  cpu: Cpu,
  server: Server,
  boxes: Boxes,
  globe: Globe,
  right: ChevronRight,
  down: ChevronDown,
  chevrons: ChevronsUpDown,
  collapse: PanelLeftClose,
  expand: PanelLeftOpen,
  search: Search,
  menu: Menu,
  x: X,
  alert: TriangleAlert,
  info: Info,
  help: CircleHelp,
  database: Database,
  date: CalendarDays,
  org: Building2,
  more: Ellipsis,
  download: Download,
  play: Play,
  left: ChevronLeft,
  plus: Plus,
  open: ArrowUpRight,
  up: TrendingUp,
  trenddown: TrendingDown,
  minus: Minus,
  refresh: RefreshCw,
  eye: Eye,
  check: Check,
  copy: Copy,
  clock: Clock3,
  danger: ShieldAlert,
  file: FileText,
  graph: Waypoints,
  flask: FlaskConical,
  radio: RadioTower,
  outline: Shield,
  route: Route,
  signed: FileKey2,
  command: Command,
  sun: Sun,
  moon: Moon,
  filter: Filter,
  sort: ArrowDownUp,
  maximize: Maximize2,
  pause: Pause,
  guide: BookOpenCheck,
  user: UserRound,
  back: ArrowLeft,
  mail: Mail,
  external: ExternalLink,
  face: ScanFace,
  link: Link2,
  globelock: GlobeLock,
  terminal: SquareTerminal,
  bookmarked: BookMarked,
  receipt: ReceiptText,
  pie: ChartPie,
  day: CalendarClock,
  panel: PanelTop,
  dot: Dot,
};
export function I({
  n,
  size = 17,
  ...rest
}: {
  n: string;
  size?: number;
  className?: string;
  strokeWidth?: number;
}) {
  const C = icons[n] ?? Boxes;
  return <C size={size} strokeWidth={1.75} aria-hidden="true" {...rest} />;
}
export function Brand({
  short = false,
  motion = false,
}: {
  short?: boolean;
  motion?: boolean;
}) {
  return (
    <span
      className={"brand " + (motion ? "brand-motion" : "")}
      aria-label="VANIAN AI Security Control Plane"
    >
      <svg viewBox="550 158 474 365" role="img" aria-label="VANIAN orbital V">
        <image href="/brand/vanian-original.jpeg" width="1536" height="1024" />
      </svg>
      {!short && (
        <span className="brand-type">
          <svg viewBox="337 568 887 87" aria-label="VANIAN" role="img">
            <image
              href="/brand/vanian-original.jpeg"
              width="1536"
              height="1024"
            />
          </svg>
          <small>AI SECURITY CONTROL PLANE</small>
        </span>
      )}
    </span>
  );
}
export const fmt = (n: number) =>
  !Number.isFinite(n)
    ? "Unavailable"
    : new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(n);
export const money = (n: number) =>
  !Number.isFinite(n)
    ? "Unavailable"
    : new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
        maximumFractionDigits: 2,
      }).format(n);
export const stamp = (at: string, full = false) =>
  !at
    ? "Unavailable"
    : new Intl.DateTimeFormat("en-GB", {
        month: "short",
        day: "2-digit",
        ...(full ? ({ year: "numeric" } as const) : {}),
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
        timeZone: "UTC",
      }).format(new Date(at)) + " UTC";
export function tone(s: string) {
  const t = s.toLowerCase();
  if (/critical|high risk|^high$|^blocked$|^block$|failed|revoked/.test(t))
    return "red";
  if (
    /suspected|warn|medium|unregistered|orphan|delayed|pending|unknown|unverified|unbound|restricted|review required/.test(
      t,
    )
  )
    return "amber";
  if (
    /^(verified|healthy|passed|allowed|allow|approved|registered|active|enabled|resolved)$/.test(
      t,
    )
  )
    return "green";
  if (/in review|routed|^route$|open|observed|evidence available/.test(t))
    return "violet";
  return "neutral";
}
export function Badge({
  children,
  kind,
  dot = false,
}: {
  children: ReactNode;
  kind?: string;
  dot?: boolean;
}) {
  return (
    <span className={"badge " + (kind ?? tone(String(children)))}>
      {dot && <b />}
      {children}
    </span>
  );
}
export function ProvenanceLine({
  meta,
  onClick,
}: {
  meta: Provenance;
  onClick?: () => void;
}) {
  return (
    <button
      className="source-line"
      onClick={onClick}
      title={
        meta.source +
        " · " +
        stamp(meta.processedAt, true) +
        " · " +
        meta.status
      }
    >
      <span className="source-dot" />
      {meta.mode === "demo" ? "Synthetic telemetry" : "Live telemetry"}
      <span>·</span>
      {stamp(meta.asOf)}
      <span>·</span>
      {meta.status}
      <I n="info" size={12} />
    </button>
  );
}
export function Layer({
  title,
  children,
  close,
  drawer = false,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
  drawer?: boolean;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const label = useId();
  const cb = useRef(close);
  cb.current = close;
  useEffect(() => {
    const el = ref.current;
    el?.showModal();
    const old = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = old;
      el?.close();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={drawer ? "drawer" : wide ? "modal wide" : "modal"}
      aria-labelledby={label}
      onCancel={(e) => {
        e.preventDefault();
        cb.current();
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          const box = e.currentTarget.getBoundingClientRect();
          if (
            e.clientX < box.left ||
            e.clientX > box.right ||
            e.clientY < box.top ||
            e.clientY > box.bottom
          )
            cb.current();
        }
      }}
    >
      <div className="layer-head">
        <h2 id={label}>{title}</h2>
        <button className="icon-btn" onClick={close} aria-label="Close dialog">
          <I n="x" />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function Empty({
  title = "No matching records",
  message = "Try another filter or a wider date range.",
  action,
  label,
}: {
  title?: string;
  message?: string;
  action?: () => void;
  label?: string;
}) {
  return (
    <div className="empty">
      <span>
        <I n="search" size={23} />
      </span>
      <h3>{title}</h3>
      <p>{message}</p>
      {action && (
        <button className="btn" onClick={action}>
          {label || "Clear filters"}
        </button>
      )}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <div />
      <div />
      <div />
      <span>Loading workspace records…</span>
    </div>
  );
}
export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}
export function Select({
  value,
  onChange,
  options,
  label,
  icon,
}: {
  value: string;
  onChange: (v: string) => void;
  options: (string | [string, string])[];
  label: string;
  icon?: string;
}) {
  return (
    <label className={"select-wrap " + (icon ? "with-icon" : "")}>
      {icon && <I n={icon} size={15} />}
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => {
          const [v, t] = typeof o === "string" ? [o, o] : o;
          return (
            <option key={v} value={v}>
              {t}
            </option>
          );
        })}
      </select>
      <I n="down" size={13} />
    </label>
  );
}
export function saveFile(
  name: string,
  data: BlobPart,
  type = "application/json",
) {
  const u = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 800);
}
export function csv(values: (string | number | boolean)[][]) {
  const escape = (v: unknown) => {
    let s = String(v ?? "");
    if (/^[=+@\-\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replaceAll('"', '""') + '"';
  };
  return values.map((r) => r.map(escape).join(",")).join("\r\n");
}
export function DataPairs({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="data-pairs">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v || "Unspecified"}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Mark({ row }: { row: Entry }) {
  return (
    <span className={"appmark hue" + (row.name.charCodeAt(0) % 5)}>
      {row.name.slice(0, 1)}
    </span>
  );
}
