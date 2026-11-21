"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { bySlug, canRead, defaultOpen, pages, sections } from "../navigation";
import { type Mode, type Role, type Bundle, type Entry } from "../types";
import { groups } from "../types";
import { Context, request, useDesk } from "./context";
import {
  Brand,
  I,
  Badge,
  Select,
  Layer,
  Loading,
  Empty,
  DataPairs,
  ProvenanceLine,
  stamp,
  fmt,
  Field,
} from "./primitives";
import Home from "./Home";
import Module from "./Modules";
import LiveRecords from "./LiveRecords";
import Detail from "./Detail";
const groupIcons: Record<string, string> = {
  Overview: "panel",
  Discovery: "scan",
  Analytics: "chart",
  Conversations: "message",
  Security: "outline",
  Governance: "landmark",
  "Agent Accountability": "fingerprint",
  Evidence: "filecheck",
  "AI FinOps": "wallet",
  Administration: "sliders",
};
const tourSteps = [
  [
    "home",
    "Security overview",
    "Compare the eight security and discovery indicators. Select a card to inspect the records behind it.",
  ],
  [
    "ai-applications",
    "Application discovery",
    "Review discovered domains, ownership, approval and risk. Open a record to inspect its supporting activity.",
  ],
  [
    "behavioral-activity",
    "Behavioral analytics",
    "Compare interaction volume and investigate the classifications behind a trend.",
  ],
  [
    "conversations",
    "Conversation forensics",
    "Open an interaction to inspect its timeline, masked prompt and decision.",
  ],
  [
    "alerts",
    "Investigate a detection",
    "Inspect a detection, assign an analyst and preserve case notes alongside the evidence.",
  ],
  [
    "policies",
    "Policy management",
    "Edit an ordered policy and use its simulator to check a benign condition.",
  ],
  [
    "sniffer-dog",
    "Independent execution monitoring",
    "Explore the runtime topology and replay its time-ordered observations.",
  ],
  [
    "agent-lineage",
    "Trace delegated work",
    "Follow actors and workloads across declared, observed and inferred relationships.",
  ],
  [
    "verification",
    "Verify the evidence",
    "Run the original verifier on a retained lab capture or export a signed synthetic batch.",
  ],
];
function Tour({
  step,
  setStep,
  close,
}: {
  step: number;
  setStep: (x: number) => void;
  close: () => void;
}) {
  const d = useDesk(),
    [rect, R] = useState<DOMRect | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const welcome = step < 0,
    done = step >= tourSteps.length;
  useEffect(() => {
    if (welcome || done) {
      R(null);
      return;
    }
    const selector =
      step === 0
        ? '[data-tour="home"]'
        : step === 6 || step === 7
          ? ".vgraph"
          : step === 8
            ? ".native-research"
            : '[data-tour="records"], .module-tools, .analytics-layout';
    const find = () => {
      const el = document.querySelector(selector);
      if (el) {
        const r = el.getBoundingClientRect();
        if (r.bottom > innerHeight + 50 || r.top < 65) {
          const box = el.closest(".workspace-canvas");
          if (box)
            box.scrollTo({
              top: Math.max(0, (el as HTMLElement).offsetTop - 130),
              behavior: "instant",
            });
        }
        R(el.getBoundingClientRect());
      }
    };
    const timer = setTimeout(find, 180);
    window.addEventListener("resize", find);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("resize", find);
    };
  }, [step, welcome, done, d.data]);
  useEffect(() => {
    const el = ref.current;
    const old = document.activeElement as HTMLElement | null;
    el?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
      if (e.key === "Tab" && el) {
        const a = [...el.querySelectorAll<HTMLElement>("button, [href]")];
        if (!a.length) return;
        if (
          e.shiftKey &&
          (document.activeElement === a[0] || document.activeElement === el)
        ) {
          e.preventDefault();
          a[a.length - 1].focus();
        } else if (!e.shiftKey && document.activeElement === a[a.length - 1]) {
          e.preventDefault();
          a[0].focus();
        }
      }
    };
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("keydown", key);
      old?.focus();
    };
  }, [close]);
  const move = (n: number) => {
    if (n >= 0 && n < tourSteps.length) d.go(tourSteps[n][0]);
    setStep(n);
  };
  const usable =
    rect && rect.width > 0 && rect.top < innerHeight && rect.bottom > 0;
  const fixedCard = usable && !welcome && !done && innerWidth > 680;
  return (
    <div className={"tour-layer " + (!fixedCard ? "center" : "")}>
      <div
        className="tour-shade"
        style={
          fixedCard
            ? {
                left: Math.max(rect!.left - 4, 4),
                top: Math.max(rect!.top - 4, 66),
                width: Math.min(rect!.width + 8, innerWidth - 20),
                height: Math.min(rect!.height + 8, innerHeight * 0.35),
              }
            : {}
        }
      />
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-title"
        className="tour-card"
        style={
          fixedCard
            ? {
                left: Math.max(12, Math.min(innerWidth - 378, rect!.left + 12)),
                top: Math.max(
                  75,
                  Math.min(
                    innerHeight - 225,
                    Math.max(rect!.top, 65) +
                      Math.min(rect!.height + 8, innerHeight * 0.35) +
                      13,
                  ),
                ),
              }
            : {}
        }
      >
        <div className="tour-cap">
          {welcome ? (
            <Brand short motion />
          ) : (
            <span className="tour-symbol">
              <I n={done ? "checkcircle" : "guide"} />
            </span>
          )}
          <button className="icon-btn" aria-label="Close tour" onClick={close}>
            <I n="x" size={16} />
          </button>
        </div>
        <small>
          {welcome
            ? "GUIDED PRODUCT TOUR"
            : done
              ? "TOUR COMPLETE"
              : step + 1 + " OF " + tourSteps.length}
        </small>
        <h2 id="tour-title">
          {welcome
            ? "Explore VANIAN"
            : done
              ? "Continue your evaluation"
              : tourSteps[step][1]}
        </h2>
        <p>
          {welcome
            ? "Follow an AI interaction from discovery and authorization through investigation and independent evidence verification. This tour uses a synthetic tenant."
            : done
              ? "Review the evidence workflow with your team or record a request for a guided demonstration."
              : tourSteps[step][2]}
        </p>
        <div className="tour-buttons">
          <button
            className="text-btn"
            onClick={welcome || done ? close : () => move(step - 1)}
          >
            {welcome ? "Skip tour" : done ? "Close" : "Back"}
          </button>
          <button
            className="btn primary"
            onClick={() => {
              if (done) {
                close();
                d.modal("sales");
              } else move(step + 1);
            }}
          >
            {welcome
              ? "Start tour"
              : done
                ? "Request a demo"
                : step === tourSteps.length - 1
                  ? "Finish"
                  : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}
function GlobalModal({ name, close }: { name: string; close: () => void }) {
  const d = useDesk(),
    [s, S] = useState(""),
    [contact, C] = useState(""),
    [msg, M] = useState("");
  const form = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (name === "search") form.current?.focus();
  }, [name]);
  if (name === "search") {
    const matches = pages.filter(
      (p) =>
        canRead(p, d.role) &&
        (p.title + " " + p.section).toLowerCase().includes(s.toLowerCase()),
    );
    return (
      <Layer title="Search workspace" close={close}>
        <div className="modal-pad">
          <label className="searchbox large">
            <I n="search" />
            <input
              ref={form}
              autoFocus
              aria-label="Search workspace pages and records"
              placeholder="Search pages or investigate a term…"
              value={s}
              onChange={(e) => S(e.target.value)}
            />
            <kbd>ESC</kbd>
          </label>
          <div className="search-results">
            {s &&
              ["ai-agents", "ai-applications", "alerts", "conversations"].map(
                (sl) => (
                  <button
                    key={sl}
                    onClick={() => {
                      d.go(sl + "?q=" + encodeURIComponent(s));
                      close();
                    }}
                  >
                    <I n="search" />
                    <span>
                      Search {bySlug[sl].title} for “{s}”
                    </span>
                    <I n="right" size={13} />
                  </button>
                ),
              )}
            {matches.map((p) => (
              <button
                key={p.slug}
                onClick={() => {
                  d.go(p.slug);
                  close();
                }}
              >
                <I n={p.icon} />
                <span>
                  {p.title}
                  <small>{p.section}</small>
                </span>
                <I n="right" size={13} />
              </button>
            ))}
          </div>
        </div>
      </Layer>
    );
  }
  if (name === "profile" || name === "mode") {
    return (
      <Layer
        title={name === "mode" ? "Data environment" : "Workspace profile"}
        close={close}
      >
        <div className="modal-pad stack">
          <div className="identity">
            <span className="avatar">VA</span>
            <div>
              <b>
                {d.mode === "demo"
                  ? "VANIAN demo operator"
                  : "Signed-in operator"}
              </b>
              <small>
                {d.mode === "live" && !d.data
                  ? "Membership unverified"
                  : d.role}
              </small>
            </div>
          </div>
          <Field label="Data environment">
            <Select
              value={d.mode}
              options={[
                ["demo", "Demo · deterministic synthetic data"],
                ["live", "Live · authenticated telemetry"],
              ]}
              label="Data environment"
              onChange={(v) => {
                d.changeMode(v as Mode);
                close();
              }}
            />
          </Field>
          {d.mode === "demo" && (
            <Field label="Demo role">
              <Select
                label="Demo role"
                value={d.role}
                options={["Administrator", "Analyst", "Auditor"]}
                onChange={async (v) => {
                  await d.changeRole(v as Role);
                  close();
                }}
              />
            </Field>
          )}
          <p className="muted">
            Demo changes are scoped to your evaluation tenant. Live privileges
            are assigned by the organization.
          </p>
        </div>
      </Layer>
    );
  }
  if (name === "notice") {
    return (
      <Layer title="Notifications" close={close}>
        <div className="modal-pad">
          <p className="muted">
            Recent detections in this workspace and time range.
          </p>
          {d.data?.references?.some((r) => r.id.startsWith("ALT-")) ? (
            d.data.references
              .filter((r) => r.id.startsWith("ALT-"))
              .slice(0, 5)
              .map((r) => (
                <button
                  className="notice-record"
                  key={r.id}
                  onClick={() => {
                    close();
                    d.open(r, "alerts");
                  }}
                >
                  <I n="bell" />
                  <span>
                    {r.name}
                    <small>
                      {stamp(r.at)} · {r.fields.risk}
                    </small>
                  </span>
                </button>
              ))
          ) : (
            <button
              className="btn"
              onClick={() => {
                d.go("alerts");
                close();
              }}
            >
              Open alerts
            </button>
          )}
        </div>
      </Layer>
    );
  }
  if (name === "sales")
    return (
      <Layer title="Request a guided demo" close={close}>
        <form
          className="modal-pad stack"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await request("evaluation/request", "demo", d.params, {
                email: contact,
                message: s,
              });
              M(
                "Request recorded in this evaluation workspace. Sales delivery requires a configured support channel.",
              );
            } catch (e) {
              M((e as Error).message);
            }
          }}
        >
          <Field label="Work email">
            <input
              type="email"
              required
              value={contact}
              onChange={(e) => C(e.target.value)}
            />
          </Field>
          <Field label="Evaluation focus">
            <textarea
              value={s}
              onChange={(e) => S(e.target.value)}
              maxLength={500}
            />
          </Field>
          <button className="btn primary" disabled={!!msg}>
            Record demo request
          </button>
          {msg && <p role="status">{msg}</p>}
        </form>
      </Layer>
    );
  if (name === "connection")
    return (
      <Layer title="Connect live telemetry" close={close}>
        <div className="modal-pad stack">
          <p>
            A workspace administrator connects the authenticated customer
            verifier service and grants tenant membership. The source must
            identify its observation time, processing state and supported
            capabilities.
          </p>
          <DataPairs
            items={[
              ["Deployment origin", "HTTPS, server-configured"],
              ["Authorization", "Scoped service token and user membership"],
              ["Sensor", "Sniffer Dog native batch and health records"],
              ["Verification", "Operator-provisioned public trust anchor"],
            ]}
          />
          <button
            className="btn"
            onClick={() => {
              d.go("verification");
              close();
            }}
          >
            Open verification
          </button>
        </div>
      </Layer>
    );
  return (
    <Layer title="Data provenance" close={close}>
      <div className="modal-pad">
        <DataPairs
          items={[
            ["Environment", d.mode],
            ["Source", d.data?.meta.source ?? "Unavailable"],
            [
              "Snapshot",
              d.data ? stamp(d.data.meta.asOf, true) : "Unavailable",
            ],
            [
              "Processed",
              d.data ? stamp(d.data.meta.processedAt, true) : "Unavailable",
            ],
            ["Status", d.data?.meta.status ?? "Disconnected"],
            [
              "Window",
              d.data
                ? stamp(d.data.meta.start, true) +
                  " – " +
                  stamp(d.data.meta.end, true)
                : "Unavailable",
            ],
            ["Group", d.params.get("group") || "All groups"],
          ]}
        />
      </div>
    </Layer>
  );
}
function Workspace({ initial }: { initial: string }) {
  const [url, U] = useState("/" + initial),
    [ready, Ready] = useState(false),
    [collapsed, Col] = useState(false),
    [mobile, Mobile] = useState(false),
    [open, Open] = useState<string[]>(defaultOpen),
    [mod, M] = useState(""),
    [tour, T] = useState<number | null>(null),
    [detail, D] = useState<{ row: Entry; slug: string } | null>(null),
    [msg, Msg] = useState(""),
    [role, R] = useState<Role>("Administrator"),
    [command, Cmd] = useState(false);
  const scroller = useRef<HTMLElement>(null),
    qClient = useQueryClient();
  const location = new URL(url, "https://vanian.invalid"),
    slug = location.pathname.split("/").filter(Boolean).at(-1) || "home",
    page = bySlug[slug] ?? bySlug.home,
    search = location.searchParams,
    mode: Mode = search.get("mode") === "live" ? "live" : "demo";
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const toast = useCallback((s: string) => {
    Msg(s);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => Msg(""), 4500);
  }, []);
  useEffect(() => {
    const update = () => {
      U(window.location.pathname + window.location.search);
      D(null);
      Mobile(false);
    };
    update();
    Ready(true);
    try {
      Col(localStorage.getItem("vanian-sidebar") === "collapsed");
      Cmd(localStorage.getItem("vanian-command") === "true");
    } catch {}
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  const write = useCallback((path: string, replace = false) => {
    window.history[replace ? "replaceState" : "pushState"](null, "", path);
    U(path);
  }, []);
  const go = useCallback(
    (href: string) => {
      const next = new URL(
        "/" + href.replace(/^\//, ""),
        "https://vanian.invalid",
      );
      const at = new URL(window.location.href);
      for (const k of ["group", "days", "mode"])
        if (!next.searchParams.has(k) && at.searchParams.has(k))
          next.searchParams.set(k, at.searchParams.get(k)!);
      write(next.pathname + next.search);
      D(null);
      Mobile(false);
      scroller.current?.scrollTo({ top: 0, behavior: "instant" });
    },
    [write],
  );
  const set = useCallback(
    (changes: Record<string, string | null>) => {
      const n = new URL(window.location.href);
      for (const [k, v] of Object.entries(changes))
        if (!v) n.searchParams.delete(k);
        else n.searchParams.set(k, v);
      write(n.pathname + n.search, true);
      D(null);
    },
    [write],
  );
  const sessionQuery = useQuery({
    queryKey: ["session", mode],
    queryFn: () =>
      request<{ role: Role }>("session", "demo", new URLSearchParams()),
    enabled: ready && mode === "demo",
    staleTime: 60000,
    retry: false,
  });
  useEffect(() => {
    if (mode === "demo" && sessionQuery.data) R(sessionQuery.data.role);
  }, [mode, sessionQuery.data]);
  const ds = useQuery({
    queryKey: ["data", page.api, mode, location.search, role],
    queryFn: () =>
      request<Bundle>(page.api, mode, new URLSearchParams(location.search)),
    enabled: ready && (mode === "live" || sessionQuery.isSuccess),
    staleTime: 20000,
    retry: false,
  });
  const data = ds.data;
  useEffect(() => {
    if (data?.meta.role && data.meta.role !== role) R(data.meta.role);
  }, [data?.meta.role, role]);
  const refresh = useCallback(() => {
    void qClient.invalidateQueries({ queryKey: ["data"] });
    void qClient.invalidateQueries({ queryKey: ["detail"] });
  }, [qClient]);
  const changeMode = useCallback(
    (m: Mode) => {
      D(null);
      T(null);
      M("");
      qClient.removeQueries({ queryKey: ["detail"] });
      set({ mode: m, page: null, trace: null });
    },
    [set, qClient],
  );
  const changeRole = useCallback(
    async (r: Role) => {
      try {
        await request("session/role", "demo", new URLSearchParams(), {
          role: r,
        });
        R(r);
        qClient.setQueryData(["session", "demo"], { role: r });
        qClient.removeQueries({ queryKey: ["detail"] });
        qClient.removeQueries({ queryKey: ["data"] });
        D(null);
        toast("Demo role changed to " + r);
      } catch (e) {
        toast((e as Error).message);
      }
    },
    [qClient, toast],
  );
  const closeModal = useCallback(() => M(""), []);
  const closeTour = useCallback(() => T(null), []);
  const modal = useCallback(
    (key: string) => {
      if (key === "tour") {
        Mobile(false);
        if (mode !== "demo") changeMode("demo");
        T(-1);
        M("");
      } else M(key);
    },
    [mode, changeMode],
  );
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        M((v) => (v === "search" ? "" : "search"));
      }
      if (e.key === "Escape") Mobile(false);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  useEffect(() => {
    document.title = page.title + " · VANIAN";
    Open((prev) =>
      prev.includes(page.section) ? prev : [...prev, page.section],
    );
  }, [page]);
  const toggleCollapse = () => {
    Col(!collapsed);
    localStorage.setItem(
      "vanian-sidebar",
      collapsed ? "expanded" : "collapsed",
    );
  };
  const toggleCommand = () => {
    Cmd(!command);
    localStorage.setItem("vanian-command", String(!command));
  };
  const openRow = useCallback(
    (row: Entry, pageSlug?: string) => {
      D({ row, slug: pageSlug || page.slug });
    },
    [page.slug],
  );
  const ctx = {
    page,
    selectedRowId: detail?.row.id,
    mode,
    role,
    params: search,
    data,
    go,
    set,
    open: openRow,
    toast,
    refresh,
    modal,
    changeMode,
    changeRole,
    command,
    toggleCommand,
  };
  const isHome = page.slug === "home",
    isDark =
      command &&
      ["sniffer-dog", "agent-lineage", "identity-authorization"].includes(
        page.slug,
      );
  const err = ds.error ?? (mode === "demo" ? sessionQuery.error : null);
  const navRole = mode === "live" && !data ? "Auditor" : role;
  const navigation = (
    <>
      <div className="brand-area">
        <button
          aria-label="VANIAN home"
          className="brand-button"
          onClick={() => go("home")}
        >
          <Brand short={collapsed && !mobile} />
        </button>
        <button
          className="mobile-close icon-btn"
          onClick={() => Mobile(false)}
          aria-label="Close navigation"
        >
          <I n="x" />
        </button>
      </div>
      <div className="org-wrap">
        <button
          className="org-switch"
          title="Workspace and environment"
          onClick={() => modal("mode")}
        >
          <span className="org-mark">
            <I n="boxes" size={19} />
          </span>
          <span>
            <b>VANIAN workspace</b>
            <small>
              {mode === "demo" ? "Demo organization" : "Live organization"}
            </small>
          </span>
          <I n="chevrons" size={14} />
        </button>
      </div>
      <div className="nav-head">
        <span>Navigation</span>
        <button
          title="Search navigation"
          aria-label="Search navigation"
          className="icon-btn"
          onClick={() => modal("search")}
        >
          <I n="search" size={14} />
        </button>
      </div>
      <nav aria-label="Primary navigation">
        {sections.map((section) => {
          const items = pages.filter(
              (p) => p.section === section && canRead(p, navRole),
            ),
            isOpen = open.includes(section);
          if (!items.length) return null;
          return (
            <div className="nav-group" key={section}>
              <button
                aria-expanded={isOpen}
                className={
                  "group-btn " + (section === page.section ? "is-current" : "")
                }
                title={section}
                onClick={() => {
                  if (collapsed && !mobile) {
                    Col(false);
                    Open([section]);
                  } else
                    Open((prev) =>
                      prev.includes(section)
                        ? prev.filter((v) => v !== section)
                        : [...prev, section],
                    );
                }}
              >
                <I n={groupIcons[section]} size={17} />
                <span>{section}</span>
                <I n={isOpen ? "down" : "right"} size={13} />
              </button>
              {isOpen && (
                <div className="nav-children">
                  {items.map((p) => (
                    <a
                      key={p.slug}
                      href={"/" + p.slug}
                      aria-current={p.slug === page.slug ? "page" : undefined}
                      title={p.title}
                      onClick={(e) => {
                        if (e.ctrlKey || e.metaKey) return;
                        e.preventDefault();
                        go(p.slug);
                      }}
                    >
                      <span>{p.title}</span>
                      {p.slug === page.slug && <i />}
                    </a>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>
      <div className="nav-bottom">
        <button className="tour-launch" onClick={() => modal("tour")}>
          <span>
            <I n="guide" size={17} />
          </span>
          <b>Product tour</b>
          <I n="right" size={14} />
        </button>
        <button
          className="collapse-btn"
          onClick={toggleCollapse}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <I n={collapsed ? "expand" : "collapse"} size={15} />
          <span>Collapse sidebar</span>
        </button>
      </div>
    </>
  );
  return (
    <Context.Provider value={ctx}>
      <div
        className={
          "app-shell " +
          (collapsed ? "collapsed " : "") +
          (isDark ? "command-view" : "")
        }
      >
        <a className="skip" href="#main">
          Skip to content
        </a>
        {mobile && (
          <button
            className="mobile-shade"
            aria-label="Close navigation"
            onClick={() => Mobile(false)}
          />
        )}
        <aside className={"sidebar " + (mobile ? "mobile-open" : "")}>
          {navigation}
        </aside>
        <div className="workspace">
          <header className="topbar">
            <button
              aria-label="Open navigation"
              className="mobile-menu icon-btn"
              onClick={() => Mobile(true)}
            >
              <I n="menu" />
            </button>
            <div className="crumb">
              <I n="panel" size={16} />
              <span>Workspace</span>
              <i>/</i>
              <span>{page.section}</span>
              <i>/</i>
              <b>{page.title}</b>
            </div>
            <div className="top-actions">
              <button className="global-search" onClick={() => modal("search")}>
                <I n="search" size={15} />
                <span>Search workspace</span>
                <kbd>⌘ K</kbd>
              </button>
              <button
                className="icon-btn notify"
                title="Notifications"
                aria-label="Notifications"
                onClick={() => modal("notice")}
              >
                <I n="bell" size={18} />
                {(data?.stats?.riskEvents ?? 0) > 0 && <i />}
              </button>
              <span className="separator" />
              <button
                className="profile-button"
                aria-label="Workspace profile"
                onClick={() => modal("profile")}
              >
                <span className="avatar">VA</span>
                <I n="down" size={12} />
              </button>
            </div>
          </header>
          <main id="main" ref={scroller} className="workspace-canvas">
            <div className="page-wrap">
              <div className="page-heading">
                <div>
                  <h1>{isHome ? "Security overview" : page.title}</h1>
                  <p>
                    {isHome
                      ? "AI activity, risk and agent accountability across your organization."
                      : page.description}
                  </p>
                </div>
                <div className="global-filters">
                  <Select
                    value={search.get("days") || "7"}
                    onChange={(v) => set({ days: v, page: null, trace: null })}
                    options={[
                      ["1", "Last 24 hours"],
                      ["7", "Last 7 days"],
                      ["14", "Last 14 days"],
                      ["30", "Last 30 days"],
                    ]}
                    label="Date range"
                    icon="date"
                  />
                  <Select
                    value={search.get("group") || "All groups"}
                    onChange={(v) =>
                      set({
                        group: v === "All groups" ? null : v,
                        page: null,
                        trace: null,
                      })
                    }
                    options={[
                      "All groups",
                      ...(data?.groups ?? (mode === "demo" ? groups : [])),
                    ]}
                    label="Organization group"
                    icon="org"
                  />
                </div>
              </div>
              <div className="mode-row">
                <button
                  className={"mode-pill " + mode}
                  onClick={() => modal("mode")}
                >
                  <I n={mode === "demo" ? "flask" : "radio"} size={13} />
                  {mode === "demo" ? "Demo environment" : "Live environment"}
                  <I n="down" size={11} />
                </button>
                <span className="provenance-divider" />
                {data ? (
                  <ProvenanceLine
                    meta={data.meta}
                    onClick={() => modal("provenance")}
                  />
                ) : (
                  <span className="muted">
                    {mode === "live"
                      ? "Authenticated source"
                      : "Synthetic telemetry"}{" "}
                    · {err ? "Unavailable" : "Loading"}
                  </span>
                )}
                <button
                  className="provenance-action"
                  onClick={() => modal("provenance")}
                >
                  <I n="database" size={13} />
                  Data sources
                </button>
              </div>
              {err ? (
                <div className="card error-panel">
                  <div className="error-symbol">
                    <I n={mode === "live" ? "plug" : "alert"} size={25} />
                  </div>
                  <h2>
                    {mode === "live"
                      ? "Live telemetry unavailable"
                      : "Workspace unavailable"}
                  </h2>
                  <p>{err.message}</p>
                  <div className="btn-group">
                    <button
                      className="btn"
                      onClick={() => {
                        void ds.refetch();
                        if (sessionQuery.isError) void sessionQuery.refetch();
                      }}
                    >
                      <I n="refresh" size={14} />
                      Retry
                    </button>
                    {mode === "live" && (
                      <>
                        <button
                          className="btn"
                          onClick={() => go("sniffer-dog")}
                        >
                          Open sensor records
                        </button>
                        <button
                          className="btn primary"
                          onClick={() => changeMode("demo")}
                        >
                          Open demo workspace
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ) : !data ? (
                <Loading />
              ) : mode === "live" ? (
                <LiveRecords />
              ) : isHome ? (
                <Home />
              ) : (
                <Module />
              )}
            </div>
          </main>
        </div>
      </div>
      {mod && <GlobalModal key={mod} name={mod} close={closeModal} />}
      {tour !== null && <Tour step={tour} setStep={T} close={closeTour} />}
      {detail && (
        <Detail
          key={detail.slug + detail.row.id}
          row={detail.row}
          slug={detail.slug}
          close={() => D(null)}
        />
      )}
      {msg && (
        <div className="toast" role="status">
          <I n="info" size={16} />
          {msg}
          <button
            className="icon-btn"
            onClick={() => Msg("")}
            aria-label="Dismiss message"
          >
            <I n="x" size={14} />
          </button>
        </div>
      )}
    </Context.Provider>
  );
}
export default function Console({ initial }: { initial: string }) {
  const [c] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { refetchOnWindowFocus: false, retry: false },
        },
      }),
  );
  return (
    <QueryClientProvider client={c}>
      <Workspace initial={initial} />
    </QueryClientProvider>
  );
}
