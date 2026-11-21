"use client";

import {
  lazy,
  memo,
  Suspense,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  BaseEdge,
  getSmoothStepPath,
  MarkerType,
  type EdgeProps,
  Position,
  ReactFlow,
  useReactFlow,
  type Edge,
  type Node as FlowNode,
  type NodeProps,
} from "@xyflow/react";
import {
  Box,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Download,
  GitBranch,
  List,
  Maximize,
  Minus,
  Plus,
  Search,
  Workflow,
  X,
} from "lucide-react";
import "@xyflow/react/dist/style.css";
import "./visual.css";
import { DiagramGlyph, TopologyGlyph } from "./TopologyGlyph";
import {
  kindNames,
  prepareGraph,
  relationNames,
  type GraphCommand,
  type GraphLayout,
  type Relation,
  type TopologyEdge,
  type TopologyNode,
} from "./model";

export type { TopologyEdge, TopologyNode } from "./model";
export interface GraphExport {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  relationshipFilter: Relation | "all";
}
const Spatial = lazy(() => import("./Topology3D"));
const CARD_WIDTH = 192;
const CARD_HEIGHT = 94;
type DisplayNode = FlowNode<
  {
    record: TopologyNode;
    active: boolean;
    collapsed: boolean;
    connected: boolean;
    commandMode: boolean;
  },
  "record"
>;
type DisplayEdge = Edge<
  { relationship: TopologyEdge; emphasis: boolean },
  "conduit"
>;

// Fold long chains into readable rows while keeping each level and branch intact.
function instrumentLayout(g: GraphLayout, columns: number): GraphLayout {
  const xs = [...new Set(g.nodes.map((n) => n.x))].sort((a, b) => a - b);
  const ranks = xs.map((x) =>
    g.nodes.filter((n) => n.x === x).sort((a, b) => a.y - b.y),
  );
  const placed: GraphLayout["nodes"] = [];
  let top = 0;
  for (let start = 0; start < ranks.length; start += columns) {
    const band = ranks.slice(start, start + columns);
    const height =
      Math.max(...band.map((lane) => lane.length), 1) * (CARD_HEIGHT + 22) - 22;
    const reverse = Math.floor(start / columns) % 2 === 1;
    band.forEach((lane, index) => {
      const col = reverse ? columns - index - 1 : index;
      lane.forEach((n, j) =>
        placed.push({
          ...n,
          x: col * (CARD_WIDTH + 64),
          y:
            top +
            (height - (lane.length * (CARD_HEIGHT + 22) - 22)) / 2 +
            j * (CARD_HEIGHT + 22),
        }),
      );
    });
    top += height + 86;
  }
  return { ...g, nodes: placed };
}
function portSides(
  a: GraphLayout["nodes"][number],
  b: GraphLayout["nodes"][number],
) {
  if (a.id === b.id) return [Position.Top, Position.Right] as const;
  if (Math.abs(a.x - b.x) < 1)
    return a.y < b.y
      ? ([Position.Bottom, Position.Top] as const)
      : ([Position.Top, Position.Bottom] as const);
  return a.x < b.x
    ? ([Position.Right, Position.Left] as const)
    : ([Position.Left, Position.Right] as const);
}
type View = "2d" | "3d" | "records";

interface Props {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  title?: string;
  mode?: "light" | "command";
  initialView?: View;
  onSelect?: (node: TopologyNode) => void;
  onExport?: (visible: GraphExport) => void;
  className?: string;
}

const RecordCard = memo(function RecordCard({ data }: NodeProps<DisplayNode>) {
  const record = data.record;
  return (
    <div
      className={
        "vgraph-node vgraph-node--" +
        record.kind +
        (data.active ? " vgraph-node--active" : "") +
        (data.connected ? " vgraph-node--connected" : "")
      }
      title={record.label + " · " + (record.status ?? record.id)}
    >
      {[Position.Top, Position.Right, Position.Bottom, Position.Left].map(
        (side) => (
          <span key={side}>
            <Handle
              id={side + "-out"}
              type="source"
              position={side}
              isConnectable={false}
            />
            <Handle
              id={side + "-in"}
              type="target"
              position={side}
              isConnectable={false}
            />
          </span>
        ),
      )}
      <span className="vgraph-glyph-well">
        {data.commandMode ? (
          <TopologyGlyph kind={record.kind} />
        ) : (
          <DiagramGlyph kind={record.kind} />
        )}
      </span>
      <span className="vgraph-node-copy">
        <small>{kindNames[record.kind] ?? "Identity"}</small>
        <strong>{record.label}</strong>
      </span>
      <span className="vgraph-node-rail">
        <code title={record.id}>{record.id}</code>
        {typeof record.confidence === "number" ? (
          <span
            title={
              (record.status ? record.status + " · " : "") +
              "Attribution confidence"
            }
          >
            {record.confidence}%
          </span>
        ) : record.status ? (
          <span title={record.status}>{record.status}</span>
        ) : null}
      </span>
      {data.collapsed && (
        <span className="vgraph-foldmark">
          <Plus size={10} />
        </span>
      )}
    </div>
  );
});
const nodeTypes = { record: RecordCard };

function Conduit(props: EdgeProps<DisplayEdge>) {
  const rel = props.data?.relationship;
  if (!rel) return null;
  const [route, x, y] = getSmoothStepPath({
    ...props,
    borderRadius: 11,
    offset: 26,
  });
  const cls =
    "vgraph-conduit vgraph-conduit--" +
    rel.relation +
    (props.data?.emphasis ? " vgraph-conduit--focused" : "");
  return (
    <g className={cls}>
      <title>
        {(rel.label ?? "Relationship") +
          " · " +
          relationNames[rel.relation] +
          (rel.evidence ? " · " + rel.evidence : "")}
      </title>
      <path d={route} fill="none" className="vgraph-conduit-under" />
      <BaseEdge
        id={props.id}
        path={route}
        className="vgraph-conduit-line"
        markerEnd={props.markerEnd}
        interactionWidth={16}
      />
      <g
        transform={"translate(" + x + " " + y + ")"}
        className="vgraph-conduit-marker"
        aria-hidden="true"
      >
        {rel.relation === "observed" ? (
          <>
            <circle r={4.3} />
            <circle r={1.6} className="vgraph-conduit-dot" />
          </>
        ) : rel.relation === "inferred" ? (
          <path d="m0-4.4 4.4 4.4L0 4.4-4.4 0Z" />
        ) : (
          <rect x={-2.8} y={-2.8} width="5.6" height="5.6" rx=".8" />
        )}
      </g>
    </g>
  );
}
const edgeTypes = { conduit: Conduit };
const reduced = () =>
  typeof window !== "undefined" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function ViewportDriver({
  command,
  layout,
}: {
  command: GraphCommand | null;
  layout: GraphLayout;
}) {
  const { fitView, getZoom, zoomIn, zoomOut, setCenter } = useReactFlow();
  const last = useRef<{ layout?: GraphLayout; command?: GraphCommand | null }>(
    {},
  );
  useEffect(() => {
    const changed = last.current.layout !== layout;
    const next = last.current.command !== command ? command : null;
    if (!changed && !next) return;
    let current = true;
    const frame = requestAnimationFrame(() => {
      last.current = { layout, command };
      const duration = reduced() ? 0 : 180;
      if (next?.kind === "focus") {
        const n = layout.nodes.find((n) => n.id === next.nodeId);
        if (n)
          void setCenter(n.x + CARD_WIDTH / 2, n.y + CARD_HEIGHT / 2, {
            zoom: 1,
            duration,
          });
      } else if (next?.kind === "in") void zoomIn({ duration });
      else if (next?.kind === "out") void zoomOut({ duration });
      else {
        void fitView({
          padding: 0.18,
          maxZoom: 1.1,
          duration: next ? duration : 0,
        }).then(() => {
          // Preserve legibility for narrow screens and very large traces.
          // The explicit fit action still displays the complete graph.
          const root = layout.nodes[0];
          if (current && !next && root && getZoom() < 0.64)
            void setCenter(
              root.x + CARD_WIDTH * 0.86,
              root.y + CARD_HEIGHT * 0.82,
              { zoom: 0.77, duration: 0 },
            );
        });
      }
    });
    return () => {
      current = false;
      cancelAnimationFrame(frame);
    };
  }, [layout, command, setCenter, fitView, getZoom, zoomIn, zoomOut]);
  return null;
}

function downloadGraph(graph: GraphExport) {
  const content = JSON.stringify(
    { schema: "vanian.graph.v1", ...graph },
    null,
    2,
  );
  const url = URL.createObjectURL(
    new Blob([content], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "vanian-topology.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Topology({
  nodes,
  edges,
  title = "Execution topology",
  mode = "light",
  initialView = "2d",
  onSelect,
  onExport,
  className = "",
}: Props) {
  const [view, setView] = useState<View>(initialView);
  const [relationship, setRelationship] = useState<Relation | "all">("all");
  const [term, setTerm] = useState("");
  const [selected, setSelected] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [command, setCommand] = useState<GraphCommand | null>(null);
  const id = useId();
  const searchRef = useRef<HTMLInputElement>(null);
  const panel = useRef<HTMLElement>(null);
  const [columns, setColumns] = useState(4);
  useEffect(() => {
    const el = panel.current;
    if (!el) return;
    const resize = () =>
      setColumns(el.clientWidth < 525 ? 2 : el.clientWidth < 850 ? 3 : 4);
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  const layout = useMemo(
    () => instrumentLayout(prepareGraph(nodes, edges, collapsed), columns),
    [nodes, edges, collapsed, columns],
  );
  const graph = useMemo(
    () => ({
      ...layout,
      edges:
        relationship === "all"
          ? layout.edges
          : layout.edges.filter((edge) => edge.relation === relationship),
    }),
    [layout, relationship],
  );
  const positions = useMemo(
    () => new Map(graph.nodes.map((n) => [n.id, n])),
    [graph],
  );
  const adjacent = useMemo(
    () =>
      new Set(
        graph.edges
          .filter((e) => e.source === selected || e.target === selected)
          .flatMap((e) => [e.source, e.target]),
      ),
    [graph, selected],
  );
  const record = graph.nodes.find((n) => n.id === selected);
  const lookup = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const rels = record
    ? graph.edges.filter(
        (e) => e.source === record.id || e.target === record.id,
      )
    : [];
  const hits = useMemo(() => {
    const q = term.toLowerCase().trim();
    return q
      ? nodes.filter((n) =>
          (n.label + " " + n.id + " " + n.kind + " " + (n.owner ?? ""))
            .toLowerCase()
            .includes(q),
        )
      : [];
  }, [nodes, term]);
  const flowNodes = useMemo<DisplayNode[]>(
    () =>
      graph.nodes.map((n) => ({
        id: n.id,
        type: "record",
        position: { x: n.x, y: n.y },
        width: CARD_WIDTH,
        height: CARD_HEIGHT,
        data: {
          record: n,
          active: n.id === selected,
          collapsed: collapsed.has(n.id),
          connected: adjacent.has(n.id),
          commandMode: mode === "command",
        },
        ariaLabel: (kindNames[n.kind] ?? "Identity") + ", " + n.label,
        draggable: false,
        connectable: false,
        focusable: true,
      })),
    [graph, selected, collapsed, adjacent, mode],
  );
  const flowEdges = useMemo<DisplayEdge[]>(
    () =>
      graph.edges.map((e, i) => {
        const color =
          mode === "command"
            ? { observed: "#bba1ff", declared: "#a99cbc", inferred: "#cf9de6" }[
                e.relation
              ]
            : { observed: "#7b52d5", declared: "#797583", inferred: "#ab74c0" }[
                e.relation
              ];
        const [out, into] = portSides(
          positions.get(e.source)!,
          positions.get(e.target)!,
        );
        return {
          id: "relationship-" + i,
          source: e.source,
          target: e.target,
          type: "conduit",
          sourceHandle: out + "-out",
          targetHandle: into + "-in",
          data: {
            relationship: e,
            emphasis:
              !!selected && (e.source === selected || e.target === selected),
          },
          animated: false,
          selectable: false,
          focusable: true,
          ariaLabel:
            (e.label ?? "Relationship") +
            ", " +
            relationNames[e.relation] +
            " from " +
            (lookup.get(e.source)?.label ?? e.source) +
            " to " +
            (lookup.get(e.target)?.label ?? e.target),
          style: {
            stroke: color,
            strokeWidth: e.relation === "observed" ? 1.9 : 1.65,
            strokeDasharray:
              e.relation === "declared"
                ? "2 5"
                : e.relation === "inferred"
                  ? "7 4"
                  : undefined,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color,
            width: 11,
            height: 11,
          },
        };
      }),
    [graph, lookup, mode, positions, selected],
  );
  function move(kind: GraphCommand["kind"], nodeId?: string) {
    setCommand((c) => ({ kind, nodeId, epoch: (c?.epoch ?? 0) + 1 }));
  }
  function select(n: TopologyNode, inspect = true) {
    setSelected(n.id);
    if (inspect) onSelect?.(n);
  }
  function go(n: TopologyNode) {
    setCollapsed(new Set());
    setTerm("");
    select(n, false);
    move("focus", n.id);
    searchRef.current?.focus();
  }
  function toggle(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  const tools = (
    <div
      className="vgraph-canvas-tools"
      role="group"
      aria-label="Graph viewport"
    >
      <button
        type="button"
        title="Zoom in"
        aria-label="Zoom in"
        onClick={() => move("in")}
      >
        <Plus size={15} />
      </button>
      <button
        type="button"
        title="Zoom out"
        aria-label="Zoom out"
        onClick={() => move("out")}
      >
        <Minus size={15} />
      </button>
      <button
        type="button"
        title="Fit graph"
        aria-label="Fit graph"
        onClick={() => move("fit")}
      >
        <Maximize size={14} />
      </button>
    </div>
  );
  const visibleHits = hits.slice(0, 8);
  return (
    <section
      ref={panel}
      className={
        "vgraph " + (mode === "command" ? "vgraph--command " : "") + className
      }
      aria-labelledby={id + "-title"}
    >
      <div className="vgraph-bar">
        <h3 id={id + "-title"}>
          <GitBranch size={18} aria-hidden />
          {title}
        </h3>
        <div
          className="vgraph-switch"
          aria-label="Graph presentation"
          role="group"
        >
          {(["2d", "3d", "records"] as View[]).map((v) => (
            <button
              key={v}
              type="button"
              aria-pressed={view === v}
              onClick={() => setView(v)}
            >
              {v === "2d" ? (
                <Workflow size={14} />
              ) : v === "3d" ? (
                <Box size={14} />
              ) : (
                <List size={14} />
              )}
              <span>{v === "records" ? "Records" : v.toUpperCase()}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="vgraph-toolbar">
        <div className="vgraph-search">
          <Search size={15} aria-hidden />
          <input
            ref={searchRef}
            type="search"
            aria-label="Find a graph record"
            autoComplete="off"
            placeholder="Find node…"
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setTerm("");
              if (e.key === "Enter" && hits[0]) {
                e.preventDefault();
                go(hits[0]);
              }
              if (e.key === "ArrowDown" && hits.length) {
                e.preventDefault();
                document.getElementById(id + "-option-0")?.focus();
              }
            }}
          />
          {!!term && (
            <div className="vgraph-hits" aria-label="Matching records">
              {visibleHits.length ? (
                visibleHits.map((n, i) => (
                  <button
                    type="button"
                    id={id + "-option-" + i}
                    key={n.id}
                    onClick={() => go(n)}
                    onKeyDown={(e) => {
                      if (e.key === "Escape") {
                        setTerm("");
                        searchRef.current?.focus();
                      }
                      if (e.key === "ArrowDown")
                        document
                          .getElementById(
                            id +
                              "-option-" +
                              Math.min(visibleHits.length - 1, i + 1),
                          )
                          ?.focus();
                      if (e.key === "ArrowUp")
                        (i
                          ? document.getElementById(id + "-option-" + (i - 1))
                          : searchRef.current
                        )?.focus();
                    }}
                  >
                    <span>{n.label}</span>
                    <small>{n.id}</small>
                  </button>
                ))
              ) : (
                <div role="status">No matching records</div>
              )}
            </div>
          )}
        </div>
        <span className="vgraph-total" role="status">
          {graph.nodes.length} nodes <span>·</span>{" "}
          {relationship === "all"
            ? graph.edges.length
            : graph.edges.length + " of " + layout.edges.length}{" "}
          links
        </span>
        <button
          className="vgraph-export"
          type="button"
          onClick={() => {
            const visible = {
              nodes: graph.nodes.map((node) => lookup.get(node.id)!),
              edges: graph.edges,
              relationshipFilter: relationship,
            };
            (onExport ?? downloadGraph)(visible);
          }}
          title="Export visible graph and evidence references"
        >
          <Download size={14} />
          <span>Export</span>
        </button>
      </div>
      {!graph.nodes.length ? (
        <div className="vgraph-empty">
          <Workflow size={28} />
          <strong>No graph records in this selection</strong>
        </div>
      ) : view === "records" ? (
        <div
          className="vgraph-records"
          tabIndex={0}
          role="region"
          aria-label="Graph records list"
        >
          <table>
            <thead>
              <tr>
                <th>Record</th>
                <th>Type</th>
                <th>Status</th>
                <th>Links</th>
              </tr>
            </thead>
            <tbody>
              {graph.nodes.map((n) => (
                <tr key={n.id}>
                  <td>
                    <button type="button" onClick={() => select(n)}>
                      {n.label}
                    </button>
                    <small>{n.id}</small>
                  </td>
                  <td>{kindNames[n.kind] ?? "Identity"}</td>
                  <td>{n.status ?? "Unspecified"}</td>
                  <td>
                    {
                      graph.edges.filter(
                        (e) => e.source === n.id || e.target === n.id,
                      ).length
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          className="vgraph-canvas"
          aria-label={title + ", " + view.toUpperCase() + " diagram"}
        >
          {view === "2d" ? (
            <ReactFlow<DisplayNode, DisplayEdge>
              nodes={flowNodes}
              edges={flowEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              fitView
              fitViewOptions={{ padding: 0.18, maxZoom: 1.1 }}
              minZoom={0.06}
              maxZoom={2.2}
              nodesDraggable={false}
              nodesConnectable={false}
              deleteKeyCode={null}
              zoomOnDoubleClick={false}
              onNodeClick={(_, n) => select(n.data.record)}
              onNodeDoubleClick={(_, n) => toggle(n.id)}
              className={mode === "command" ? "dark" : "light"}
              onPaneClick={() => setTerm("")}
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={20}
                size={0.72}
                color={mode === "command" ? "#493950" : "#d7d4dc"}
              />
              <ViewportDriver command={command} layout={layout} />
            </ReactFlow>
          ) : (
            <Suspense
              fallback={
                <div className="vgraph-empty" role="status">
                  Loading 3D view…
                </div>
              }
            >
              <Spatial
                layout={layout}
                relationship={relationship}
                selected={selected}
                mode={mode}
                onSelect={(n) => select(n)}
                command={command}
                onFallback={() => setView("2d")}
              />
            </Suspense>
          )}
          {tools}
        </div>
      )}
      <div className="vgraph-legend">
        <div
          className="vgraph-relations"
          role="group"
          aria-label="Filter relationship evidence"
        >
          {(["all", "observed", "declared", "inferred"] as const).map(
            (type) => {
              const count =
                type === "all"
                  ? layout.edges.length
                  : layout.edges.filter((edge) => edge.relation === type)
                      .length;
              return (
                <button
                  key={type}
                  type="button"
                  aria-label={
                    type === "all"
                      ? "Show all links"
                      : "Show " + type + " links"
                  }
                  aria-pressed={type === relationship}
                  onClick={() => setRelationship(type)}
                >
                  {type !== "all" && (
                    <i
                      aria-hidden="true"
                      className={"vgraph-line vgraph-line--" + type}
                    />
                  )}
                  {type === "all" ? "All links" : relationNames[type]}{" "}
                  <b>{count}</b>
                </button>
              );
            },
          )}
        </div>
        {graph.unresolved > 0 && (
          <span className="vgraph-gap">
            {graph.unresolved} unresolved{" "}
            {graph.unresolved === 1 ? "link" : "links"}
          </span>
        )}
        {!!collapsed.size && (
          <button type="button" onClick={() => setCollapsed(new Set())}>
            Expand all
          </button>
        )}
      </div>
      {record && (
        <div className="vgraph-selection">
          <div className="vgraph-selection-head">
            <span>
              <small>{kindNames[record.kind]}</small>
              <b>{record.label}</b>
            </span>
            {edges.some((e) => e.source === record.id) && (
              <button type="button" onClick={() => toggle(record.id)}>
                {collapsed.has(record.id) ? (
                  <ChevronRight size={14} />
                ) : (
                  <ChevronDown size={14} />
                )}{" "}
                {collapsed.has(record.id) ? "Expand" : "Collapse"} descendants
              </button>
            )}
            {onSelect && (
              <button type="button" onClick={() => onSelect(record)}>
                <Crosshair size={14} />
                Inspect
              </button>
            )}
            <button
              type="button"
              className="vgraph-close"
              title="Clear selection"
              aria-label="Clear selection"
              onClick={() => setSelected("")}
            >
              <X size={15} />
            </button>
          </div>
          <dl className="vgraph-meta">
            {(
              [
                ["Identity", record.id],
                ["State", record.status],
                ["Owner", record.owner],
                ["Authority", record.scope],
                ["Observed", record.at],
                [
                  "Confidence",
                  typeof record.confidence === "number"
                    ? record.confidence + "%"
                    : undefined,
                ],
                ["Evidence", record.evidence],
              ] as const
            )
              .filter(([, v]) => v != null && v !== "")
              .map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
          </dl>
          {rels.length > 0 && (
            <details>
              <summary>
                {rels.length}{" "}
                {rels.length === 1 ? "relationship" : "relationships"}
              </summary>
              <ul>
                {rels.map((r, i) => (
                  <li key={i}>
                    <i className={"vgraph-line vgraph-line--" + r.relation} />
                    <button
                      type="button"
                      className="vgraph-neighbor"
                      aria-label={
                        "Follow connection to " +
                        lookup.get(
                          r.source === record.id ? r.target : r.source,
                        )!.label
                      }
                      onClick={() => {
                        const neighbor =
                          r.source === record.id ? r.target : r.source;
                        setSelected(neighbor);
                        move("focus", neighbor);
                      }}
                    >
                      {lookup.get(r.source)?.label ?? r.source} →{" "}
                      {lookup.get(r.target)?.label ?? r.target}
                    </button>
                    <b>{r.label ?? relationNames[r.relation]}</b>
                    <small>
                      {relationNames[r.relation]}
                      {r.evidence ? " · " + r.evidence : ""}
                    </small>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </section>
  );
}
