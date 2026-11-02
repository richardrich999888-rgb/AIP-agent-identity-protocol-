import type { AccountabilityFlowNode, AccountabilityFlowEdge } from "./types";

/**
 * Helper to trigger browser file download for a given Blob
 */
export function downloadBlob(blob: Blob, filename: string) {
  if (typeof window === "undefined") return;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * 1. Export Graph as Graphviz DOT string
 * Conforms 100% to F9.5 / P1.4 test specifications
 */
export function exportGraphAsDot(
  graph: { nodes: AccountabilityFlowNode[]; edges: AccountabilityFlowEdge[] },
  filename = "accountability-graph.dot"
) {
  const lines: string[] = ["digraph AccountabilityGraph {", "  rankdir=LR;"];
  for (const node of graph.nodes) {
    const k = (node.data?.kind || node.type || "").toLowerCase();
    const shape =
      k === "principal"
        ? "house"
        : k === "authority_grant"
        ? "note"
        : k === "delegation"
        ? "cds"
        : k === "agent"
        ? "component"
        : k === "decision"
        ? "diamond"
        : k === "action"
        ? "box"
        : "tab";
    const label = (node.data?.label || node.id).replace(/"/g, '\\"');
    lines.push(`  "${node.id}" [label="${label}", shape="${shape}"];`);
  }
  for (const edge of graph.edges) {
    const src = edge.source || (edge as any).from;
    const tgt = edge.target || (edge as any).to;
    const rel = edge.data?.relation || (edge as any).relation || "Issues";
    lines.push(`  "${src}" -> "${tgt}" [label="${rel}"];`);
  }
  lines.push("}");
  const dotStr = lines.join("\n");
  const blob = new Blob([dotStr], { type: "text/vnd.graphviz;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 2. Export Graph as JSON
 */
export function exportGraphAsJson(
  graph: { nodes: AccountabilityFlowNode[]; edges: AccountabilityFlowEdge[] },
  filename = "accountability-graph.json"
) {
  const jsonStr = JSON.stringify(graph, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 3. Export Graph as Vector SVG
 */
export function exportGraphAsSvg(filename = "accountability-graph.svg") {
  if (typeof document === "undefined") return;
  const viewport = document.querySelector(".react-flow__viewport");
  if (!viewport) {
    console.warn("React Flow viewport element not found for SVG export");
    return;
  }
  const svgData = new XMLSerializer().serializeToString(viewport);
  const fullSvg = `<svg xmlns="http://www.w3.org/2000/svg" style="background:#080B11;">${svgData}</svg>`;
  const blob = new Blob([fullSvg], { type: "image/svg+xml;charset=utf-8" });
  downloadBlob(blob, filename);
}

/**
 * 4. Export Graph as PNG Image
 */
export async function exportGraphAsPng(filename = "accountability-graph.png") {
  if (typeof document === "undefined") return;
  const viewport = document.querySelector(".react-flow__viewport");
  if (!viewport) return;

  const svgData = new XMLSerializer().serializeToString(viewport);
  const svgBlob = new Blob(
    [`<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" style="background:#080B11;">${svgData}</svg>`],
    { type: "image/svg+xml;charset=utf-8" }
  );
  const url = URL.createObjectURL(svgBlob);
  const img = new Image();

  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 1600;
    canvas.height = 900;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = "#080B11";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      canvas.toBlob((blob) => {
        if (blob) downloadBlob(blob, filename);
        URL.revokeObjectURL(url);
      }, "image/png");
    }
  };
  img.src = url;
}
