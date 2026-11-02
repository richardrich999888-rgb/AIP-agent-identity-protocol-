## 2026-11-02T13:22:21Z
You are the Milestone 3 Implementation Worker for the AIP Enterprise Accountability Console.
Working directory: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m3_worker\

Read these authoritative documents and explorer blueprints:
- ORIGINAL_REQUEST.md: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\ORIGINAL_REQUEST.md
- PROJECT.md: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\PROJECT.md
- TEST_READY.md: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\TEST_READY.md
- M3 Explorer 1 Blueprint: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m3_explorer_1\handoff.md
- M3 Explorer 2 Blueprint: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m3_explorer_2\handoff.md
- M3 Explorer 3 Blueprint: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m3_explorer_3\handoff.md

Scope: Implement Milestone 3 (Interactive Accountability Graph DAG Viewer - Requirement R2 / Features F9, F10).
Files you exclusively own:
- All files in `aip-console/src/components/graph/`
- `aip-console/src/app/page.tsx` (graph tab container wiring)
- `aip-console/src/app/graph/page.tsx`
- `aip-console/src/app/globals.css` (importing React Flow styles)

Implementation requirements:
1. Ensure `@xyflow/react/dist/style.css` is imported in `globals.css` or `AccountabilityGraph.tsx`.
2. Implement `src/components/graph/types.ts`: TypeScript models for nodes, edges, layout, and reachability.
3. Implement `src/components/graph/dagLayout.ts`: Zero-dependency deterministic hierarchical layout engine supporting both Left-to-Right (`LR`) and Top-to-Bottom (`TB`) with mathematical cross-axis centering, supporting 0 to 8 delegation hops and 25+ parallel actions with zero overlapping.
4. Implement `src/components/graph/reachability.ts`: Single-Principal BFS reachability algorithm enforcing exactly 1 root Principal and detecting orphan/unreachable nodes.
5. Implement `src/components/graph/transformer.ts`: `transformWasmGraphToFlow` bridging WASM `get_accountability_graph` output and `EvidencePacket` into `@xyflow/react` nodes and edges with 1:1 rule verification status and DOT export support.
6. Implement `src/components/graph/nodes/`:
   - `BaseNodeCard.tsx`: Reusable cyber obsidian shell with handle placement, verified/unverified badges, and top strip.
   - 7 custom nodes: `PrincipalNode`, `AuthorityGrantNode`, `DelegationNode`, `AgentNode`, `DecisionNode`, `ActionNode`, `ReceiptNode`.
   - `index.ts`: `nodeTypes` dictionary for React Flow.
7. Implement `src/components/graph/edges/`:
   - `AccountabilityEdge.tsx`: Verified edges glow cyan (`#00E5FF`) with animated flow pulse; tampered/unverified edges render dashed crimson (`#FF1744`) with animated warning pulse and alert badges.
   - `EdgeMarkerDefs.tsx`: Arrow markers and SVG definitions.
   - `index.ts`: `edgeTypes` dictionary for React Flow.
8. Implement `src/components/graph/InspectionSheet.tsx`:
   - Slide-out sheet / drawer displaying full JSON payload, truncated and copyable Ed25519 signatures, public keys, and canonical hashes.
   - 1:1 rule verification details from `report.checks`.
   - Fallback defaults for missing/optional metadata.
9. Implement `src/components/graph/BreadcrumbTrail.tsx`:
   - Interactive clickable chain of custody breadcrumbs from Principal down to selected node.
10. Implement `src/components/graph/GraphControls.tsx`:
   - Canvas actions: Fit View, Zoom in/out, Reset.
   - Layout orientation switch: `LR` vs `TB`.
   - Node visibility filter toggles with counts.
   - Export tools: PNG, SVG, DOT, JSON.
11. Implement `src/components/graph/AccountabilityGraph.tsx`:
   - React Flow canvas integrating `ConsoleContext` and `EvidenceContext`.
   - Clean state handling: Loading spinner, Error alert, Empty state with fixture quick-loader, and Active interactive DAG.
   - Wire into `src/app/page.tsx` and `src/app/graph/page.tsx`.

Verification commands to run:
- `cd aip-console; npm run lint` (must pass with 0 errors)
- `cd aip-console; npm run build` (must pass with 0 errors, prerendering all static pages)
- `npm run test:e2e` in workspace root (all 52 test files, 260 tests must pass)
