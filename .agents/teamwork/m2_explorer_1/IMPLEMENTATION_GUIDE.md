# Milestone 2 Worker Implementation Guide
**Syntriass Enterprise Accountability Console — App Shell & Branding**

This guide provides the exact file-by-file blueprint and execution steps for the Worker agent to materialize the Next.js 15 App Shell, Syntriass cyber/crypto branding, navigation header, and application state in `aip-console/`.

---

## 1. Target File Mapping

The Worker must create/copy the following proposed files from `.agents/teamwork/m2_explorer_1/` into `aip-console/`:

| Source in `m2_explorer_1/` | Target Path in `aip-console/` | Purpose |
|---|---|---|
| `proposed_package.json` | `aip-console/package.json` | Next.js 15, React 19, @xyflow/react, Tailwind dependencies |
| `proposed_next.config.ts` | `aip-console/next.config.ts` | Webpack asyncWebAssembly & React strict mode |
| `proposed_tsconfig.json` | `aip-console/tsconfig.json` | TypeScript compiler options & `@/*` path aliases |
| `proposed_tailwind.config.ts` | `aip-console/tailwind.config.ts` | Obsidian cyber/crypto palette & glow shadows |
| `proposed_postcss.config.mjs` | `aip-console/postcss.config.mjs` | PostCSS config for Tailwind CSS & Autoprefixer |
| `proposed_globals.css` | `aip-console/src/app/globals.css` | Root obsidian variables, cyber scrollbars & styling |
| `proposed_utils.ts` | `aip-console/src/lib/utils.ts` | `cn()` clsx + tailwind-merge helper |
| `proposed_types.ts` | `aip-console/src/lib/types.ts` | Normative TypeScript interfaces for AIP & verification |
| `proposed_ConsoleContext.tsx`| `aip-console/src/lib/context/ConsoleContext.tsx` | Centralized state: active tab, packet, report, fixtures |
| `proposed_SyntriassLogo.tsx` | `aip-console/src/components/brand/SyntriassLogo.tsx` | Tripartite cryptographic knot vector SVG logo |
| `proposed_SyntriassWordmark.tsx`| `aip-console/src/components/brand/SyntriassWordmark.tsx` | Enterprise corporate wordmark with AEP1 badge |
| `proposed_TrustFloorBadge.tsx`| `aip-console/src/components/brand/TrustFloorBadge.tsx` | Trust Floor progression ladder badge |
| `proposed_ConsoleHeader.tsx` | `aip-console/src/components/navigation/ConsoleHeader.tsx` | Navigation bar with 5 view tabs & status pills |
| `proposed_layout.tsx` | `aip-console/src/app/layout.tsx` | Root Next.js layout with dark mode & header |
| `proposed_page.tsx` | `aip-console/src/app/page.tsx` | Main console page with quick fixtures & view switcher |

---

## 2. Directory Creation Order

Before writing the files, create the destination directories:
```powershell
New-Item -ItemType Directory -Force -Path "aip-console/src/app"
New-Item -ItemType Directory -Force -Path "aip-console/src/components/brand"
New-Item -ItemType Directory -Force -Path "aip-console/src/components/navigation"
New-Item -ItemType Directory -Force -Path "aip-console/src/lib/context"
```

---

## 3. Package Installation & Build Verification Commands

Execute the following commands from the workspace root or `aip-console/`:

```powershell
cd aip-console
npm install
npm run build
```

---

## 4. Verification Criteria for Worker

1. `npm install` completes with exit code 0.
2. `npm run build` compiles all pages and outputs `.next/` without TypeScript or Tailwind syntax errors.
3. Brand components render cleanly:
   - `SyntriassLogo` renders inline SVG with tripartite delta knot and core keyhole.
   - `SyntriassWordmark` displays "SYNTRIASS" and "ACCOUNTABILITY CONSOLE".
   - `ConsoleHeader` displays 5 tabs (Ingestion, Graph, Tamper, Authority, Vault) and switches active tab state.
4. Quick fixture ribbon allows clicking sample buttons and loads fixture JSON from `/fixtures/`.
