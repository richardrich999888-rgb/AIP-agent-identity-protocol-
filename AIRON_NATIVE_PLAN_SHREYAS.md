# AIRON Native YC Demo - Implementation Plan (Shreyas)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A branded, offline AIRON Native web app with four working screens (Intelligence Workspace, Private Knowledge, Persistent Memory, Agent Accountability) running on real local Ollama, Docling and Qdrant, plus a 2:30 product walkthrough recording and a separate full technical recording.

**Architecture:** A React + TypeScript single-page app talks only to one local Python (FastAPI) backend bound to `127.0.0.1`. The backend calls Ollama (chat + embeddings), Docling (document extraction), Qdrant (vector index), a local SQLite file (approved corrections) and proxies Anuj's AIP adapter for evidence verification. Nothing in the request path leaves the machine.

**Tech Stack:** Vite, React 18, TypeScript, Tailwind CSS, lucide-react | Python 3.12, FastAPI, uvicorn, httpx, qdrant-client, docling, sqlite3 (stdlib), pytest | Ollama (Windows installer), Qdrant (Windows release binary), OBS Studio for recording.

**Spec:** "URGENT - AIRON Native YC Product Demo, SYNTRIASS Labs Engineering Execution Order" (Naga Sri Ganesh). Shreyas's sections: Task 1 (clone/install), Task 2 (four screens), Task 3 (recording); shared deliverables; demo script Scenes 1-6; strict priorities P0/P1/P2.

---

## 0. Situation as checked on 2026-11-02

| Item | Status on this laptop | Consequence |
|---|---|---|
| Hardware | 15.7 GB RAM, Intel Core 5 120U, Intel integrated graphics (no CUDA GPU), 117 GB free | All inference is CPU. Use a 3B chat model; an 8B model will be too slow on camera. |
| Ollama | Not installed | Install Windows build (Task 1). |
| Docker | Not installed | Do **not** install Docker just for Qdrant. Use Qdrant's native Windows binary. |
| Python | 3.12.10 | Backend in Python (Docling is a Python library). |
| Node / npm | 24.17 / 11.13 | Frontend tooling OK. |
| Rust / cargo | 1.98 | Only needed if Anuj's adapter must be built locally. |
| `gh` CLI | Not installed | Push with plain `git`; open PRs in the browser. |
| AIRON Native repo | Not cloned yet | Task 1 clones and audits it first. |
| AIP repo | Present at `Sniffer Dog/AIP-agent-identity-protocol-`; workspace has `banking-demo`, `aip-verify`, `aip-wasm` (exports `verify_evidence_packet`, `get_sample_packet`) | Screen 4 consumes Anuj's adapter; the wasm verifier is a fallback **only if Anuj and Ganesh agree** (see Task 7). |

## Global Constraints

- Brand: "AIRON Native" product name, "SYNTRIASS Labs" maker. Reuse the corporate palette already used in `aip-console/tailwind.config.ts` (primary `#1A2B3C`, secondary `#0B1F2E`, accent `#2E7D32`, steel `#607D8B`, light text tints `accent-light #66BB6A`, `steel-light #90A4AE`, `danger-light #EF5350`, `warning-light #D69E2E`). No emoji, no em-dashes in UI copy, icons from lucide-react only.
- "No fabricated features" and "No unfinished components presented as operational": every status badge, model name, citation and verification result shown in the UI must come from a live call. If a dependency is down, the UI says so; it never falls back to canned data.
- Everything listens on `127.0.0.1` only (backend, Qdrant, Ollama, Anuj's adapter). Never `0.0.0.0`.
- No CDN assets at runtime: fonts, icons and scripts are bundled so the app works with networking disabled.
- Record exact versions of Ollama, Docling, Qdrant and model digests in `VERSIONS.md`.
- Do not modify Ollama, Docling or Qdrant engines; use official packages/binaries.
- Memory is "persistent approved memory", not training. Copy must never say the model "learned".
- Do not claim kernel observation / Sniffer Dog evidence anywhere in UI or narration.
- P2 (P2P distribution, Filecoin-style storage, adaptive compute, distributed inference) is out of scope. Do not start it.
- If the deadline gets critical: record the P0 demo (Screens 1, 2, 4) immediately, before finishing Screen 3.

## Decisions locked by this plan

| Decision | Choice | Why |
|---|---|---|
| Chat model | `llama3.2:3b` (fallback `qwen2.5:3b` if citation-following is poor) | CPU-only laptop; ~2 GB; acceptable token rate on a 120U. |
| Embedding model | `nomic-embed-text` via Ollama (768-dim) | Keeps all model inference in Ollama; one runtime to prove offline. |
| Qdrant | Native Windows binary from GitHub releases, storage in `airon-data/qdrant/` | No Docker on this machine. |
| Docling options | PDF pipeline with `do_ocr=False` (documents are digital PDFs) | Faster on CPU; avoids downloading OCR models. Layout models still need to be pre-downloaded (Task 1). |
| Backend | FastAPI on `127.0.0.1:8000`; in demo mode it also serves the built frontend | One origin, one process to restart for Scene 4. |
| Frontend dev | Vite on `127.0.0.1:5173`, proxy `/api` to `:8000` | Standard. |
| Corrections store | SQLite file `airon-data/memory.db` | Required by spec. |
| Correction retrieval | On approval, embed `question + corrected_text` and store the vector as a BLOB in SQLite; at query time cosine-rank approved rows, threshold `0.75`, top 2 | Proves persistence comes from SQLite, not from Qdrant or process memory. Few rows, so brute force is fine. |
| AIP integration | Backend proxies `/api/evidence/{status,demo,verify}` to Anuj's adapter at `AIP_ADAPTER_URL` (default `http://127.0.0.1:8090`, confirm with Anuj) | Single origin for the browser; the adapter stays local-only. |
| Chunking | Use Docling's `HybridChunker` (max ~400 tokens), keep `doc_name`, `page_no`, `headings` per chunk | Gives citations with document + section + page. |

## Directory layout (inside the AIRON Native repo)

If Task 1's audit finds an existing app structure, map these responsibilities onto it instead of creating parallel folders.

```
AIRON-native-/
  README.md                       install + demo commands (modify)
  VERSIONS.md                     exact versions + model digests (create)
  .env.example                    OLLAMA_URL, QDRANT_URL, AIP_ADAPTER_URL, CHAT_MODEL, EMBED_MODEL, DATA_DIR
  demo-docs/
    generate_docs.py              builds the three synthetic PDFs (reportlab)
    pump-a17-maintenance-manual.pdf
    factory-equipment-registry.pdf
    industrial-safety-procedure.pdf
  backend/
    pyproject.toml
    airon/
      config.py                   settings from env
      main.py                     FastAPI app, router wiring, static serving, started_at/boot_id
      status.py                   live health probes for all dependencies
      ollama_client.py            chat (streaming) + embed
      ingest.py                   Docling convert + chunk
      vector_store.py             Qdrant collection create/upsert/search
      memory_store.py             SQLite corrections CRUD + similarity lookup
      rag.py                      retrieval + prompt assembly + citation parsing
      evidence_proxy.py           proxy to Anuj's AIP adapter with validation
      routes/{chat,documents,memory,evidence,status}.py
    tests/
      test_memory_store.py
      test_rag_prompt.py
      test_citations.py
      test_evidence_proxy.py
      test_status.py
      integration/test_live_stack.py   (marked `live`, needs real services)
  frontend/
    package.json, vite.config.ts, tailwind.config.ts
    src/
      api/client.ts               typed fetch + SSE helpers
      components/AppShell.tsx     sidebar nav + top status bar
      components/StatusBar.tsx
      components/ChatPanel.tsx    shared by Screens 1 and 2
      components/CitationDrawer.tsx
      screens/Workspace.tsx
      screens/Knowledge.tsx
      screens/Memory.tsx
      screens/Accountability.tsx
  scripts/
    start-all.ps1                 start Qdrant, Ollama, backend (localhost only)
    restart-ai.ps1                stop + start backend and Ollama, print new boot id
    offline-check.ps1             prove no external network, then hit every local endpoint
  airon-data/                     gitignored: qdrant storage, memory.db, uploads
```

## API contract (backend, all JSON unless noted)

| Method + path | Request | Response |
|---|---|---|
| `GET /api/status` | - | `{ service: {started_at, boot_id, pid}, ollama: {ok, version, chat_model, chat_model_present, embed_model_present}, qdrant: {ok, version, points}, docling: {version}, memory: {ok, db_path, approved_count}, aip: {ok, detail} }` |
| `POST /api/chat` | `{ question: str, use_knowledge: bool, use_memory: bool }` | `text/event-stream`: `event: token` (data = text), then one `event: done` with `{ answer, citations: Citation[], memory_used: MemoryHit[], model, elapsed_ms }` |
| `POST /api/documents` | multipart `file` (pdf/docx/md, max 20 MB) | `{ doc_id, name, pages, chunks }` |
| `GET /api/documents` | - | `[{ doc_id, name, pages, chunks, indexed_at }]` |
| `GET /api/documents/{doc_id}/chunks/{chunk_id}` | - | `Citation` |
| `POST /api/memory/corrections` | `{ question, original_answer, corrected_text, source }` | `Correction` with `status: "pending"` |
| `POST /api/memory/corrections/{id}/approve` | `{ approved_by }` | `Correction` with `status: "approved"`, `approved_at` |
| `POST /api/memory/corrections/{id}/reject` | `{ approved_by }` | `Correction` with `status: "rejected"` |
| `GET /api/memory/corrections` | - | `Correction[]` |
| `GET /api/evidence/status`, `GET /api/evidence/demo`, `POST /api/evidence/verify` | passthrough to Anuj's adapter | passthrough body + status; on adapter down: `503 { error: "aip_adapter_unavailable" }` |

Types:
- `Citation = { ref: "S1", doc_id, doc_name, page_no, headings: str[], text, score }`
- `MemoryHit = { ref: "M1", correction_id, corrected_text, approved_at, approved_by, similarity }`
- `Correction = { id, question, original_answer, corrected_text, source, status: "pending"|"approved"|"rejected", created_at, approved_at|null, approved_by|null }` (timestamps ISO-8601 UTC)

## Review Focus

1. **Docling silently downloading models while offline.** Docling fetches layout models from Hugging Face on first conversion. If not pre-fetched, Scene 2 upload fails with networking off. Expected: models pre-downloaded in Task 1, `HF_HUB_OFFLINE=1` set by `start-all.ps1`, and upload errors surface as a readable message. Test: Task 3 `test_ingest_offline_env` + Task 9 offline run.
2. **Model ignores or invents citation markers.** A 3B model may write `[S4]` when only 3 sources were given, or cite nothing. Expected: UI only shows citations that map to real retrieved chunks; unknown refs are dropped; if none cited, show the retrieved passages as "Sources consulted" (never claim it cited). Test: Task 4 `test_parse_citations_drops_unknown_refs`.
3. **Dependency down mid-demo** (Ollama not started, Qdrant not running, adapter off). Expected: status bar shows the real failing component; chat returns a clear error, not a hang or fake answer; Screen 4 shows "AIP adapter unavailable", never sample data. Tests: Task 2 `test_status_reports_ollama_down`, Task 7 `test_adapter_down_returns_503`.
4. **Pending or rejected corrections leaking into answers.** Expected: only `approved` rows are ever retrieved. Test: Task 5 `test_lookup_ignores_pending_and_rejected`.
5. **Same document uploaded twice** (common while rehearsing). Expected: re-upload replaces that document's chunks (id = sha256 of file bytes), no duplicate citations. Test: Task 3 `test_reupload_replaces_chunks`.

---

## Task 1: Clone, install, pin versions (Spec: Shreyas Task 1)

**Files:**
- Create: `VERSIONS.md`, `.env.example`, `.gitignore` entries for `airon-data/`, `demo/recordings/`
- Create: `scripts/start-all.ps1`

**Interfaces:**
- Produces: running services at `http://127.0.0.1:11434` (Ollama), `http://127.0.0.1:6333` (Qdrant); env vars `OLLAMA_URL`, `QDRANT_URL`, `AIP_ADAPTER_URL`, `CHAT_MODEL=llama3.2:3b`, `EMBED_MODEL=nomic-embed-text`, `DATA_DIR=airon-data`.

- [ ] **Step 1: Clone and branch**
  `git clone https://github.com/richardrich999888-rgb/AIRON-native-` next to the AIP repo, then `git checkout -b feature/shreyas-airon-demo`.
- [ ] **Step 2: Audit the existing repo** (15 min max). Write 5-10 lines at the top of `README.md` under "Existing state" listing what is there. If it already has a frontend/backend skeleton, adapt the directory layout above to it; do not duplicate.
- [ ] **Step 3: Install Ollama** (Windows installer from ollama.com / GitHub releases). Set user env `OLLAMA_HOST=127.0.0.1:11434`. Run `ollama pull llama3.2:3b` and `ollama pull nomic-embed-text`.
  Verify: `ollama run llama3.2:3b "Say OK"` prints a reply; `ollama list` shows both models.
- [ ] **Step 4: Install Qdrant** (latest Windows zip from github.com/qdrant/qdrant/releases). Create `airon-data/qdrant/config.yaml` with `service.host: 127.0.0.1`, `storage.storage_path: ./airon-data/qdrant/storage`, telemetry disabled (`telemetry_disabled: true`).
  Verify: `curl http://127.0.0.1:6333/` returns JSON with `version`.
- [ ] **Step 5: Python env + Docling**: `py -3.12 -m venv backend/.venv`, install `fastapi uvicorn[standard] httpx qdrant-client docling python-multipart pytest reportlab`. Pre-download Docling models: `docling-tools models download` (check the exact command in the installed version's docs). Then run one conversion of any PDF with `HF_HUB_OFFLINE=1` set to prove models are cached.
- [ ] **Step 6: Record versions** in `VERSIONS.md`: `ollama --version`, `ollama show llama3.2:3b` digest, `ollama show nomic-embed-text` digest, Qdrant `version` from Step 4, `pip show docling qdrant-client fastapi`, Node/npm versions, AIP repo commit SHA used by Anuj's adapter.
- [ ] **Step 7: `scripts/start-all.ps1`**: sets `HF_HUB_OFFLINE=1`, `OLLAMA_HOST=127.0.0.1:11434`, starts Qdrant with the config, ensures `ollama serve` is running, starts uvicorn `airon.main:app --host 127.0.0.1 --port 8000`. Prints each service's health.
- [ ] **Step 8: Install OBS Studio now** (needed offline later). Commit: `chore: pin AIRON Native dependencies and startup script`.

## Task 2: Backend skeleton + live status (Screen 1 status data)

**Files:**
- Create: `backend/airon/config.py`, `main.py`, `status.py`, `ollama_client.py`, `routes/status.py`
- Test: `backend/tests/test_status.py`

**Interfaces:**
- Produces: `Settings` (pydantic-settings) with fields matching `.env.example`; `async def get_status() -> dict` (shape in API contract); `OllamaClient.chat_stream(messages: list[dict], model: str) -> AsyncIterator[str]`; `OllamaClient.embed(texts: list[str]) -> list[list[float]]`; module-level `STARTED_AT: datetime`, `BOOT_ID: str` (uuid4 per process start).

- [ ] **Step 1: Write failing tests** with `httpx.MockTransport`:
  - `test_status_reports_ollama_up`: mock `/api/version` -> `{"version":"0.x"}`, `/api/tags` lists `llama3.2:3b` -> `status["ollama"] == {ok: True, chat_model_present: True, ...}`.
  - `test_status_reports_ollama_down`: transport raises `ConnectError` -> `ok is False` and request still returns 200 within 3 s.
  - `test_status_chat_model_missing`: tags without the model -> `chat_model_present is False`.
  - `test_boot_id_stable_within_process`: two calls return the same `boot_id`.
- [ ] **Step 2: Run** `pytest backend/tests/test_status.py -v` -> FAIL (module missing).
- [ ] **Step 3: Implement** status probes with 2 s timeouts each, run concurrently (`asyncio.gather`). Qdrant probe: `GET /` for version and `GET /collections/airon_docs` for point count. Docling version via `importlib.metadata.version("docling")`. AIP probe calls `GET {AIP_ADAPTER_URL}/api/evidence/status`.
- [ ] **Step 4: Run tests** -> PASS. Manual: `start-all.ps1`, `curl 127.0.0.1:8000/api/status` shows real versions.
- [ ] **Step 5: Commit** `feat(backend): live dependency status endpoint`.

## Task 3: Synthetic documents + Docling ingestion + Qdrant index (Screen 2, P0)

**Files:**
- Create: `demo-docs/generate_docs.py` and the three PDFs; `backend/airon/ingest.py`, `vector_store.py`, `routes/documents.py`
- Test: `backend/tests/test_ingest.py`, `backend/tests/test_vector_store.py`

**Interfaces:**
- Consumes: `OllamaClient.embed`.
- Produces: `convert_and_chunk(path: Path) -> tuple[DocMeta, list[Chunk]]` where `Chunk = {chunk_id, doc_id, doc_name, page_no, headings, text}`; `VectorStore.upsert_document(meta, chunks, vectors)`; `VectorStore.delete_document(doc_id)`; `VectorStore.search(vector, top_k=5) -> list[Citation]` (without `ref`); collection `airon_docs`, cosine, size 768.

- [ ] **Step 1: Write the documents** (`generate_docs.py`, reportlab). Every page footer: "SYNTHETIC DOCUMENT - FOR DEMONSTRATION ONLY - SYNTRIASS Labs". Required content:
  - *Pump A17 Maintenance Manual* (4-5 pages): sections 1 Overview, 2 Specifications, 3 Startup, **4 Shutdown Procedure** with **4.1 Normal Shutdown** as numbered steps (notify control room; reduce flow to 20% via VFD over 2 min; stop motor at panel MCC-3; close discharge valve V-17A; wait 10 minutes for casing to cool below 60 C; close suction valve V-17S; lock-out/tag-out per safety procedure SP-04), 4.2 Emergency Shutdown, 5 Maintenance Schedule.
  - *Factory Equipment Registry*: table with ~12 assets including Pump A17 (location Bay 3, asset tag EQ-0417, panel MCC-3, valves V-17A/V-17S, commissioned 2019).
  - *Industrial Safety Procedure* SP-04 Lock-Out/Tag-Out with numbered steps.
  The correction scenario (Task 5) is **not** written into any document: in the documents the wait is "10 minutes" and there is no V-17B. That makes the memory effect visible.
- [ ] **Step 2: Failing tests**:
  - `test_convert_and_chunk_pump_manual`: on the generated pump PDF, at least one chunk contains "V-17A" and has `"Shutdown" in " ".join(headings)` and `page_no >= 1`.
  - `test_doc_id_is_sha256_of_bytes`.
  - `test_reupload_replaces_chunks` (fake Qdrant via `QdrantClient(":memory:")`): upsert twice -> point count unchanged.
  - `test_ingest_offline_env`: with `HF_HUB_OFFLINE=1` set, conversion succeeds (marked `live`; requires Step 5 of Task 1).
- [ ] **Step 3: Run** -> FAIL.
- [ ] **Step 4: Implement** with Docling `DocumentConverter` (PDF `do_ocr=False`) + `HybridChunker`; point ids = uuid5(doc_id, chunk index); payload holds all `Chunk` fields. Upload route: validate extension in {pdf, docx, md} and size <= 20 MB, save to `airon-data/uploads/`, delete old doc points, embed in batches of 16, upsert.
- [ ] **Step 5: Run tests** -> PASS. Manual: upload the 3 PDFs via `curl -F file=@...`; `GET /api/documents` lists 3 with chunk counts.
- [ ] **Step 6: Commit** `feat: local document extraction and vector index`.

## Task 4: RAG chat with real citations (Screens 1+2, P0)

**Files:**
- Create: `backend/airon/rag.py`, `routes/chat.py`
- Test: `backend/tests/test_rag_prompt.py`, `backend/tests/test_citations.py`

**Interfaces:**
- Consumes: `VectorStore.search`, `OllamaClient.chat_stream`, `MemoryStore.lookup` (Task 5; pass an empty list until Task 5 lands).
- Produces: `build_messages(question: str, passages: list[Citation], memory: list[MemoryHit]) -> list[dict]`; `parse_citations(answer: str, passages: list[Citation]) -> list[Citation]`; SSE route per API contract.

- [ ] **Step 1: Failing tests**:
  - `test_prompt_labels_passages`: passages appear as `[S1]`, `[S2]` with doc name + page; memory hits as `[M1]` in a separate block titled "Approved organizational corrections (take precedence over documents)".
  - `test_prompt_instructs_citation_and_refusal`: system prompt says to cite `[S#]`/`[M#]` and to say "not found in the provided documents" when unsupported.
  - `test_parse_citations_drops_unknown_refs`: answer with `[S1] [S4]` and 3 passages -> returns only S1.
  - `test_parse_citations_dedupes`.
- [ ] **Step 2: Run** -> FAIL.
- [ ] **Step 3: Implement**. Retrieval: embed question, `top_k=5`, drop score < 0.35. Chat options: `temperature: 0.1`, `num_ctx: 4096`. `use_knowledge=false` sends the question with no passages (plain chat). The `done` event carries both cited passages and all retrieved passages (`retrieved`), so the UI can honestly show "Sources consulted" when the model cited none.
- [ ] **Step 4: Run tests** -> PASS. **Live acceptance:** ask "What is the shutdown procedure for Pump A17?" five times. Pass = every answer lists the 4.1 steps and cites the pump manual chunk containing V-17A. If fewer than 4/5 pass, switch `CHAT_MODEL` to `qwen2.5:3b` and retest; record the result in `VERSIONS.md`.
- [ ] **Step 5: Commit** `feat: grounded chat with source citations`.

## Task 5: Persistent approved memory in SQLite (Screen 3, P1)

**Files:**
- Create: `backend/airon/memory_store.py`, `routes/memory.py`, `scripts/restart-ai.ps1`
- Test: `backend/tests/test_memory_store.py`

**Interfaces:**
- Consumes: `OllamaClient.embed`.
- Produces: `MemoryStore(db_path)`, `.create(question, original_answer, corrected_text, source) -> Correction`, `.approve(id, approved_by) -> Correction`, `.reject(id, approved_by) -> Correction`, `.list() -> list[Correction]`, `.lookup(question_vec, threshold=0.75, limit=2) -> list[MemoryHit]`.
- Schema: `corrections(id INTEGER PK, question TEXT NOT NULL, original_answer TEXT NOT NULL, corrected_text TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL, approved_at TEXT, approved_by TEXT, embedding BLOB)`.

- [ ] **Step 1: Failing tests** (temp file DB):
  - `test_create_is_pending_with_timestamp`.
  - `test_approve_sets_status_time_and_approver`.
  - `test_lookup_ignores_pending_and_rejected`.
  - `test_survives_reopen`: approve, close, new `MemoryStore` on same path -> `lookup` returns the row.
  - `test_cannot_approve_rejected` -> raises `ValueError`; route maps it to 409.
  - `test_empty_corrected_text_rejected` -> 422 at route level.
- [ ] **Step 2: Run** -> FAIL.
- [ ] **Step 3: Implement**. Embedding is computed on approve (not on create). Vectors stored as float32 bytes; cosine in Python.
- [ ] **Step 4: Run tests** -> PASS.
- [ ] **Step 5: `restart-ai.ps1`**: stops uvicorn and Ollama processes, starts both again via `start-all.ps1`, prints the new `boot_id` and `started_at` from `/api/status`. This is the on-camera "restart the AI service" proof.
- [ ] **Step 6: Live acceptance** using the scripted correction: question "What is the shutdown procedure for Pump A17?"; correction text "Approved site update (Maintenance Supervisor, 2026-10-15): after the 2026 retrofit, also close isolation valve V-17B after V-17A, and wait 15 minutes (not 10) before closing suction valve V-17S."; source "Maintenance Supervisor review"; approve. Run `restart-ai.ps1`; boot_id changes; ask again; answer mentions V-17B and 15 minutes and shows an `[M1]` memory hit with approval time.
- [ ] **Step 7: Commit** `feat: SQLite-backed approved corrections with retrieval`.

## Task 6: Frontend shell, branding, Screens 1-3

**Files:**
- Create: everything under `frontend/` listed in the layout.
- Test: `frontend/src/api/client.test.ts` (vitest)

**Interfaces:**
- Consumes: the API contract above.
- Produces: routes `/workspace`, `/knowledge`, `/memory`, `/accountability`; `/` redirects to `/workspace` (the "dashboard" in Scenes 1 and 6).

- [ ] **Step 1: Scaffold** with Vite React-TS; Tailwind with the palette from Global Constraints; system font stack (no Google Fonts); lucide-react icons. Sidebar header: "AIRON Native" wordmark with "by SYNTRIASS Labs" under it.
- [ ] **Step 2: Failing client tests**: `test_streamChat_emits_tokens_then_done` (mocked SSE); `test_getStatus_maps_network_error_to_offline_state`.
- [ ] **Step 3: Implement `StatusBar`** (polls `/api/status` every 5 s): chips for Model (`llama3.2:3b`, green only if `chat_model_present`), Ollama, Qdrant (point count), Memory (approved count), AIP adapter, plus "Service started HH:MM:SS" (from `started_at`) so the restart is visible on camera. Red chip text = exact `detail`.
- [ ] **Step 4: Screen 1 Workspace**: `ChatPanel` with message list showing the user's questions, streaming answers, a "Use private knowledge" toggle (default on) and "Use approved memory" toggle (default on). Under each answer: citation chips `[S1] Pump A17 Maintenance Manual p.3`, memory chips `[M1] Approved correction 2026-11-..`. Empty state copy: "Ask a question. Answers are generated on this machine by {model}."
- [ ] **Step 5: `CitationDrawer`**: clicking a chip opens a side drawer with document name, heading path, page, and the exact chunk text (from `/api/documents/{doc_id}/chunks/{chunk_id}`). This is Scene 3's "original document passage".
- [ ] **Step 6: Screen 2 Knowledge**: upload zone (pdf/docx/md), document table (name, pages, chunks, indexed time), per-row progress/error, and the same `ChatPanel` below it.
- [ ] **Step 7: Screen 3 Memory**: on any answer in `ChatPanel`, a "Correct this answer" action opens a form (corrected text, source) -> creates a pending correction. Memory screen lists corrections with status badges, Approve / Reject buttons with a confirm step ("Approve this correction for use in future answers?"), and columns source, created, approved at, approved by. Banner copy: "Approved corrections are stored in a local SQLite database and retrieved at answer time. The model itself is not retrained."
- [ ] **Step 8: Run** `npm test` and `npm run build` -> pass. Manual run-through of Scenes 1-4 against the live backend.
- [ ] **Step 9: Commit** `feat(frontend): AIRON Native workspace, knowledge and memory screens`.

## Task 7: Agent Accountability screen (Screen 4, P0) - depends on Anuj

**Files:**
- Create: `backend/airon/evidence_proxy.py`, `routes/evidence.py`, `frontend/src/screens/Accountability.tsx`
- Test: `backend/tests/test_evidence_proxy.py`

**Interfaces:**
- Consumes: Anuj's adapter `GET /api/evidence/status`, `GET /api/evidence/demo`, `POST /api/evidence/verify`.
- Produces: same three paths on `127.0.0.1:8000`.

- [ ] **Step 1: Agree the contract with Anuj today** (write it into both READMEs). Needed from his responses: agent identity (AIP id, public key), delegated authority (principal, scope, constraints e.g. max amount, expiry), authorized action (verb, resource, amount), the signed evidence packet JSON, verification result (pass/fail, trust floor, per-rule results), and on failure the exact rule id + reason. Also agree **which JSON path holds the payment amount** for the tamper button, and the adapter port.
- [ ] **Step 2: Failing tests** (MockTransport): `test_status_passthrough`; `test_demo_passthrough_preserves_body`; `test_verify_rejects_non_json_and_bodies_over_1mb` (413/422 before forwarding); `test_adapter_down_returns_503` with `{error:"aip_adapter_unavailable"}`.
- [ ] **Step 3: Implement** the proxy (10 s timeout, forwards status codes and bodies unchanged).
- [ ] **Step 4: Screen**: "Load demo record" calls `/demo`; six panels in order: Agent identity, Delegated authority, Authorized action, Signed evidence packet (collapsible JSON with signature fields highlighted), Verification result (from `/verify` on the untouched packet), Tampering detection. Tampering panel: "Modify payment amount" button changes only the agreed field (shows before -> after diff), posts to `/verify`, and displays the adapter's failure reason verbatim plus the rule id. Footer note: "Verification performed by the AIP verifier via the local adapter. Results are not cached." No kernel/Sniffer Dog wording.
- [ ] **Step 5: Run tests** -> PASS; live run with Anuj's adapter: valid -> pass, tampered -> fail with reason.
- [ ] **Step 6: Commit** `feat: agent accountability screen via local AIP adapter`.
- **Contingency (decide with Anuj and Ganesh, do not decide alone):** if the adapter is late, the AIP repo's `aip-wasm` crate already exposes `verify_evidence_packet` and `get_sample_packet` and is used by `aip-console`. It is real AIP verification code, but it is not "Anuj's adapter", so use it only with sign-off and label it honestly on screen.

## Task 8: README, demo commands, rehearsal checklist

**Files:**
- Modify: `README.md`

- [ ] **Step 1:** Sections: What it is (one paragraph, no P2 claims); Requirements; Install (Task 1 steps as commands); Run (`scripts/start-all.ps1`, `npm --prefix frontend run build`, open `http://127.0.0.1:8000`); Demo script (Scenes 1-6 with exact questions and the correction text); Offline check; Versions (link `VERSIONS.md`); Known limitations (CPU-only latency, 3B model quality, synthetic documents).
- [ ] **Step 2:** Follow the README from a fresh terminal on this laptop; fix anything that does not work verbatim.
- [ ] **Step 3: Commit** `docs: installation and demo instructions`.

## Task 9: Offline validation (joint with Anuj's Task 4)

**Files:**
- Create: `scripts/offline-check.ps1`, `backend/tests/integration/test_live_stack.py`, `docs/offline-test-log-2026-11-XX.txt`

- [ ] **Step 1: `test_live_stack.py`** (pytest marker `live`): status all ok; upload 3 docs; Pump A17 question cites the pump manual; create + approve correction; (manual restart between phases is in the script) answer uses `[M1]`; evidence demo verifies; tampered packet fails.
- [ ] **Step 2: `offline-check.ps1`**: prints `Get-NetAdapter` state, shows `Test-NetConnection 1.1.1.1 -Port 443` failing and `Resolve-DnsName ollama.com` failing, then runs `pytest -m live` and `restart-ai.ps1` in the middle. Output tee'd to the log file.
- [ ] **Step 3:** Disable Wi-Fi/Ethernet in Windows settings, run the script, save the log. Expected: network probes fail, all live tests pass.
- [ ] **Step 4: Commit** the scripts and log: `test: offline validation log`.

## Task 10: Recordings (Spec: Shreyas Task 3)

- [ ] **Step 1: Setup**: networking disabled; OBS 1920x1080 30 fps; a fresh browser profile (`--user-data-dir` new folder, no extensions, bookmarks bar hidden); browser zoom 125%; Windows notifications off (Focus assist); app in demo mode at `127.0.0.1:8000`; `airon-data/` reset with `memory.db` deleted and the 3 docs already indexed (Scene 3 opens a citation; uploads can be shown in the full technical recording).
- [ ] **Step 2: Full technical recording first** (unedited, ~10-15 min): `offline-check.ps1` output, start-all, status bar, uploads, Pump A17 Q&A with citation drawer, correction create -> approve -> `restart-ai.ps1` -> same question, accountability valid + tampered. This is the safety copy.
- [ ] **Step 3: Walkthrough recording** following the timed script: S1 0:00-0:15 dashboard; S2 0:15-0:40 show network disabled (Windows network flyout or 3 s of `offline-check.ps1` output) then ask the Pump A17 question; S3 0:40-1:05 open citation; S4 1:05-1:35 show approved correction, run restart (terminal only for the restart line + new boot id), ask again, show `[M1]`; S5 1:35-2:10 accountability valid then tampered; S6 2:10-2:30 back to workspace. Because CPU generation is slow, record each scene separately and cut out waiting time; **never** speed up or replace generated text, and note any cuts in the video description.
- [ ] **Step 4:** Narration recorded per scene with the exact lines from the spec. Export `airon-native-walkthrough.mp4` (target <= 2:30) and `airon-native-technical-full.mp4`. Keep both out of git; share via the team drive and link them in the README.

## Suggested order and checkpoints

| Order | Work | Priority | Checkpoint to share with Ganesh |
|---|---|---|---|
| 1 | Task 1 | P0 | Versions file + "Ollama, Qdrant, Docling running locally" |
| 2 | Tasks 2, 3, 4 | P0 | Screenshot: cited answer to the Pump A17 question |
| 3 | Task 7 Step 1 (contract with Anuj) | P0 | Started in parallel on day 1 |
| 4 | Task 6 Steps 1-6 | P0 | Branded Screens 1-2 working |
| 5 | Task 7 remaining | P0 | Valid + tampered results in UI |
| 6 | **If deadline critical: Task 10 for P0 scenes now** | P0 | P0 recording |
| 7 | Task 5 + Task 6 Step 7 | P1 | Memory survives restart |
| 8 | Tasks 8, 9, 10 | - | README, offline log, both recordings, branch pushed |

## Open questions to raise early

1. Does the AIRON Native repo already contain code or a chosen stack? (Task 1 Step 2 answers this; may reshape the layout.)
2. Anuj's adapter port and the exact JSON field for the payment amount (Task 7 Step 1).
3. Is a Python backend acceptable? The brief says "simple local backend" and Docling is Python, so this plan assumes yes.
4. Where should the recordings be delivered (drive link / format)?
