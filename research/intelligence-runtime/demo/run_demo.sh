#!/usr/bin/env bash
# SYNTRIASS intelligence runtime v0.1 — offline demonstration (six scenes).
#
#   usage: run_demo.sh OUT_DIR [--propose]
#
# Every scene runs the real binary and real models; nothing is simulated.
# Model calls run inside research/compute-memory/bench/offline.sh, which
# refuses to start if any external route exists. Scene 3 uses the recorded
# model draft (results/propose_qwen1.5b-q8/round_1.json) plus the 7 recorded
# engineer corrections unless --propose is given, in which case the local
# model drafts it again (~4 min on 2 vCPU; it is expected to fail validation
# on its own, as it did in the benchmark).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT=$1; shift || true
BIN="$ROOT/target/release/syntriass"
OFF="$ROOT/research/compute-memory/bench/offline.sh"
CL="$ROOT/research/capability-learning"
H="$ROOT/research/intelligence-runtime/harness"
rm -rf "$OUT"; mkdir -p "$OUT"
say() { printf '\n=== %s ===\n' "$*"; }
SCENE=setup; N=0
ask() { # principal-json text [capability]; raw response saved to $OUT/scenes/<scene>-<n>.json
  local line; N=$((N+1)); mkdir -p "$OUT/scenes"
  if [[ $# -ge 3 ]]; then line=$(printf '{"id":"q","principal":%s,"text":%s,"capability":"%s"}' "$1" "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$2")" "$3")
  else line=$(printf '{"id":"q","principal":%s,"text":%s}' "$1" "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$2")"); fi
  echo "$line" | "$OFF" "$BIN" serve --eval --config "$CFG" 2>/dev/null | tee "$OUT/scenes/$SCENE-$N.json" | python3 -c '
import json,sys
d=json.loads(sys.stdin.readline()); r=d.get("response") or {}; c=r.get("cost",{})
print(json.dumps({"strategy": r.get("strategy"), "outcome": r.get("outcome"),
  "wall_ms": round(c.get("wall_ms",0),1), "model_calls": c.get("model_calls"),
  "cpu_s": c.get("cpu_s"), "rss_mib": c.get("rss_mib"), "error": d.get("error")}, ensure_ascii=False, indent=1))'
}
KORAVI='{"tenant":"koravi-process","clearance":"restricted"}'
ALPHA='{"tenant":"plant-alpha","clearance":"internal"}'
TARVEL='{"tenant":"tarvel-grid","clearance":"restricted"}'
KORAVI_LOW='{"tenant":"koravi-process","clearance":"internal"}'

say "Scene 6 — offline operation (checked first; every later model call runs the same way)"
mkdir -p "$OUT/scenes"
"$OFF" python3 -I -c 'import socket
for h in ("1.1.1.1","8.8.8.8"):
    try: socket.create_connection((h,443),timeout=2); print(h, "REACHABLE")
    except OSError as e: print(h, "unreachable:", e.__class__.__name__)' | tee "$OUT/scenes/scene6.txt"

say "Setup — fresh installation, keys, ingest (19 documents, 3 organisations)"
mkdir -p "$OUT/keys"
"$BIN" keygen --id expert:koravi-elec-lead --out "$OUT/keys/expert.json" >/dev/null
"$BIN" keygen --id user:koravi-elec-authority --out "$OUT/keys/approver.json" >/dev/null
python3 -c "import json;k=json.load(open('$OUT/keys/expert.json'));json.dump({k['id']:k['public_hex']},open('$OUT/keys/experts.json','w'))"
python3 -c "import json;k=json.load(open('$OUT/keys/approver.json'));json.dump({k['id']:k['public_hex']},open('$OUT/keys/approvers.json','w'))"
SYNTRIASS_BIN="$BIN" python3 "$H/mkconfig.py" "$OUT/state" balanced --approvers "$OUT/keys/approvers.json" --experts "$OUT/keys/experts.json"
CFG="$OUT/state/config.json"

SCENE=scene1; say "Scene 1 — private intelligence: an authorised engineer asks about a confidential procedure"
ask "$KORAVI" "What is the minimum insulation resistance for a 6.6 kV motor under EP-114?"

SCENE=scene2; say "Scene 2 — efficient computation: a structured report decided by exact rules, no model"
ask "$ALPHA" "Cooling water pump P-7, drive end, 7.9 mm/s overall vibration."

say "Scene 3 — learning: draft -> corrections -> signed expert suite -> validation -> approval -> active"
if [[ "${1:-}" == "--propose" ]]; then
  "$OFF" python3 -I "$CL/harness/propose.py" "$OUT/propose" --model /home/claude/vanian-build/models/qwen2.5-1.5b-instruct-q8_0.gguf \
    --model-sha d7efb072e7724d25048a4fda0a3e10b04bdef5d06b1403a1c93bd9f1240a63c8 \
    --server /home/claude/vanian-build/build-llama-native/bin/llama-server --bin "$BIN" | tail -1
  DRAFT="$OUT/propose/round_1.json"
else
  DRAFT="$CL/results/propose_qwen1.5b-q8/round_1.json"; echo "using recorded model draft: $DRAFT"
fi
echo "-- model draft on the demonstrations:"; "$BIN" cap-check --file "$DRAFT" --cases "$CL/results/propose_qwen1.5b-q8/demos.cases.jsonl" | tee "$OUT/scenes/scene3-draft-check.jsonl" | head -2
python3 -I "$CL/harness/correct.py" "$DRAFT" "$OUT/capability.json" "$OUT/corrections.json"
python3 -c "
import json
for r in map(json.loads, open('$CL/data/ir-tasks-v1/validation.jsonl')):
    r['counterexample'] = r['label'] in ('OUT_OF_SCOPE','INVALID_TEST','INSUFFICIENT_INPUT'); print(json.dumps(r))" > "$OUT/suite_cases.jsonl"
"$BIN" suite-sign --key "$OUT/keys/expert.json" --cases "$OUT/suite_cases.jsonl" --suite-id ir-tasks-v1/validation \
  --tenant koravi-process --task "motor IR acceptance (EP-114 rev C)" --out "$OUT/suite.json"
HASH=$("$BIN" cap-propose --config "$CFG" --file "$OUT/capability.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["hash"])')
"$BIN" cap-validate --config "$CFG" --hash "$HASH" --suite "$OUT/suite.json" | tee "$OUT/scenes/scene3-validation.json" | python3 -c '
import json,sys; r=json.load(sys.stdin); print({k:r[k] for k in ("passed","expert_cases","expert_passed","counterexamples","suite_signature_ok","suite_independent","evidence_scope_ok")})'
"$BIN" cap-approve --config "$CFG" --hash "$HASH" --key "$OUT/keys/approver.json"
"$BIN" cap-transition --config "$CFG" --hash "$HASH" --to ACTIVE --role operator --actor operator:koravi-ot --reason "approved for service"
"$BIN" cap-list --config "$CFG" | tee "$OUT/scenes/scene3-records.jsonl"

SCENE=scene4; say "Scene 4 — reuse on a new example (not in the demos or the validation suite), no fine-tuning"
ask "$KORAVI" "Can we put the 6.6 kV ID fan motor back in service? Megger gave 180 MΩ at 35 °C, PI 2.6."
echo "-- for comparison, recorded baseline B2 (1.5B + conventional RAG) on the 32 unseen decision items:"
python3 -c "
import json; e=json.load(open('$CL/results/economics.json'))
print({'B2_per_task_cpu_s': e['baselines']['B2']['per_task_cpu_s'], 'B2_accuracy': e['baselines']['B2']['accuracy'],
       'capability_accuracy': e['capability']['accuracy'], 'capability_per_task_cpu_s_upper_bound': e['capability']['per_task_cpu_s_upper_bound'],
       'break_even_uses_vs_B2': e['break_even_uses']['B2']})"

SCENE=scene5; say "Scene 5 — security: unauthorised principals and a tampered capability"
echo "-- another organisation invokes the capability explicitly:"; ask "$TARVEL" "M-1 6.6 kV IR 180 megohms at 35 C, PI 2.6" koravi.ep114.ir-acceptance.learned
echo "-- same organisation, lower clearance, same request:"; ask "$KORAVI_LOW" "M-1 6.6 kV IR 180 megohms at 35 C, PI 2.6"
echo "-- tamper with the stored capability (weaken REJECT threshold) and retry:"
F=$(ls "$OUT"/state/capabilities/*.json | head -1)
python3 -c "
import json; r=json.load(open('$F')); r['capability']['procedure']['rules'][1]['when']='corrected_resistance < 0'; json.dump(r, open('$F','w'))"
ask "$KORAVI" "Motor M-122 (11 kV) IR 70 megohms at 30 C, PI 1.8."
"$BIN" cap-list --config "$CFG"

"$BIN" cap-list --config "$CFG" > "$OUT/scenes/scene5-records-after-tamper.jsonl"

say "Audit chain"
"$BIN" audit-verify --config "$CFG" | tee "$OUT/scenes/audit.json"
python3 "$ROOT/research/intelligence-runtime/demo/render_demo.py" "$OUT" && echo "page: $OUT/demo.html"
