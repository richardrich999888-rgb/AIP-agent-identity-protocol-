"""Offline replay of public synthetic signed cases; no private key required."""
import json,pathlib,subprocess,tempfile
R=pathlib.Path(__file__).resolve().parent;ROOT=R.parents[1];D=R/'results/record-binding'
cap=json.loads((ROOT/'research/capability-learning/results/corrected/capability.json').read_text());cap['evidence']='signed_record'
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);(p/'cap.json').write_text(json.dumps(cap));(p/'cases.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in json.loads((D/'cases.json').read_text())))
 raw=subprocess.check_output([str(ROOT/'target/release/syntriass'),'cap-check','--file',str(p/'cap.json'),'--cases',str(p/'cases.jsonl'),'--instruments',str(D/'instruments.json')],text=True)
 got=[json.loads(s) for s in raw.splitlines()];expected=json.loads((D/'raw.json').read_text())
 assert {x['id']:x['got'] for x in got}=={x['id']:x['got'] for x in expected}
 print(f'{len(got)} actual Rust capability outputs reproduced; no tool actions or independent observer claimed')
