// Screenshot sequence for one recorded mode (W9.1).
//
//   node screenshots.js MODE MODE_DIR
//
// Renders only files the run itself wrote under MODE_DIR/run/run (text in a
// <pre>, HTML as is) and writes MODE_DIR/shots/NN-name.png. Each text shot
// carries a footer naming the file it shows. Nothing is drawn that the run
// did not produce. Offline: the page is a local file and every network
// request is blocked and counted; a blocked request fails the shot.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const [mode, dir] = process.argv.slice(2);
const run = path.join(dir, 'run', 'run');
const shots = path.join(dir, 'shots');
fs.mkdirSync(shots, { recursive: true });

const esc = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const pre = (title, file) => {
  const p = path.join(run, file);
  const body = fs.readFileSync(p, 'utf8');
  return `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#111;color:#e8e8e8;font:15px/1.35 ui-monospace,monospace">
<div style="padding:10px 16px;background:#222;color:#9fd;font-weight:bold">${esc(title)}</div>
<pre style="margin:0;padding:14px 16px;white-space:pre-wrap">${esc(body)}</pre>
<div style="padding:8px 16px;color:#999;border-top:1px solid #333">file: ${esc(file)} — written by this run</div></body>`;
};
const pqTable = () => {
  const rows = fs.readFileSync(path.join(run, 'phases.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const tr = rows.map((r) => `<tr><td>${esc(r.phase)}</td><td>${r.delivered_to_server_app ? 'yes' : 'no'}</td>
<td style="color:${r.marker_on_wire ? '#f88' : '#8f8'}">${r.marker_on_wire ? 'IN CLEAR' : 'not seen'}</td><td>${r.bytes_on_wire}</td></tr>`).join('');
  return `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#111;color:#e8e8e8;font:16px system-ui">
<div style="padding:10px 16px;background:#222;color:#9fd;font-weight:bold">Post-quantum in one switch — proof of concept</div>
<table style="margin:14px 16px;border-collapse:collapse" cellpadding="6"><tr style="color:#aaa"><th align=left>phase</th><th align=left>server app got the data</th><th align=left>data on the wire</th><th align=left>bytes on wire</th></tr>${tr}</table>
<div style="padding:8px 16px;color:#999;border-top:1px solid #333">file: phases.jsonl — written by this run</div></body>`;
};

const PLAN = {
  security: [['01-agent-story', () => pre('Catch the lying agent — what each witness says', 'screen.txt')],
             ['02-control', () => pre('Control: the same agent without the hidden step', 'control-screen.txt')]],
  quantum: [['01-ground-truth', () => pre('Quantum X-ray — ground truth checked without the scanner', 'ground_truth_check.txt')],
            ['02-report', 'report.html'],
            ['03-acceptance', () => pre('Quantum X-ray — acceptance', 'acceptance.txt')]],
  pq: [['01-phases', pqTable],
       ['02-acceptance', () => pre('Post-quantum in one switch — acceptance and overhead', 'acceptance.txt')]],
};

(async () => {
  const plan = PLAN[mode];
  if (!plan) { console.error(`no screenshot plan for ${mode}`); process.exit(2); }
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1100, height: 700 } });
  let external = 0;
  await page.route('**/*', (r) => (r.request().url().startsWith('file:') ? r.continue() : (external++, r.abort())));
  for (const [name, src] of plan) {
    let url;
    if (typeof src === 'string') {
      url = 'file://' + path.join(run, src);
    } else {
      const tmp = path.join(shots, `.${name}.html`);
      fs.writeFileSync(tmp, src());
      url = 'file://' + tmp;
    }
    await page.goto(url);
    await page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true });
  }
  for (const f of fs.readdirSync(shots)) if (f.startsWith('.')) fs.unlinkSync(path.join(shots, f));
  await browser.close();
  if (external) { console.error(`${external} external request(s) blocked — shot set rejected`); process.exit(1); }
})();
