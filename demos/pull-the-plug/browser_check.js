// Drives the real page in Chromium: no page errors, no request leaves the
// page's own origin, both columns render, and the result-file path is shown.
// usage: node browser_check.js URL SCREENSHOT.png   → one JSON line on stdout
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1200, height: 800 } });
  const errors = [], external = [];
  p.on('pageerror', e => errors.push(String(e)));
  p.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  p.on('request', r => { if (!r.url().startsWith(process.argv[2])) external.push(r.url()); });
  await p.goto(process.argv[2]);
  await p.waitForFunction(() => document.getElementById('net').textContent !== 'checking network…');
  await p.fill('#q', 'What is the refund policy?');
  await p.click('#go');
  await p.waitForFunction(() => document.getElementById('foot').textContent.includes('result file'), null, { timeout: 30000 });
  await p.screenshot({ path: process.argv[3], fullPage: true });
  console.log(JSON.stringify({
    net: await p.textContent('#net'), local: await p.textContent('#local .status'),
    cloud: await p.textContent('#cloud .status'), foot: await p.textContent('#foot'), errors, external }));
  await b.close();
})().catch(e => { console.log(JSON.stringify({ fatal: String(e) })); process.exit(1); });
