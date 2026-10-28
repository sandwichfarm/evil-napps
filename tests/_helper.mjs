// Shared harness-driving helpers for evil-napp specs.
// Resolves playwright from a sibling Hyprgate checkout (no repo-local dep),
// and runs the repo's static server itself so each spec is self-contained.
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire('/Users/sandwich/Develop/Hyprgate/');
export const { chromium } = require('playwright');

// Hard watchdog: a wedged Playwright run (e.g. browser.close() on a page that
// navigates in a loop) must never hang a session forever. Unref'd so a
// normally-finished process still exits immediately; check.finish()'s
// process.exit and the exit handler below clean up.
const WATCHDOG_MS = Number(process.env.EVIL_WATCHDOG_MS || 5 * 60_000);
setTimeout(() => {
  console.error('WATCHDOG: process wedged ' + WATCHDOG_MS + 'ms — hard exit');
  process.exit(124);
}, WATCHDOG_MS).unref?.();

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export const PORT = Number(process.env.EVIL_PORT || 8899);
export const BASE = 'http://localhost:' + PORT;

// ── static server (repo root), shared by all specs in this process ─────────
let server = null;
async function ensureServer() {
  if (server) return server;
  server = spawn('python3', ['-m', 'http.server', String(PORT)], { cwd: root, stdio: 'ignore' });
  const t0 = Date.now();
  while (Date.now() - t0 < 15000) {
    try {
      const res = await fetch(BASE + '/harness/');
      if (res.ok) return server;
    } catch (_) {}
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error('static server did not come up on ' + BASE);
}
process.on('exit', () => { if (server) server.kill(); });
export { ensureServer };

export function makeChecks() {
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok });
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (ok || !detail ? '' : ' — ' + detail));
  };
  check.finish = (exit = true) => {
    const failed = results.filter((r) => !r.ok);
    console.log('\n' + (failed.length === 0 ? 'ALL CHECKS PASSED (' + results.length + ')' : failed.length + ' FAILED of ' + results.length));
    if (exit) process.exit(failed.length === 0 ? 0 : 1);
  };
  return check;
}

/** Apply knobs, load the harness, and return the settled evil frame. */
export async function loadHarness(page, opts = {}) {
  await ensureServer();
  await page.goto(BASE + '/harness/');
  if (opts.preset) await page.check('input[name="preset"][value="' + opts.preset + '"]');
  if (opts.scheme) await page.check('input[name="scheme"][value="' + opts.scheme + '"]');
  if (opts.atlauncher === true) await page.check('input[name="atlauncher"]');
  if (opts.victim === true) await page.check('input[name="victim"]');
  if (opts.referrer) await page.selectOption('select[name="referrer"]', opts.referrer);
  if (opts.router) await page.selectOption('select[name="router"]', opts.router);
  if (opts.prompts) await page.selectOption('select[name="prompts"]', opts.prompts);
  const wantId = opts.napp || await page.$eval('#nappSel', (el) => el.value);
  if (opts.napp) await page.selectOption('#nappSel', opts.napp);
  await page.click('#loadBtn');
  const f = await findEvilFrame(page, wantId);
  if (opts.settleMs !== 0) await waitSettled(f, opts.settleMs || 9000);
  return f;
}

export async function findEvilFrame(page, wantId) {
  for (let i = 0; i < 400; i++) {
    for (const f of page.frames()) {
      if (f === page.mainFrame()) continue;
      try {
        const ok = await f.evaluate((id) => window.__EVIL_ID__ === id && !!document.getElementById('rows'), wantId);
        if (ok) return f;
      } catch (_) { /* navigating / destroyed */ }
    }
    await page.waitForTimeout(100);
  }
  throw new Error('evil frame not found for ' + wantId);
}

export async function waitSettled(f, ms) {
  await f.waitForFunction(() => {
    const rows = document.querySelectorAll('.attack');
    return rows.length > 0 && Array.from(rows).every((r) => r.dataset.status && r.dataset.status !== 'pending');
  }, null, { timeout: ms + 8000 });
}

export async function statuses(f) {
  return await f.evaluate(() => {
    const out = {};
    for (const el of document.querySelectorAll('.attack')) out[el.dataset.attack] = el.dataset.status;
    return out;
  });
}
export async function evidence(f, id) {
  return await f.evaluate((attackId) => {
    const el = document.querySelector('.attack[data-attack="' + attackId + '"] .evidence');
    return el ? el.textContent : '';
  }, id);
}
export async function report(f) {
  return await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
}

/** The stern gate: wrong case must not enable; exact phrase must. */
export async function armVeryEvil(f, collector, timeoutMs = 30000) {
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  if (collector) await dlg.locator('#collectorInput').fill(collector);
  const disabledBefore = await dlg.locator('#confirmBtn').isDisabled();
  await dlg.locator('#confirmInput').fill('execute evil');
  const wrongCaseHeld = await dlg.locator('#confirmBtn').isDisabled();
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  const enabled = !(await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmBtn').click();
  return { disabledBefore, wrongCaseHeld, enabled };
}

export function collectExfil(page, out) {
  const wire = (p) => p.on('request', (r) => {
    const u = r.url();
    if (u.includes('/collect')) out.push({ url: u, body: r.postData() || '' });
  });
  wire(page);
  // popups the napp opens are their own pages — their requests fire there
  try {
    page.context().on('page', (p) => {
      wire(p);
      p.on('framenavigated', (fr) => {
        if (fr === p.mainFrame() && fr.url().includes('/collect')) out.push({ url: fr.url(), body: '(popup)' });
      });
    });
  } catch (_) {}
  page.on('framenavigated', (fr) => {
    if (fr !== page.mainFrame()) return;
    if (fr.url().includes('/collect')) out.push({ url: fr.url(), body: '(top navigation)' });
  });
}
