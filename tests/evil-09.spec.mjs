// Red-team verification: evil-09-manifest-rollback — the fetch half of the
// unverified-bytes gap (GAP-08). The mock relay (tests/_mockrelay.mjs)
// serves REAL BIP340-signed kind 35130 manifests; the harness's faithful
// fetchManifest miniature selects newest-created_at-wins among the author's
// answers. A relay withholding the newest manifest makes the launcher
// install the older one: rollback, with no forgery anywhere.
//
// The honest counterpoint is machine-checked too: the hostile clone (the
// NEWEST manifest of all, by a different key) is dropped by the reference's
// author binding — id takeover held, rollback armed. Both verdicts in one
// rung.
//
// Run: node tests/evil-09.spec.mjs
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  chromium, BASE, makeChecks, loadHarness, statuses, evidence, collectExfil, waitSettled,
} from './_helper.mjs';
import { schnorrVerify, eventId } from '../tools/bip340.mjs';

const check = makeChecks();
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const FX = join(root, 'napps', 'evil-09-manifest-rollback', 'fixtures');
const ID = 'evil-09-manifest-rollback';

// ─── A. the fixtures are real: signed, id-verified kind 35130 events ────────
{
  const read = f => JSON.parse(readFileSync(join(FX, f), 'utf8'));
  const v1 = read('manifest-v1.json');
  const v2 = read('manifest-v2.json');
  const attacker = read('manifest-attacker.json');
  const author = readFileSync(join(FX, 'author-pubkey.txt'), 'utf8').trim();
  for (const [name, ev] of [['v1', v1], ['v2', v2], ['attacker', attacker]]) {
    check('fixture ' + name + ': id is sha256 of the serialized event', eventId(ev) === ev.id, ev.id.slice(0, 16));
    check('fixture ' + name + ': BIP340 signature verifies', schnorrVerify(Buffer.from(ev.id, 'hex'), ev.pubkey, ev.sig), ev.sig.slice(0, 16));
  }
  check('fixture: v1 and v2 are both by the author, v1 older', v1.pubkey === author && v2.pubkey === author && v1.created_at < v2.created_at,
    v1.created_at + ' < ' + v2.created_at);
  check('fixture: the hostile clone is the NEWEST of all, by a different key',
    attacker.created_at > v2.created_at && attacker.pubkey !== author,
    attacker.created_at + ' by ' + attacker.pubkey.slice(0, 8));
}

// ─── the mock relay ────────────────────────────────────────────────────────
const relay = spawn('node', [join(root, 'tests', '_mockrelay.mjs'), '9101'], { cwd: root, stdio: 'ignore' });
process.on('exit', () => relay.kill());
let relayUp = false;
for (let i = 0; i < 50 && !relayUp; i++) {
  try { relayUp = await fetch('http://localhost:9101/health').then(r => r.ok); } catch (_) {}
  if (!relayUp) await new Promise(r => setTimeout(r, 100));
}
check('mock relay is up', relayUp, 'ws://localhost:9101');

const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });
const logs = (page) => page.evaluate(() => window.__evilLogLines || []);

// ─── B. local source baseline: nothing armed, nothing to see ────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { napp: ID });
  const st = await statuses(f);
  check('local: rollback row held (the newest bytes, unverified as always)',
    st['rollback-bytes'] === 'blocked', st['rollback-bytes']);
  check('local: no-pin row is an honest na', st['no-pin'] === 'na', st['no-pin']);
  check('local: no relay was asked', !(await logs(page)).some(l => l.includes('[relay] asking')),
    'relay asked under local source');
  await page.close();
}

// ─── C. relay source, well-behaved relays: newest wins, author binding holds
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { napp: ID, source: 'relay' });
  const st = await statuses(f);
  check('relay: rollback row held — the newest manifest won', st['rollback-bytes'] === 'blocked', st['rollback-bytes']);
  const lg = await logs(page);
  check('relay: both relays answered', lg.some(l => l.includes('relay-a answered:')) && lg.some(l => l.includes('relay-b answered:')), '');
  check('relay: relay-a (hostile) served v2 AND the foreign clone', lg.some(l => /relay-a answered: v1, v2, attacker-v3/.test(l)),
    lg.filter(l => l.includes('relay-a answered')).join('|'));
  check('relay: author binding dropped the foreign clone', lg.some(l => l.includes('author binding DROPPED 1 foreign manifest(s): attacker-v3')), '');
  check('relay: honest note — the clone was the newest answer of all', lg.some(l => l.includes('the foreign clone was the NEWEST answer of all')), '');
  check('relay: newest-created_at-wins selected v2', lg.some(l => l.includes('selected v2 (created_at')), '');
  check('relay: files fetched by sha and hash-verified', lg.some(l => l.includes('fetched by sha') && l.includes('hash VERIFIED')), '');
  check('relay: no rollback line (nothing withheld)', !lg.some(l => l.includes('⚠ ROLLBACK')), '');
  await page.close();
}

// ─── D. the rollback: relay-a withholds the newest manifest ─────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { napp: ID, source: 'relay', withhold: true, settleMs: 15000 });
  const st = await statuses(f);
  check('rollback: the frame IS the older manifest\'s bytes', st['rollback-bytes'] === 'armed', st['rollback-bytes']);
  const ev = await evidence(f, 'rollback-bytes');
  check('rollback: evidence says ROLLBACK PROVEN', /ROLLBACK PROVEN/.test(ev), ev);
  check('rollback: evidence names the withheld newest (v2)', /withheld v2/.test(ev), ev);
  const lg = await logs(page);
  check('rollback: relay-a answered WITHOUT v2', lg.some(l => /relay-a answered: v1, attacker-v3/.test(l)),
    lg.filter(l => l.includes('relay-a answered')).join('|'));
  check('rollback: the launcher selected the older v1', lg.some(l => l.includes('selected v1 (created_at')), '');
  check('rollback: the harness oracle flags the withheld newest', lg.some(l => l.includes('⚠ ROLLBACK: the newest signed manifest')), '');
  check('rollback: v2\'s bytes still hash-verified on fetch — validity is not the issue',
    lg.some(l => l.includes('hash VERIFIED')), '');
  await page.close();
}

// ─── E. VERY EVIL under the rollback: the evidence exfiltrates ──────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napp: ID, source: 'relay', withhold: true, settleMs: 15000 });
  const st = await statuses(f);
  check('very evil: one armed row (rollback)', st['rollback-bytes'] === 'armed', st['rollback-bytes']);
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  check('confirm: the rollback row is listed with its payload', planCount >= 1, String(planCount));
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 30000 });
  check('evil: the rollback evidence exfiltrated (the frame knows it is old)',
    exfil.some(x => (x.body || '').includes('rollback-evidence')),
    exfil.map(x => (x.body || '').slice(0, 90)).join(' || '));
  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const rb = report.findings.find(x => x.id === 'rollback-bytes');
  check('evil: the report carries running=v1, rolled_back=true',
    rb?.evil?.running === 'v1' && rb?.evil?.rolled_back === true, JSON.stringify(rb?.evil));
  await page.close();
}

await browser.close();
relay.kill();
check.finish();
