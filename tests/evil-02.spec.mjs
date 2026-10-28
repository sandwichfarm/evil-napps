// Red-team verification: evil-02-launcher-xss against the victim harness.
// Self-contained: starts its own static server (node, for CSP headers) + Chromium.
// Run: node tests/evil-02.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, statuses, evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-02-launcher-xss';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. safe render (the reference behavior): every payload inert ──────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { render: 'safe', lcsp: 'none', napp: ID });
  const st = await statuses(f);
  check('safe render: all payload rows held',
    ['card-html', 'icon-attr', 'silent-sign'].every(id => st[id] === 'blocked'),
    JSON.stringify(st));
  // the card shows the payload as inert text — visible to the operator
  const card = await page.evaluate(() => document.getElementById('launcherCard').innerText);
  check('safe render: payload visible as inert text on the card',
    card.includes('onerror') && card.includes('icon:'), card.slice(0, 140));
  await page.close();
}

// ─── B. unsafe render (innerHTML), no launcher CSP → armed, demo stays inert ─
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { render: 'unsafe', lcsp: 'none', napp: ID });
  const st = await statuses(f);
  check('unsafe render: description injection armed', st['card-html'] === 'armed', st['card-html']);
  check('unsafe render: icon attribute injection armed', st['icon-attr'] === 'armed', st['icon-attr']);
  check('unsafe render: silent-sign armed (implant parked)', st['silent-sign'] === 'armed', st['silent-sign']);
  const ev = await evidence(f, 'card-html');
  check('unsafe render: evidence names the launcher origin', /launcher origin/.test(ev), ev);
  check('ROE: demo mode made no exfil requests', exfil.length === 0, String(exfil.length));
  await page.close();
}

// ─── C. unsafe render + strict launcher CSP → held (last line of defense) ──
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { render: 'unsafe', lcsp: 'strict', napp: ID });
  const st = await statuses(f);
  check('strict CSP: payload rows held',
    ['card-html', 'icon-attr', 'silent-sign'].every(id => st[id] === 'blocked'),
    JSON.stringify(st));
  // the launcher itself kept working under its own CSP (external script)
  check('strict CSP: the launcher still runs (externalized script)',
    await page.evaluate(() => (window.__evilLogLines || []).length > 0));
  await page.close();
}

// ─── D. VERY EVIL: implant armed → theft + forged grant + silent signing ────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  // deterministic: clear any remembered decisions from earlier scenarios
  await page.goto(BASE + '/harness/');
  await page.evaluate(() => localStorage.removeItem('__harness_decisions__'));
  const f = await loadHarness(page, { render: 'unsafe', lcsp: 'none', prompts: 'prompt', napp: ID });

  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  check('confirm: dialog lists all three armed rows', planCount === 3, String(planCount));
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  check('confirm: disabled before typing the phrase', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('execute evil');
  check('confirm: wrong case does not enable', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());

  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 30000 });

  check('evil: grant-theft exfiltrated from the launcher origin',
    exfil.some(x => (x.body || '').includes('launcher-xss-grant-theft')),
    exfil.map(x => (x.body || '').slice(0, 100)).join(' || '));
  check('evil: canary nsec in the theft payload',
    exfil.some(x => (x.body || '').includes('nsec1fake_redteam_canary')),
    exfil.map(x => (x.body || '').slice(0, 140)).join(' || '));
  check('evil: forged allow-always decision written to the permission store',
    await page.evaluate((id) => {
      try { return JSON.parse(localStorage.getItem('__harness_decisions__') || '{}')[id + '|signEvent'] === 'allow'; }
      catch (_) { return false; }
    }, ID));
  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const cardRow = report.findings.find(x => x.id === 'card-html');
  check('evil: implant reported back from the launcher origin',
    /done:|forged/.test((cardRow?.evil?.implantReply) || ''), JSON.stringify(cardRow?.evil).slice(0, 220));
  const silentRow = report.findings.find(x => x.id === 'silent-sign');
  check('evil: marker note signed with NO prompt (forged grant governs)',
    silentRow?.evil?.promptFree === true, JSON.stringify(silentRow?.evil).slice(0, 220));
  check('evil: no permission dialog ever opened',
    await page.evaluate(() => (window.__promptCount || 0) === 0),
    String(await page.evaluate(() => window.__promptCount)));
  await page.close();
}

await browser.close();
check.finish();
