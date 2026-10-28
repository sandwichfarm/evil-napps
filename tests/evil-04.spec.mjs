// Red-team verification: evil-04-action-squat against the victim harness.
// Run: node tests/evil-04.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, findEvilFrame, waitSettled, statuses,
  evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-04-action-squat';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// the rows' probe windows are open while the launcher dispatches; no settle wait
async function loadSquat(page, opts) {
  const f = await loadHarness(page, { ...opts, napp: ID, settleMs: 0 });
  await f.waitForFunction(() => document.querySelectorAll('.attack').length > 0, null, { timeout: 8000 });
  return f;
}

// ─── A. sole-auto (the reference policy) with the victim open: the picker ───
{
  const page = await browser.newPage();
  const f = await loadSquat(page, { pickpolicy: 'sole-auto', victim: true, prompts: 'auto' });
  await page.click('#dispatchProfile');
  await page.waitForTimeout(1500);
  const picked = await page.evaluate(() => window.__pickerCount || 0);
  check('sole-auto: ambiguous squat makes the launcher ASK (picker opened)', picked >= 1, String(picked));
  await waitSettled(f, 15000);
  const st = await statuses(f);
  check('sole-auto: no dispatch landed on the squatter (the ask stood in the way)',
    st['name-squat'] === 'blocked' || st['name-squat'] === 'na', st['name-squat']);
  await page.close();
}

// ─── B. newest-wins pick policy: the squat silently hijacks ─────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadSquat(page, { pickpolicy: 'newest', victim: true, prompts: 'auto' });
  await page.click('#dispatchProfile');
  await page.waitForTimeout(800);
  await page.click('#dispatchView1');
  await waitSettled(f, 30000);
  const st = await statuses(f);
  check('newest policy: profile squat armed (dispatch arrived at the squatter)',
    st['name-squat'] === 'armed', st['name-squat']);
  check('newest policy: evidence names the received caller payload',
    /ARRIVED AT ME/.test(await evidence(f, 'name-squat')), await evidence(f, 'name-squat'));
  check('newest policy: view wildcard armed',
    st['view-wildcard'] === 'armed', st['view-wildcard']);
  check('newest policy: poisoned result round-trip armed',
    st['result-poison'] === 'armed', st['result-poison']);
  check('ROE: demo made no exfil requests', exfil.length === 0, String(exfil.length));
  await page.close();
}

// ─── C. first-wins pick policy: the victim keeps the namespace ──────────────
{
  const page = await browser.newPage();
  const f = await loadSquat(page, { pickpolicy: 'first', victim: true, prompts: 'auto' });
  await page.click('#dispatchProfile');
  await waitSettled(f, 25000);
  const st = await statuses(f);
  check('first policy: dispatches flow to the victim, not the squatter',
    st['name-squat'] === 'blocked', st['name-squat']);
  await page.close();
}

// ─── D. sole-auto with the victim CLOSED: the reference's auto-pick arms it ──
{
  const page = await browser.newPage();
  const f = await loadSquat(page, { pickpolicy: 'sole-auto', victim: true, prompts: 'auto' });
  // close the victim window: the squatter becomes the sole handler
  await page.locator('#victimWin .nappwin-head button').click();
  await page.waitForTimeout(500);
  await page.click('#dispatchProfile');
  await waitSettled(f, 25000);
  const st = await statuses(f);
  check('victim closed: sole-handler auto-pick routes the launcher\'s profile to the squatter',
    st['name-squat'] === 'armed', st['name-squat']);
  const ev = await evidence(f, 'name-squat');
  check('sole-auto armed evidence names the auto-pick',
    /squatters? the name|squat the name/.test(ev), ev);
  await page.close();
}

// ─── E. VERY EVIL: stolen payloads + poisoned results ────────────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadSquat(page, { pickpolicy: 'newest', victim: true, prompts: 'auto', settleMs: 0 });
  await f.waitForFunction(() => document.querySelectorAll('.attack').length > 0, null, { timeout: 8000 });

  // feed the demo probes first, then let them settle — all rows arm
  await page.click('#dispatchProfile');
  await page.waitForTimeout(700);
  await page.click('#dispatchView1');
  await waitSettled(f, 30000);
  const stPre = await statuses(f);
  check('newest (evil run): all three rows armed before the gate',
    ['name-squat', 'view-wildcard', 'result-poison'].every(id => stPre[id] === 'armed'),
    JSON.stringify(stPre));

  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  check('confirm: all three rows listed', planCount === 3, String(planCount));
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());

  // feed the payloads while the evil rows wait: the launcher dispatches…
  await page.click('#dispatchProfile');
  await page.waitForTimeout(700);
  await page.click('#dispatchView1');

  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 40000 });
  check('evil: squatted profile payload exfiltrated',
    exfil.some(x => (x.body || '').includes('squat-profile-payload')),
    exfil.map(x => (x.body || '').slice(0, 90)).join(' || '));
  check('evil: squatted view payload exfiltrated',
    exfil.some(x => (x.body || '').includes('squat-view-payload')));
  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const poison = report.findings.find(x => x.id === 'result-poison');
  check('evil: poisoned result round-tripped to the victim',
    poison?.evil?.roundTrip === true, JSON.stringify(poison?.evil).slice(0, 160));
  await page.close();
}

await browser.close();
check.finish();
