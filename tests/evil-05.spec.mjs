// Red-team verification: evil-05-store-poison against the victim harness.
// Run: node tests/evil-05.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, statuses, evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-05-store-poison';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. ungated removes (the reference): censor + poison + wipe all arm ────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { removegate: false, victim: true, prompts: 'auto', napp: ID });
  const st = await statuses(f);
  check('ungated (reference): censor armed — removed+restored the victim event',
    st['store-censor'] === 'armed', st['store-censor']);
  check('ungated (reference): evidence names the no-gate/no-author-check gap',
    /no gate and no author check/.test(await evidence(f, 'store-censor')), await evidence(f, 'store-censor'));
  check('ungated (reference): poison-add armed', st['poison-add'] === 'armed', st['poison-add']);
  check('ungated (reference): store-wipe armed (remove authority proven on own marker)',
    st['store-wipe'] === 'armed', st['store-wipe']);
  // ROE: the store is intact after the demo (censor restored, markers cleaned)
  const store = await page.evaluate(() => window.__harnessStore());
  check('ROE: victim canary restored, markers cleaned up',
    store.some(e => (e.content || '').includes('victim note')) &&
    !store.some(e => (e.content || '').includes('__evil05')),
    JSON.stringify(store.map(e => (e.content || '').slice(0, 24))));
  await page.close();
}

// ─── B. gated removes (the knob) + prompt policy: the launcher holds ───────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { removegate: true, victim: true, prompts: 'prompt', napp: ID });
  const st = await statuses(f);
  check('gated: censor held (the remove prompt stood in the way)',
    st['store-censor'] === 'blocked', st['store-censor']);
  check('gated: store-wipe held', st['store-wipe'] === 'blocked', st['store-wipe']);
  check('gated: poison-add still armed (add is ungated — the shared read is by design)',
    st['poison-add'] === 'armed', st['poison-add']);
  // clean the marker the gated demo could not remove
  await page.evaluate(() => {
    const s = window.__harnessStore();
    const i = s.findIndex(e => (e.content || '').includes('__evil05'));
    if (i !== -1) s.splice(i, 1);
  });
  await page.close();
}

// ─── C. VERY EVIL: real censorship, poison, and the wipe ────────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { removegate: false, victim: true, prompts: 'auto', napp: ID });
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const lastPlan = await dlg.locator('#planList li').last().innerText();
  check('confirm: destructive wipe listed LAST', /wipe|LAST|store/i.test(lastPlan), lastPlan);
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 30000 });

  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const censor = report.findings.find(x => x.id === 'store-censor');
  const poison = report.findings.find(x => x.id === 'poison-add');
  const wipe = report.findings.find(x => x.id === 'store-wipe');
  check('evil: victim canary censored for real', censor?.evil?.goneForReal === true, JSON.stringify(censor?.evil));
  check('evil: poison trio added to the shared store',
    (poison?.evil?.added || []).length === 3 && (poison?.evil?.added || []).every(a => a.ok),
    JSON.stringify(poison?.evil?.added));
  check('evil: store dump exfiltrated', exfil.some(x => (x.body || '').includes('store-poison-dump')));
  // destructive wipe last: the launcher-wide store is empty
  const store = await page.evaluate(() => window.__harnessStore());
  check('evil: the launcher-wide store is EMPTY (destructive payload ran last)',
    store.length === 0, JSON.stringify(store.map(e => (e.content || '').slice(0, 20))));
  check('evil: wipe report shows before/after', (wipe?.evil?.before || 0) > 0 && wipe?.evil?.after === 0,
    JSON.stringify(wipe?.evil));
  await page.close();
}

await browser.close();
check.finish();
