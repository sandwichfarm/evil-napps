// Red-team verification: evil-07-persistence against the victim harness.
// Run: node tests/evil-07.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, findEvilFrame, waitSettled, statuses,
  evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-07-persistence';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. stubbed registration (the reference): the slot is held ──────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { swstub: true, napp: ID });
  const st = await statuses(f);
  check('stubbed (reference): SW slot held', st['sw-slot'] === 'blocked', st['sw-slot']);
  const ev = await evidence(f, 'sw-slot');
  check('stubbed: evidence names the stub policy', /stubs registration/.test(ev), ev);
  check('per-origin storage armed (durable by design)', st['origin-persist'] === 'armed', st['origin-persist']);
  check('Cache API armed (durable by design)', st['caches-persist'] === 'armed', st['caches-persist']);
  await page.close();
}

// ─── B. unstubbed: registration is attempted for real (no bytes hold it) ────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { swstub: false, napp: ID });
  const st = await statuses(f);
  check('unstubbed: registration attempted for real — armed',
    st['sw-slot'] === 'armed', st['sw-slot']);
  const ev = await evidence(f, 'sw-slot');
  check('unstubbed: evidence names the open slot', /ATTEMPTED FOR REAL/.test(ev), ev);
  await page.close();
}

// ─── C. reload survival: the marker outlives the launcher session ──────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { swstub: true, napp: ID });
  const ev1 = await evidence(f, 'origin-persist');
  check('first load: marker written', /marker written/.test(ev1), ev1);
  await page.reload();
  const f2 = await findEvilFrame(page, ID);
  await waitSettled(f2, 20000);
  const ev2 = await evidence(f2, 'origin-persist');
  check('after launcher reload: the marker SURVIVED',
    /SURVIVED a launcher reload/.test(ev2), ev2);
  const st2 = await statuses(f2);
  check('after reload: SW slot still held (stub persists)', st2['sw-slot'] === 'blocked', st2['sw-slot']);
  await page.close();
}

// ─── D. VERY EVIL under the at-launcher mistake: a real persistent SW ───────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { atlauncher: true, napp: ID });
  const st = await statuses(f);
  check('at-launcher: SW slot armed (registration is real here)',
    st['sw-slot'] === 'armed', st['sw-slot']);
  check('at-launcher: no bridge — but the SW slot needs none', true);

  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const lastPlan = await dlg.locator('#planList li').last().innerText();
  check('confirm: destructive SW registration listed LAST', /service-worker|LAST|persistently/i.test(lastPlan), lastPlan);
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 40000 });

  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const sw = report.findings.find(x => x.id === 'sw-slot');
  check('evil: the shipped SW REGISTERED at the launcher origin',
    sw?.evil?.registered === true, JSON.stringify(sw?.evil).slice(0, 180));
  check('evil: its scope is the napp folder',
    /\/napps\/evil-07-persistence\//.test(String(sw?.evil?.scope || '')), String(sw?.evil?.scope));
  check('evil: the evil SW serves its own bytes through the scope',
    /EVIL-07 service worker/.test(String(sw?.evil?.servedByEvilSW || '')), String(sw?.evil?.servedByEvilSW));
  check('evil: persistence inventories exfiltrated',
    exfil.some(x => (x.body || '').includes('origin-persist-inventory')) ||
    exfil.some(x => (x.body || '').includes('caches-persist-inventory')));

  // a registration really exists at the launcher origin (same-origin check)
  const reg = await page.evaluate(async () => {
    const r = await navigator.serviceWorker.getRegistration('/napps/evil-07-persistence/');
    return r ? { scope: r.scope, script: r.active && r.active.scriptURL } : null;
  });
  check('evil: getRegistration confirms the persistent worker', !!reg, JSON.stringify(reg));
  // cleanup: unregister the red-team worker
  await page.evaluate(async () => {
    const r = await navigator.serviceWorker.getRegistration('/napps/evil-07-persistence/');
    if (r) await r.unregister();
  });
  await page.close();
}

await browser.close();
check.finish();
