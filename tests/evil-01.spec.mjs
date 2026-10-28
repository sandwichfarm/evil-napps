// Red-team verification: evil-01-frame-escape against the victim harness.
// Self-contained: starts its own static server + real Chromium.
// Run: node tests/evil-01.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, findEvilFrame, waitSettled,
  statuses, evidence, armVeryEvil, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-01-frame-escape';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. reference-shaped launcher: every critical/high escape probe holds ───
// (napp sandbox preset, hashed origins, victim open, strict referrer)
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { preset: 'napp', scheme: 'hashed', victim: true, referrer: 'strict', napp: ID });
  const st = await statuses(f);

  const held = ['launcher-origin', 'origin-collision', 'popup', 'top-nav'];
  check('napp preset: escape probes all held', held.every(id => st[id] === 'blocked'), JSON.stringify(st));

  check('napp preset: referrer origin-only (strict policy held the URL)', st['referrer'] === 'na', st['referrer']);
  check('napp preset: referrer evidence names the origin-only leak',
    /origin-only/.test(await evidence(f, 'referrer')), await evidence(f, 'referrer'));

  check('napp preset: frame census open (spec gap)', st['frame-census'] === 'armed', st['frame-census']);
  const censusEv = await evidence(f, 'frame-census');
  check('napp preset: no NAPP sibling scriptable (only own-origin boot frames)',
    /0 scriptable NAPP sibling/.test(censusEv) && /boot frames are my OWN origin/.test(censusEv), censusEv);

  check('napp preset: per-origin storage armed BY DESIGN (info row)', st['origin-storage'] === 'armed', st['origin-storage']);

  const summary = await f.locator('#summary').innerText();
  check('napp preset: exactly 2 armed (the two info/spec-gap rows) / 1 na', /2 armed/.test(summary) && /1 n\/a/.test(summary), summary);

  // ROE: the demo marker on the napp's own origin was cleaned up
  const leftover = await f.evaluate(() => {
    const out = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k.startsWith('__evil01_probe__')) out.push(k);
    }
    return out;
  });
  check('ROE: demo marker key cleaned up on own origin', leftover.length === 0, JSON.stringify(leftover));

  // the victim's secret survived at ITS OWN origin (nothing cross-napp happened)
  const victimSecretLeaked = /victim secret/.test(await evidence(f, 'origin-collision'));
  check('napp preset: no victim secret readable (origin derivation held)', !victimSecretLeaked, await evidence(f, 'origin-collision'));
  await page.close();
}

// ─── B. serve-at-launcher-origin: the same-origin mistake arms the escape ──
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { preset: 'napp', scheme: 'hashed', atlauncher: true, victim: true, referrer: 'strict', napp: ID });
  const st = await statuses(f);

  check('at-launcher-origin: parent DOM read armed', st['launcher-origin'] === 'armed', st['launcher-origin']);
  check('at-launcher-origin: evidence shows launcher localStorage reach',
    /launcher localStorage key/.test(await evidence(f, 'launcher-origin')), await evidence(f, 'launcher-origin'));
  check('at-launcher-origin: sibling frames scriptable',
    /SCRIPTABLE/.test(await evidence(f, 'frame-census')), await evidence(f, 'frame-census'));
  check('at-launcher-origin: victim secret readable (same origin now)',
    st['origin-collision'] === 'armed', st['origin-collision']);
  check('at-launcher-origin: top-nav armed via same-origin (readable, no navigation needed)',
    st['top-nav'] === 'armed', st['top-nav']);
  await page.close();
}

// ─── C. naive origin scheme: the collision arms cross-napp theft ────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { preset: 'napp', scheme: 'naive', victim: true, referrer: 'strict', napp: ID });
  const st = await statuses(f);

  check('naive scheme: victim secret readable at the colliding origin', st['origin-collision'] === 'armed', st['origin-collision']);
  check('naive scheme: evidence names the collision',
    /victim secret READABLE/.test(await evidence(f, 'origin-collision')), await evidence(f, 'origin-collision'));
  check('naive scheme: launcher-origin still held (unique origins, no same-origin serving)',
    st['launcher-origin'] === 'blocked', st['launcher-origin']);
  await page.close();
}

// ─── D. allow-top-navigation preset: the probe navigates, reloads, re-arms ──
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { preset: 'top-nav', scheme: 'hashed', victim: false, referrer: 'full', napp: ID, settleMs: 0 });

  // the probe navigates the launcher to its own URL + marker query param,
  // which reloads the harness and relaunches the napp (fresh frame). The
  // relaunched frame sees the param in its own referrer and reports ARMED
  // without navigating again — no reload loop.
  await page.waitForFunction(() => /[?&]evil01nav=1/.test(location.search), null, { timeout: 30000 });
  check('top-nav knob: launcher navigated by the napp (reload at its own URL)', true);
  check('top-nav knob: exactly one navigation (no reload loop)',
    (await page.evaluate(() => (window.__evilLogLines || []).join('\n').split('── load:').length - 1)) <= 2,
    await page.evaluate(() => (window.__evilLogLines || []).length));
  check('top-nav knob: harness saw the nav probe', await page.evaluate(() => !!window.__navProbe));

  const f2 = await findEvilFrame(page, ID);
  await waitSettled(f2, 12000);
  const st = await statuses(f2);
  check('top-nav knob: relaunched frame reports ancestor navigation ARMED', st['top-nav'] === 'armed', JSON.stringify(st));
  check('top-nav knob: evidence names the reload-and-relaunch proof',
    /PERMITTED/.test(await evidence(f2, 'top-nav')), await evidence(f2, 'top-nav'));
  check('top-nav knob: relaunched frame did NOT navigate again (referrer param consumed)',
    !/[?&]evil01nav=1&evil01nav/.test(page.url()), page.url());
  await page.close();
}

// ─── E. allow-popups preset ──────────────────────────────────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { preset: 'popups', scheme: 'hashed', victim: false, referrer: 'strict', napp: ID });
  const st = await statuses(f);
  check('popups knob: window.open armed', st['popup'] === 'armed', st['popup']);
  await page.close();
}

// ─── F. VERY EVIL: typed gate + real execution, destructive last ────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, {
    preset: 'no-sandbox', scheme: 'naive', atlauncher: true, victim: true,
    referrer: 'full', prompts: 'auto', napp: ID,
  });

  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  check('confirm: dialog lists every armed payload', planCount >= 6, String(planCount));
  const lastPlan = await dlg.locator('#planList li').last().innerText();
  check('confirm: destructive navigation listed LAST', /ancestor navigation|LAST/i.test(lastPlan) || /shell hijack/i.test(lastPlan), lastPlan);
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  check('confirm: disabled before typing the phrase', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('execute evil');
  check('confirm: wrong case does not enable', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  // the 7-payload plan can overflow the 62vh iframe viewport, so scroll the
  // dialog and click programmatically — the gate is the typed phrase + the
  // rendered plan, both asserted above
  await f.evaluate(() => { document.getElementById('confirmDlg').scrollTop = 1e6; });
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());

  // payloads execute in order: theft + defacement first, then the destructive
  // navigation of the launcher to the collector. Read each payload's result
  // out of the evil log BEFORE the navigation destroys the frame.
  await page.waitForFunction(() => !!document.querySelector('#__evil01_pwned_banner__'), null, { timeout: 30000 });
  check('evil: launcher DOM defaced (launcher-origin payload)', true);
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('DONE popup escape'),
    null, { timeout: 30000 });
  const popupResult = await f.evaluate(() => {
    // the log truncates long JSON; the report is updated fully after every payload
    try {
      const r = JSON.parse(document.getElementById('reportText').value);
      const row = (r.findings || []).find((x) => x.id === 'popup');
      return row && row.evil ? row.evil : null;
    } catch (e) { return { parseError: String(e) }; }
  });

  // destructive payload LAST: the launcher tab is hijacked to the collector
  await page.waitForFunction(() => location.href.includes('/collect'), null, { timeout: 30000 });
  check('evil: launcher hijacked to collector (destructive payload last)', page.url().includes('/collect'), page.url());

  // every payload before the navigation has now fired its exfil request
  check('evil: launcher canary nsec exfiltrated',
    exfil.some(x => (x.body || '').includes('__harness_canary_nsec__') || (x.body || '').includes('nsec1fake')),
    exfil.map(x => (x.body || '').slice(0, 120)).join(' || '));
  check('evil: victim secret exfiltrated (origin collision)',
    exfil.some(x => (x.body || '').includes('__victim_secret__')),
    exfil.map(x => (x.url || '') + (x.body || '').slice(0, 90)).join(' || '));
  check('evil: referrer exfiltrated', exfil.some(x => (x.body || '').includes('referrer')));
  check('evil: frame census exfiltrated', exfil.some(x => (x.body || '').includes('frame-census')));
  check('evil: origin-persist marker exfiltrated', exfil.some(x => (x.body || '').includes('origin-persist')));
  check('evil: popup escape opened a real popup (sandbox allow-popups exempts frames from the popup blocker)',
    popupResult && popupResult.opened === true, JSON.stringify(popupResult));
  check('evil: popup escape pointed at the collector',
    popupResult && /popup-exfil/.test(popupResult.attempted || ''), JSON.stringify(popupResult));
  await page.close();
}

await browser.close();
check.finish();
