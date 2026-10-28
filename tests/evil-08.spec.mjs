// Red-team verification: evil-08-hardened-oracles against the victim harness.
// These rows arm against a PERFECT launcher — findings against the protocol.
// Run: node tests/evil-08.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, findEvilFrame, waitSettled, statuses,
  evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-08-hardened-oracles';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. the hardened baseline: the traffic oracle arms by design ────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { victim: true, prompts: 'prompt', napp: ID });
  const st = await statuses(f);
  check('hardened: cross-app traffic analysis arms (protocol property)',
    st['store-traffic'] === 'armed', st['store-traffic']);
  const ev = await evidence(f, 'store-traffic');
  check('hardened: traffic evidence counts other apps\' inserts',
    /by other apps/.test(ev), ev);
  check('hardened: byte-swap records its hash (na on first run)',
    st['byte-swap'] === 'na', st['byte-swap']);
  check('hardened: metadata impersonation is an honest na',
    st['name-squat-card'] === 'na', st['name-squat-card']);
  check('hardened: policy oracle na without noisy publishes',
    st['policy-oracle'] === 'na', st['policy-oracle']);
  await page.close();
}

// ─── B. auto-allow: the oracle reads the policy off the store ───────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { victim: true, victimnoisy: true, prompts: 'auto', napp: ID });
  const st = await statuses(f);
  check('auto-allow: policy oracle arms with the auto inference',
    st['policy-oracle'] === 'armed', st['policy-oracle']);
  const ev = await evidence(f, 'policy-oracle');
  check('auto-allow: evidence says the victim\'s gated publishes LAND',
    /ARE landing/.test(ev), ev);
  await page.close();
}

// ─── C. prompt policy: the absence IS the answer ────────────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { victim: true, victimnoisy: true, prompts: 'prompt', napp: ID });
  const st = await statuses(f);
  check('prompt: policy oracle arms with the held inference',
    st['policy-oracle'] === 'armed', st['policy-oracle']);
  const ev = await evidence(f, 'policy-oracle');
  check('prompt: evidence says the absence is the answer',
    /NEVER land|absence is the answer/.test(ev), ev);
  await page.close();
}

// ─── D. the byte swap: unverified bytes, demonstrated ────────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { victim: false, napp: ID });
  const st1 = await statuses(f);
  check('byte swap: first run records the hash (na)', st1['byte-swap'] === 'na', st1['byte-swap']);
  // the launcher's debug control swaps the napp's bytes + reloads its window —
  // exactly what a hostile relay does in production. Wait for the swap to run
  // (async) and the reload to replace the frame, so findEvilFrame gets the
  // FRESH frame and not the stale one.
  await page.click('#swapFiles');
  await page.waitForFunction(() => (window.__evilLogLines || []).some(l => l.includes('[swap] re-installed')),
    null, { timeout: 15000 });
  await page.waitForTimeout(2500); // the old frame navigates away, the fresh one mounts
  const f2 = await findEvilFrame(page, ID);
  await waitSettled(f2, 25000);
  const st2 = await statuses(f2);
  check('byte swap: the relaunched frame DETECTS the swap',
    st2['byte-swap'] === 'armed', st2['byte-swap']);
  const ev2 = await evidence(f2, 'byte-swap');
  check('byte swap: evidence shows the hash divergence',
    /CHANGED UNDERNEATH ME/.test(ev2), ev2);
  await page.close();
}

// ─── E. VERY EVIL: the surveillance profile ─────────────────────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { victim: true, victimnoisy: true, prompts: 'auto', napp: ID });
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  // fresh page ⇒ fresh partitioned storage ⇒ byte-swap records its hash (na)
  check('confirm: the two armed rows listed (fresh partition: byte-swap na)', planCount === 2, String(planCount));
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 60000 });

  check('evil: the traffic profile exfiltrated',
    exfil.some(x => (x.body || '').includes('store-traffic-profile')),
    exfil.map(x => (x.body || '').slice(0, 90)).join(' || '));
  check('evil: the policy oracle exfiltrated',
    exfil.some(x => (x.body || '').includes('policy-oracle')));
  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const traffic = report.findings.find(x => x.id === 'store-traffic');
  check('evil: the profile counts real inserts',
    (traffic?.evil?.profile?.total || 0) > 0, JSON.stringify(traffic?.evil?.profile).slice(0, 140));
  const oracle = report.findings.find(x => x.id === 'policy-oracle');
  check('evil: the oracle inferred the auto-allow policy',
    /auto-allow/.test(String(oracle?.evil?.inference || '')), String(oracle?.evil?.inference));
  await page.close();
}

await browser.close();
check.finish();
