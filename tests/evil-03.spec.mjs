// Red-team verification: evil-03-bridge-forge against the victim harness.
// Run: node tests/evil-03.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, statuses, evidence,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-03-bridge-forge';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. strict router + checked boot channel: only the bridge-level row arms ─
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { router: 'strict', bootcheck: true, victim: true, prompts: 'auto', napp: ID });
  const st = await statuses(f);
  check('strict router: declared-instanceId forge held', st['cross-app-forge'] === 'blocked', st['cross-app-forge']);
  check('strict router: source-blind child frame held', st['source-blindness'] === 'blocked', st['source-blindness']);
  check('bridge-level reply injection arms (reference bridge has no source check)',
    st['reply-injection'] === 'armed', st['reply-injection']);
  check('checked boot channel: boot forgery held', st['boot-command-forgery'] === 'blocked', st['boot-command-forgery']);
  const ev = await evidence(f, 'reply-injection');
  check('bridge row evidence names the callback forgery', /forged subscription callback/.test(ev), ev);
  await page.close();
}

// ─── B. declared-only router: cross-app forge arms + victim attribution ────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { router: 'declared', bootcheck: true, victim: true, prompts: 'prompt', napp: ID });
  const st = await statuses(f);
  check('declared router: cross-app forge armed', st['cross-app-forge'] === 'armed', st['cross-app-forge']);
  check('declared router: evidence names the declared-instanceId trust',
    /DECLARED instanceId/.test(await evidence(f, 'cross-app-forge')), await evidence(f, 'cross-app-forge'));
  // attribution: a gated forged rpc opens a dialog charged to the VICTIM
  // (discover its actual instance id — the serial counter is global)
  const title = await page.evaluate(() => new Promise((resolve) => {
    const victim = (window.__harnessWins() || []).find(w => w.nappId === 'victim');
    window.postMessage({ __nostrapps: 'rpc', id: 'spec-attrib', method: 'signEvent', params: { kind: 1, content: 'x', created_at: 1 }, instanceId: victim && victim.instanceId }, '*');
    setTimeout(() => resolve(document.getElementById('dlgTitle').textContent), 800);
  }));
  check('declared router: gated forge charges the VICTIM\'s approval record',
    /victim/i.test(title), title);
  await page.close();
}

// ─── C. reference router (origin + declared instanceId): source blindness ──
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { router: 'reference', bootcheck: true, victim: true, prompts: 'auto', napp: ID });
  const st = await statuses(f);
  check('reference router: cross-app forge held (origin check)', st['cross-app-forge'] === 'blocked', st['cross-app-forge']);
  check('reference router: same-origin child frame accepted (source never checked)',
    st['source-blindness'] === 'armed', st['source-blindness']);
  const ev = await evidence(f, 'source-blindness');
  check('source-blindness evidence names MessageEvent.source', /MessageEvent\.source|never compares/.test(ev), ev);
  await page.close();
}

// ─── D. unchecked boot channel: boot forgery arms ────────────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { router: 'strict', bootcheck: false, victim: true, prompts: 'auto', napp: ID });
  const st = await statuses(f);
  check('unchecked boot channel: boot forgery armed', st['boot-command-forgery'] === 'armed', st['boot-command-forgery']);
  check('unchecked boot channel: evidence names the install channel',
    /install channel/.test(await evidence(f, 'boot-command-forgery')), await evidence(f, 'boot-command-forgery'));
  await page.close();
}

// ─── E. VERY EVIL: the destructive file swap, last ──────────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { router: 'declared', bootcheck: false, victim: true, prompts: 'auto', napp: ID });
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const lastPlan = await dlg.locator('#planList li').last().innerText();
  check('confirm: destructive file swap listed LAST', /boot-frame|LAST|runs LAST/i.test(lastPlan) || /boot/.test(lastPlan), lastPlan);
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 30000 });
  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const cross = report.findings.find(x => x.id === 'cross-app-forge');
  const boot = report.findings.find(x => x.id === 'boot-command-forgery');
  check('evil: forged publish landed under the victim\'s identity', cross?.evil?.landed === true, JSON.stringify(cross?.evil));
  check('evil: boot install acked by ≥1 origin', (boot?.evil?.installAcks || 0) >= 1, JSON.stringify(boot?.evil));
  check('evil: read-back proves the file swap', boot?.evil?.readbackProvesSwap === true, JSON.stringify(boot?.evil));
  // the victim's origin now serves attacker bytes (its running document survives)
  const swapped = await page.evaluate(async () => {
    const frames = window.parent ? [] : [];
    return (window.__evilLogLines || []).some(l => l.includes('[swap]') || l.includes('napp-install'));
  });
  await page.close();
}

await browser.close();
check.finish();
