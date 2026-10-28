// Red-team verification: evil-06-signer-abuse against the victim harness.
// Run: node tests/evil-06.spec.mjs
import {
  chromium, BASE, makeChecks, loadHarness, statuses, evidence, collectExfil,
} from './_helper.mjs';

const check = makeChecks();
const ID = 'evil-06-signer-abuse';
const browser = await chromium.launch({ viewport: { width: 1680, height: 1200 } });

// ─── A. deny-all policy: only the ungated channels arm ──────────────────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { prompts: 'deny', victim: false, napp: ID });
  const st = await statuses(f);
  check('deny-all: pubkey handout armed (identity grant, no prompt)', st['pk-handout'] === 'armed', st['pk-handout']);
  check('deny-all: gated cipher probe held', st['silent-sign'] === 'blocked', st['silent-sign']);
  check('deny-all: cipher exfil channel held', st['nip-exfil'] === 'blocked', st['nip-exfil']);
  check('deny-all: relay-REQ exfil armed (reads never prompt)',
    st['relay-exfil'] === 'armed', st['relay-exfil']);
  await page.close();
}

// ─── B. prompt policy: the dialog is all that stands — and it shows ─────────
{
  const page = await browser.newPage();
  const f = await loadHarness(page, { prompts: 'prompt', victim: false, napp: ID });
  const st = await statuses(f);
  check('prompt: gated cipher probe held by the dialog', st['silent-sign'] === 'blocked', st['silent-sign']);
  const ev = await evidence(f, 'silent-sign');
  check('prompt: evidence names the dialog and its cost',
    /dialog stood in the way/.test(ev), ev);
  check('prompt: the dialog actually opened (promptCount)', await page.evaluate(() => (window.__promptCount || 0) >= 1));
  check('prompt: relay-REQ exfil armed even under prompts (reads never prompt)',
    st['relay-exfil'] === 'armed', st['relay-exfil']);
  await page.close();
}

// ─── C. auto-allow policy: everything goes silent ────────────────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { prompts: 'auto', victim: false, napp: ID });
  const st = await statuses(f);
  check('auto-allow: silent-sign armed (fast auto-approval)', st['silent-sign'] === 'armed', st['silent-sign']);
  const ev = await evidence(f, 'silent-sign');
  check('auto-allow: evidence shows the fast approval', /AUTO-APPROVED/.test(ev), ev);
  check('auto-allow: cipher exfil channel armed', st['nip-exfil'] === 'armed', st['nip-exfil']);
  check('ROE: demo mode made no exfil requests', exfil.length === 0, String(exfil.length));
  await page.close();
}

// ─── D. VERY EVIL: the full exfil chain under auto-allow ─────────────────────
{
  const page = await browser.newPage();
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { prompts: 'auto', victim: true, napp: ID });
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  const planCount = await dlg.locator('#planList li').count();
  check('confirm: all four rows listed', planCount === 4, String(planCount));
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').evaluate((el) => el.click());
  await f.waitForFunction(
    () => (document.getElementById('evilLog')?.textContent || '').includes('finished.'),
    null, { timeout: 40000 });

  const report = await f.evaluate(() => JSON.parse(document.getElementById('reportText').value));
  const sign = report.findings.find(x => x.id === 'silent-sign');
  const nip = report.findings.find(x => x.id === 'nip-exfil');
  const relay = report.findings.find(x => x.id === 'relay-exfil');
  check('evil: marker note SIGNED under auto-allow (signature produced)',
    sign?.evil?.signed === true, JSON.stringify(sign?.evil).slice(0, 160));
  check('evil: signature exfiltrated', exfil.some(x => (x.body || '').includes('silent-sign')));
  check('evil: victim note encrypted to the attacker key',
    typeof nip?.evil?.ciphertextTo === 'string', JSON.stringify(nip?.evil).slice(0, 160));
  check('evil: ciphertext published toward attacker relays', nip?.evil?.published === true);
  check('evil: nip-exfil exfiltrated', exfil.some(x => (x.body || '').includes('nip-exfil')));

  // the launcher log shows the publish and the REQ — the observable relay traffic
  const lines = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
  check('evil: RELAY-PUBLISH logged with attacker relays',
    /RELAY-PUBLISH[^\n]*attacker-relay\.example/.test(lines),
    lines.split('\n').filter(l => l.includes('RELAY')).slice(0, 3).join(' | '));
  check('evil: RELAY-REQ filter carried the victim note content',
    /RELAY-REQ[^\n]*victim note: pretend private content/.test(lines),
    lines.split('\n').filter(l => l.includes('RELAY-REQ')).slice(-2).join(' | '));
  check('evil: relay-exfil exfiltrated', exfil.some(x => (x.body || '').includes('relay-exfil')));
  await page.close();
}

await browser.close();
check.finish();
