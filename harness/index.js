'use strict';
(function () {
  // ────────────────────────────────────────────────────────────────────────
  // evil-napps harness — a faithful miniature of the eskema/nostrapps
  // reference launcher (per-origin <label>.localhost subdomains, hidden
  // boot.html frames registering a service worker, files served from
  // per-origin IndexedDB, bridge.js injected into napp HTML, window.name
  // instance ids) with every isolation knob re-armable per rung.
  // ────────────────────────────────────────────────────────────────────────

  const controls = document.getElementById('controls');
  const nappSel = document.getElementById('nappSel');
  const meta = document.getElementById('meta');
  const msgs = document.getElementById('msgs');
  const bootsEl = document.getElementById('boots');
  const evilWinEl = document.getElementById('evilWin');
  const victimWinEl = document.getElementById('victimWin');
  const storeEl = document.getElementById('store');
  const navprobeEl = document.getElementById('navprobe');
  const launcherCardEl = document.getElementById('launcherCard');

  const FAKE_PK = '3d0e4f3a5c61787b90a1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f50617';
  const KNOB_KEY = '__harness_knobs__';
  const DECISIONS_KEY = '__harness_decisions__';

  let instanceSerial = 0;
  const wins = new Map();      // instanceId -> win
  const boots = new Map();    // nappId -> {iframe, origin}
  const registry = new Map(); // instanceId -> [{idx, pattern}]
  const pendingDispatches = new Map(); // requestId -> {instanceId, resolve, reject}
  const pendingReady = new Map();      // instanceId -> resolve

  window.__evilLogLines = [];
  function log(line) {
    window.__evilLogLines.push(line);
    msgs.textContent += line + '\n';
    msgs.scrollTop = msgs.scrollHeight;
  }
  window.__harnessWins = () => [...wins.values()].map(w => ({
    instanceId: w.instanceId, nappId: w.nappId, origin: w.origin, title: w.title,
  }));

  // ── launcher canaries (evil-01's launcher-origin theft should find these) ──
  localStorage.setItem('__harness_canary_nsec__', 'nsec1fake_redteam_canary_this_is_not_a_real_key');
  localStorage.setItem('__harness_canary_grant__', JSON.stringify({ app: 'profile-viewer', decision: 'allow', method: 'signEvent' }));

  // A share-link style payload in the launcher URL — what the referrer row
  // proves leaks into every napp under a leaky Referrer-Policy.
  if (!location.search.includes('share=')) {
    try {
      history.replaceState(null, '', location.pathname + '?share=REFERRER-CANARY-open%3Aprofile%3Apayload&' + location.search.slice(1) + location.hash);
    } catch (_) {}
  }

  // The evil-01 navigation probe marker: a napp navigated window.top to this
  // URL with the probe's marker param (a query param — referrers never carry
  // fragments, so the relaunched frame needs the marker in its own referrer).
  if (/[?&]evil01nav=1/.test(location.search)) {
    window.__navProbe = true;
    navprobeEl.style.display = 'block';
  }

  // ── knobs ────────────────────────────────────────────────────────────────
  function knobValues() {
    const f = new FormData(controls);
    return {
      preset: f.get('preset'),
      scheme: f.get('scheme'),
      atlauncher: f.get('atlauncher') === 'on',
      victim: f.get('victim') === 'on',
      referrer: f.get('referrer'),
      render: f.get('render'),
      lcsp: f.get('lcsp'),
      router: f.get('router'),
      prompts: f.get('prompts'),
      napp: nappSel.value,
    };
  }
  function persistKnobs() {
    try { localStorage.setItem(KNOB_KEY, JSON.stringify(knobValues())); } catch (_) {}
  }
  function restoreKnobs() {
    try {
      const k = JSON.parse(localStorage.getItem(KNOB_KEY) || '{}');
      if (k.preset) { const el = controls.querySelector('input[name="preset"][value="' + k.preset + '"]'); if (el) el.checked = true; }
      if (k.scheme) { const el = controls.querySelector('input[name="scheme"][value="' + k.scheme + '"]'); if (el) el.checked = true; }
      if (k.render) { const el = controls.querySelector('input[name="render"][value="' + k.render + '"]'); if (el) el.checked = true; }
      if (typeof k.atlauncher === 'boolean') controls.querySelector('input[name="atlauncher"]').checked = k.atlauncher;
      if (typeof k.victim === 'boolean') controls.querySelector('input[name="victim"]').checked = k.victim;
      if (k.referrer) controls.querySelector('select[name="referrer"]').value = k.referrer;
      if (k.lcsp) controls.querySelector('select[name="lcsp"]').value = k.lcsp;
      if (k.router) controls.querySelector('select[name="router"]').value = k.router;
      if (k.prompts) controls.querySelector('select[name="prompts"]').value = k.prompts;
      return k;
    } catch (_) { return {}; }
  }
  controls.addEventListener('change', persistKnobs);
  nappSel.addEventListener('change', persistKnobs);

  // ── origin derivation (the knob evil-01's collision row attacks) ─────────
  async function sha256Hex(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  const slug = s => String(s).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  async function labelFor(nappId, scheme) {
    if (scheme === 'naive') return slug(nappId).slice(0, 63) || 'napp';
    const head = slug(nappId).slice(0, 40);
    const tag = (await sha256Hex(nappId)).slice(0, 12);
    return (head ? head + '-' : '') + tag;
  }
  function originForLabel(label) {
    return location.protocol + '//' + label + '.' + location.host;
  }

  // ── fake signer / store / relay (the authority the bridge hands out) ─────
  function randHex(n) {
    const b = new Uint8Array(n / 2);
    crypto.getRandomValues(b);
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  }
  const store = [];
  window.__harnessStore = () => store;
  function seedStore() {
    store.push({ id: randHex(64), pubkey: FAKE_PK, created_at: Math.floor(Date.now() / 1000) - 500, kind: 10002, tags: [['relay', 'wss://relay.example'], ['relay', 'wss://nos.lol']], content: '', sig: randHex(128) });
    store.push({ id: randHex(64), pubkey: FAKE_PK, created_at: Math.floor(Date.now() / 1000) - 400, kind: 1, tags: [], content: 'victim note: pretend private content (store canary, kind 1)', sig: randHex(128) });
  }
  seedStore();
  const storeSubs = new Map(); // callbackId -> {instanceId, filters, deliver}
  function matchFilter(f, e) {
    if (f.ids && !f.ids.includes(e.id)) return false;
    if (f.kinds && !f.kinds.includes(e.kind)) return false;
    if (f.authors && !f.authors.includes(e.pubkey)) return false;
    if (typeof f.since === 'number' && e.created_at <= f.since) return false;
    if (typeof f.until === 'number' && e.created_at > f.until) return false;
    for (const [k, vals] of Object.entries(f)) {
      if (k[0] === '#' && Array.isArray(vals)) {
        const tag = k.slice(1);
        const has = e.tags.some(t => t[0] === tag && vals.includes(t[1]));
        if (!has) return false;
      }
    }
    return true;
  }
  const matchAny = (filters, e) => filters.some(f => matchFilter(f, e));
  function storeSave(event) {
    if (!event || typeof event !== 'object') return false;
    if (store.some(e => e.id === event.id)) return false;
    store.push(event);
    for (const [cbId, sub] of storeSubs) {
      if (matchAny(sub.filters, event)) sub.deliver(event);
    }
    return true;
  }
  function dumpStore() {
    storeEl.textContent = JSON.stringify(store.map(e => ({ id: e.id.slice(0, 8), kind: e.kind, pubkey: e.pubkey.slice(0, 8), content: e.content.slice(0, 48) })), null, 1);
  }
  function shapeVerified(event) {
    return !!(event && typeof event === 'object' &&
      /^[0-9a-f]{64}$/i.test(event.id || '') &&
      /^[0-9a-f]{128}$/i.test(event.sig || ''));
  }

  // ── permission prompts (knob: prompt | auto-allow | deny-all) ────────────
  const dlg = document.getElementById('dialog');
  const dlgTitle = document.getElementById('dlgTitle');
  const dlgBody = document.getElementById('dlgBody');
  let promptQueue = Promise.resolve();
  function getDecision(nappId, method) {
    try { return JSON.parse(localStorage.getItem(DECISIONS_KEY) || '{}')[nappId + '|' + method] || null; } catch (_) { return null; }
  }
  function setDecision(nappId, method, decision) {
    try {
      const all = JSON.parse(localStorage.getItem(DECISIONS_KEY) || '{}');
      all[nappId + '|' + method] = decision;
      localStorage.setItem(DECISIONS_KEY, JSON.stringify(all));
    } catch (_) {}
  }
  function openPrompt(nappId, method, detail) {
    window.__promptCount = (window.__promptCount || 0) + 1;
    return new Promise(resolve => {
      dlgTitle.textContent = 'Permission request — ' + (nappId || 'unknown') + ' wants to ' + method;
      dlgBody.textContent = detail || '(no detail provided by the launcher)';
      dlg.classList.add('open');
      const done = v => {
        dlg.classList.remove('open');
        for (const id of ['dlgAllow', 'dlgAlways', 'dlgDeny']) document.getElementById(id).onclick = null;
        resolve(v);
      };
      document.getElementById('dlgAllow').onclick = () => done('allow-once');
      document.getElementById('dlgAlways').onclick = () => done('allow-always');
      document.getElementById('dlgDeny').onclick = () => done('deny-once');
    });
  }
  async function requireApproval(nappId, method, detail) {
    const mode = knobValues().prompts;
    const cached = getDecision(nappId, method);
    if (cached === 'allow') return true;
    if (cached === 'deny') return false;
    if (mode === 'auto') return true;
    if (mode === 'deny') return false;
    const run = promptQueue.then(() => openPrompt(nappId, method, detail));
    promptQueue = run.then(() => {}, () => {});
    const decision = await run;
    if (decision === 'allow-always') setDecision(nappId, method, 'allow');
    if (decision === 'deny-once') return false;
    return decision === 'allow-once' || decision === 'allow-always';
  }

  // ── metadata render (evil-02: the launcher card) ──────────────────────────
  // metadata.json is attacker-controlled bytes. The card is what a real
  // launcher's app list, permission prompt and handler picker all do: put the
  // napp's title/description/icon into the launcher's own DOM.
  function renderCard(m) {
    const mode = knobValues().render;
    const title = String((m && m.title) || '');
    const desc = String((m && m.description) || '');
    const icon = String((m && m.icon) || '');
    if (mode === 'unsafe') {
      // THE BUG: unsigned metadata.json rendered as HTML in the launcher origin
      launcherCardEl.innerHTML =
        '<span class="l-label">launcher card (metadata render)</span><b>' + title +
        '</b><p>' + desc + '</p>' + (icon ? '<img class="l-icon" src="' + icon + '" alt="icon">' : '');
      log('[launcher] rendered metadata via innerHTML (UNSAFE) — attacker bytes in the launcher origin');
    } else {
      launcherCardEl.textContent = '';
      const label = document.createElement('span');
      label.className = 'l-label';
      label.textContent = 'launcher card (metadata render)';
      const b = document.createElement('b');
      b.textContent = title;
      const p = document.createElement('p');
      p.textContent = desc;
      launcherCardEl.append(label, b, p);
      if (icon) {
        const ic = document.createElement('p');
        ic.textContent = 'icon: ' + icon;
        launcherCardEl.append(ic);
      }
      log('[launcher] rendered metadata as text (safe)');
    }
  }

  // ── boot + install pipeline (the reference's, faithfully) ─────────────────
  function waitForBootMessage(bootIframe, expectedOrigin, type) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        window.removeEventListener('message', handler);
        reject(new Error('Timed out waiting for ' + type));
      }, 15000);
      const handler = event => {
        if (event.origin !== expectedOrigin || event.source !== bootIframe.contentWindow) return;
        const data = event.data;
        if (!data) return;
        if (data.__nostrapps === type || data.__nostrapps === 'napp-boot-error') {
          clearTimeout(timer);
          window.removeEventListener('message', handler);
          data.__nostrapps === 'napp-boot-error' ? reject(new Error(data.error)) : resolve(data);
        }
      };
      window.addEventListener('message', handler);
    });
  }
  async function bootNapp(nappId, origin, files, policy) {
    let boot = boots.get(nappId);
    if (boot && boot.origin === origin) {
      // boot frame already alive at this origin: reuse it for the install
    } else {
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = origin + '/boot.html';
      bootsEl.appendChild(iframe);
      boot = { iframe, origin };
      boots.set(nappId, boot);
      await waitForBootMessage(iframe, origin, 'napp-boot-ready');
    }
    const done = waitForBootMessage(boot.iframe, origin, 'napp-install-done');
    boot.iframe.contentWindow.postMessage({ __nostrapps: 'napp-install', files, policy }, origin);
    const res = await done;
    return res;
  }
  async function fetchNappFiles(nappDir) {
    const [html, m] = await Promise.all([
      fetch('/napps/' + nappDir + '/index.html').then(r => r.text()),
      fetch('/napps/' + nappDir + '/metadata.json').then(r => r.json()),
    ]);
    return { meta: m, files: [
      { path: '/index.html', body: html, mime: 'text/html' },
      { path: '/metadata.json', body: JSON.stringify(m), mime: 'application/json' },
    ]};
  }

  // ── mount: the visible window + iframe ────────────────────────────────────
  const SANDBOX = {
    'napp': 'allow-scripts allow-same-origin allow-forms',
    'top-nav': 'allow-scripts allow-same-origin allow-forms allow-top-navigation',
    'popups': 'allow-scripts allow-same-origin allow-forms allow-popups allow-modals',
    'no-sandbox': null,
  };
  function mount(opts) {
    // opts: {nappId, title, origin, src, atLauncher, target}
    const instanceId = String(++instanceSerial);
    const win = document.createElement('div');
    win.className = 'nappwin';
    win.dataset.nappId = opts.nappId;
    win.dataset.instanceId = instanceId;
    const head = document.createElement('div');
    head.className = 'nappwin-head';
    const b = document.createElement('b');
    b.textContent = opts.title || opts.nappId;
    const inst = document.createElement('span');
    inst.className = 'inst';
    inst.textContent = 'instance ' + instanceId + (opts.atLauncher ? ' · AT LAUNCHER ORIGIN' : ' · ' + opts.origin);
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.onclick = () => closeWindow(instanceId);
    head.append(b, inst, closeBtn);
    const iframe = document.createElement('iframe');
    iframe.name = instanceId;
    const sb = SANDBOX[knobValues().preset];
    if (sb) iframe.setAttribute('sandbox', sb);
    else iframe.removeAttribute('sandbox');
    iframe.src = opts.src;
    win.append(head, iframe);
    opts.target.appendChild(win);
    const w = {
      root: win, iframe, instanceId, nappId: opts.nappId,
      origin: opts.atLauncher ? location.origin : opts.origin,
      title: opts.title || opts.nappId,
      atLauncher: !!opts.atLauncher,
    };
    wins.set(instanceId, w);
    return w;
  }
  function closeWindow(instanceId) {
    const w = wins.get(instanceId);
    if (!w) return;
    w.root.remove();
    wins.delete(instanceId);
    registry.delete(instanceId);
  }
  function waitForReady(instanceId, ms) {
    ms = ms || 6000;
    return new Promise(resolve => {
      if (pendingReady.has(instanceId)) return resolve(false);
      const timer = setTimeout(() => { pendingReady.delete(instanceId); resolve(false); }, ms);
      pendingReady.set(instanceId, ok => { clearTimeout(timer); pendingReady.delete(instanceId); resolve(ok !== false); });
    });
  }

  // ── the message router: window-level demux by knob discipline ────────────
  // strict:      MessageEvent.source must be the window's iframe (spec-grade)
  // reference:   origin match + declared instanceId (what nostrapps does)
  // declared:    declared instanceId only (the sloppy shortcut)
  function acceptsFor(win, event) {
    const d = event.data;
    if (!d || typeof d.__nostrapps !== 'string') return false;
    const mode = knobValues().router;
    if (mode === 'strict') return event.source === win.iframe.contentWindow;
    if (mode === 'reference') return event.origin === win.origin && d.instanceId === win.instanceId;
    return d.instanceId === win.instanceId;
  }
  window.addEventListener('message', event => {
    const d = event.data;
    if (!d) return;
    if (typeof d.__nostrapps === 'string') {
      if (d.__nostrapps === 'napp-boot-ready' || /^napp-(install|wipe|set-policy|read-files|boot)/.test(d.__nostrapps)) return; // boot channel: separate, source-checked
      const win = [...wins.values()].find(w => acceptsFor(w, event));
      if (!win) {
        log('DROPPED ' + d.__nostrapps + ' from UNKNOWN source (origin ' + (event.origin || 'null') + '): ' + JSON.stringify(d).slice(0, 110));
        return;
      }
      handleWindowMessage(win, d, event);
      return;
    }
    // Non-bridge messages (evil-02's XSS implant arm channel etc.) are not
    // the launcher's bridge — ignored by the router.
  });
  function handleWindowMessage(win, d, event) {
    switch (d.__nostrapps) {
      case 'napp-ready': {
        log('ACCEPTED napp-ready instance ' + d.instanceId + ' (' + win.nappId + ')');
        const r = pendingReady.get(d.instanceId);
        if (r) r(true);
        return;
      }
      case 'napp-action-registered': {
        log('ACCEPTED napp-action-registered ' + JSON.stringify({ instance: d.instanceId, pattern: d.pattern, idx: d.idx }));
        const list = registry.get(d.instanceId) || [];
        list.push({ idx: d.idx, pattern: d.pattern });
        registry.set(d.instanceId, list);
        return;
      }
      case 'rpc': {
        log('ACCEPTED rpc ' + d.method + ' from ' + win.nappId + ' instance ' + d.instanceId);
        void handleRpc(win, d);
        return;
      }
      case 'napp-dispatch-result': {
        log('ACCEPTED napp-dispatch-result ' + JSON.stringify({ requestId: d.requestId, instance: d.instanceId }).slice(0, 110));
        settleDispatch(d, win.instanceId);
        return;
      }
      case 'napp-close': {
        log('ACCEPTED napp-close from ' + win.nappId + ' instance ' + d.instanceId);
        closeWindow(d.instanceId);
        return;
      }
      default:
        log('DROPPED unknown envelope ' + d.__nostrapps + ' from ' + win.nappId);
    }
  }

  // ── rpc dispatch (the bridge's authority surface) ────────────────────────
  const GATED = new Set(['signEvent', 'nip04.encrypt', 'nip04.decrypt', 'nip44.encrypt', 'nip44.decrypt', 'napp.publish']);
  async function handleRpc(win, d) {
    const reply = (result) => win.iframe.contentWindow.postMessage({ __nostrapps: 'rpc-result', id: d.id, result }, '*');
    const replyErr = (error) => win.iframe.contentWindow.postMessage({ __nostrapps: 'rpc-error', id: d.id, error }, '*');
    try {
      const result = await runRpc(win, d.method, d.params);
      reply(result);
    } catch (err) {
      replyErr(err && err.message ? err.message : String(err));
    }
  }
  function hasDomain(win, domain) {
    return win.atLauncher ? true : (win.policyDomains || []).includes(domain);
  }
  async function runRpc(win, method, params) {
    if (['getPublicKey', 'signEvent', 'nip04.encrypt', 'nip04.decrypt', 'nip44.encrypt', 'nip44.decrypt'].includes(method) && !hasDomain(win, 'identity')) {
      throw new Error('identity access not granted: ' + method);
    }
    if (GATED.has(method)) {
      const detail = method === 'signEvent'
        ? 'kind ' + (params && params.kind) + ' — content: ' + String(params && params.content).slice(0, 120)
        : method === 'napp.publish'
          ? 'kind ' + (params && params.event && params.event.kind) + ' to relays: ' + JSON.stringify(params && params.relays).slice(0, 120)
          : JSON.stringify(params).slice(0, 160);
      const allowed = await requireApproval(win.nappId, method, detail);
      if (!allowed) throw new Error('Permission denied: ' + method);
    }
    switch (method) {
      case 'getPublicKey':
        return FAKE_PK;
      case 'signEvent': {
        const ev = { ...params, pubkey: FAKE_PK, id: randHex(64), sig: 'FAKESIG-' + randHex(56) };
        storeSave(ev);
        dumpStore();
        return ev;
      }
      case 'nip04.encrypt':
      case 'nip44.encrypt':
        return 'FAKE-' + method + '|to:' + (params && params.pubkey) + '|' + btoa(unescape(encodeURIComponent(String(params && params.plaintext))));
      case 'nip04.decrypt':
      case 'nip44.decrypt': {
        try {
          const m = /\|(.*)\|$/.exec(String(params && params.ciphertext));
          return decodeURIComponent(escape(atob(m[1])));
        } catch (_) { return '(undecipherable)'; }
      }
      case 'nostrdb.add': {
        // shape-verified only (harness limit; the reference verifies the
        // actual signature — evil-05's rows are about remove/observe, not
        // signature forgery)
        const ev = params && params.event;
        if (!shapeVerified(ev)) return false;
        const saved = storeSave(ev);
        dumpStore();
        return saved;
      }
      case 'nostrdb.query': {
        const filters = Array.isArray(params && params.filters) ? params.filters : [params && params.filters];
        return store.filter(e => matchAny(filters, e));
      }
      case 'nostrdb.count': {
        const filters = Array.isArray(params && params.filters) ? params.filters : [params && params.filters];
        return store.filter(e => matchAny(filters, e)).length;
      }
      case 'nostrdb.event':
        return store.find(e => e.id === (params && params.id)) || undefined;
      case 'nostrdb.remove': {
        // THE REFERENCE'S GAP (validated from source): deletes by id with no
        // permission gate and no author check. Any napp can censor the
        // launcher-wide store. evil-05 demonstrates.
        const ids = Array.isArray(params && params.ids) ? params.ids : [];
        let n = 0;
        for (const id of ids) {
          const i = store.findIndex(e => e.id === id);
          if (i !== -1) { store.splice(i, 1); n++; }
        }
        dumpStore();
        return ids.slice(0, n);
      }
      case 'nostrdb.replaceable': {
        const { kind, author, identifier } = params || {};
        const matches = store.filter(e => e.kind === kind && e.pubkey === author &&
          (identifier == null ? true : (e.tags.find(t => t[0] === 'd') || [])[1] === identifier));
        matches.sort((a, b) => b.created_at - a.created_at);
        return matches[0] || undefined;
      }
      case 'nostrdb.subscribe': {
        const filters = Array.isArray(params && params.filters) ? params.filters : [params && params.filters];
        const cbId = params.callbackId;
        const sink = (event) => win.iframe.contentWindow.postMessage({ __nostrapps: 'nostrdb-sub-event', callbackId: cbId, event }, '*');
        storeSubs.set(cbId, { instanceId: win.instanceId, filters, deliver: sink });
        return null;
      }
      case 'nostrdb.unsubscribe':
        storeSubs.delete(params && params.callbackId);
        return null;
      case 'napp.subscribe': {
        // fake relay: nothing connects anywhere; the REQ (relays + filter)
        // IS the observable — evil-06's exfil channel is the filter itself.
        const relays = (params && params.relays) || [];
        log('RELAY-REQ from ' + win.nappId + ' — relays=' + JSON.stringify(relays) + ' filter=' + JSON.stringify(params && params.filter).slice(0, 400));
        const cbId = params.callbackId;
        const events = store.filter(e => matchAny([params.filter], e));
        setTimeout(() => {
          win.iframe.contentWindow.postMessage({ __nostrapps: 'napp-sub-callback', callbackId: cbId, msg: { type: 'eose', events } }, '*');
        }, 120);
        return null;
      }
      case 'napp.unsubscribe':
        return null;
      case 'napp.publish': {
        const ev = params && params.event;
        const relays = (params && params.relays) || ['wss://author-write-relays.example'];
        log('RELAY-PUBLISH from ' + win.nappId + ' — relays=' + JSON.stringify(relays) + ' event=' + JSON.stringify({ kind: ev && ev.kind, content: ev && String(ev.content).slice(0, 200) }));
        if (ev) { storeSave(ev); dumpStore(); }
        return { relays: Object.fromEntries(relays.map(r => [r, { ok: true }])), published: relays.length, failed: 0 };
      }
      case 'napp.verifyEvent':
        return shapeVerified(params);
      case 'napp.action':
        return dispatchAction(win, params || {});
      case 'napp.log':
        log('[napp:' + win.nappId + '] ' + String(params && params.message).slice(0, 200));
        return null;
      default:
        throw new Error('harness: no such method ' + method);
    }
  }

  // ── action dispatch (registerAction namespace — evil-04's rung) ───────────
  let dispatchSerial = 0;
  function patternMatches(pattern, name) {
    return pattern === name || (pattern === 'view' && /^view:\d+$/.test(name));
  }
  async function waitForRegisteredAction(instanceId, name, ms) {
    ms = ms || 8000;
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      const list = registry.get(instanceId) || [];
      const hit = list.find(r => patternMatches(r.pattern, name));
      if (hit) return hit;
      await new Promise(r => setTimeout(r, 100));
    }
    throw new Error('no registered action for ' + name);
  }
  async function dispatchAction(callerWin, params) {
    const name = params.name;
    if (!name) throw new Error('napp.action: action name is required');
    const candidates = [...wins.values()].filter(w => {
      const list = registry.get(w.instanceId) || [];
      return list.some(r => patternMatches(r.pattern, name));
    });
    if (!candidates.length) throw new Error('no handler registered for ' + name);
    const target = params.options && params.options.instance
      ? wins.get(params.options.instance)
      : candidates[0]; // first candidate wins — the auto-pick evil-04 attacks
    if (!target) throw new Error('no such instance');
    const reg = await waitForRegisteredAction(target.instanceId, name);
    const requestId = 'req' + (++dispatchSerial);
    const p = new Promise((resolve, reject) => {
      pendingDispatches.set(requestId, { instanceId: target.instanceId, resolve, reject });
      target.iframe.contentWindow.postMessage({
        __nostrapps: 'napp-dispatch-action',
        requestId,
        idx: reg.idx,
        name,
        payload: params.payload,
      }, '*');
    });
    return p;
  }
  function settleDispatch(d, demuxedInstanceId) {
    const p = pendingDispatches.get(d.requestId);
    if (!p || p.instanceId !== demuxedInstanceId) return;
    pendingDispatches.delete(d.requestId);
    if (d.error != null) p.reject(new Error(String(d.error)));
    else p.resolve(d.result ?? null);
  }

  // ── launch flow ───────────────────────────────────────────────────────────
  function teardown() {
    for (const w of wins.values()) w.root.remove();
    wins.clear();
    registry.clear();
    pendingDispatches.clear();
    storeSubs.clear();
  }
  async function launchNapp(opts) {
    // opts: {nappId, nappDir, title, target, isVictim}
    const knobs = knobValues();
    if (knobs.atlauncher) {
      // THE MISTAKE: napp bytes served from the launcher's own origin,
      // sandboxed with allow-same-origin → the napp IS the launcher origin.
      const w = mount({
        nappId: opts.nappId, title: opts.title,
        origin: location.origin,
        src: '/napps/' + opts.nappDir + '/index.html',
        atLauncher: true, target: opts.target,
      });
      log('[launcher] mounted ' + opts.nappId + ' AT THE LAUNCHER ORIGIN (same-origin mistake): ' + location.origin + '/napps/' + opts.nappDir + '/index.html');
      if (!opts.isVictim) {
        try {
          const m = await fetch('/napps/' + opts.nappDir + '/metadata.json').then(r => r.json());
          renderCard(m);
        } catch (_) {}
      }
      await waitForReady(w.instanceId, 1500); // no bridge injected here: tolerate
      return w;
    }
    const label = await labelFor(opts.nappId, knobs.scheme);
    const origin = originForLabel(label);
    const { meta: m, files } = await fetchNappFiles(opts.nappDir);
    const policy = {
      domains: ['identity', 'network'],
      v: 2,
      referrer: knobs.referrer,
    };
    await bootNapp(opts.nappId, origin, files, policy);
    const w = mount({
      nappId: opts.nappId, title: opts.title || m.title,
      origin, src: origin + '/', atLauncher: false, target: opts.target,
    });
    w.policyDomains = policy.domains;
    log('[launcher] mounted ' + opts.nappId + ' at ' + origin + ' (label scheme: ' + knobs.scheme + ')');
    await waitForReady(w.instanceId, 8000);
    // the card renders AFTER the napp is ready: evil-02's payload calls back
    // into the napp, so the napp's listener must be up
    if (!opts.isVictim) renderCard(m);
    return w;
  }

  async function load() {
    persistKnobs();
    const knobs = knobValues();
    // The referrer a napp frame receives is governed by THIS page's policy —
    // full → the launcher URL and its share payloads leak into every napp.
    document.getElementById('referrerMeta').setAttribute('content',
      knobs.referrer === 'full' ? 'unsafe-url' : 'strict-origin-when-cross-origin');
    teardown();
    log('── load: preset=' + knobs.preset + ' scheme=' + knobs.scheme + ' atlauncher=' + knobs.atlauncher + ' victim=' + knobs.victim + ' referrer=' + knobs.referrer + ' render=' + knobs.render + ' lcsp=' + knobs.lcsp + ' router=' + knobs.router + ' prompts=' + knobs.prompts);

    let evilLaunched = false;
    if (knobs.victim) {
      // victim first: it must seed its origin's localStorage (and load) before
      // a naive-scheme collision can hand the evil napp the same origin.
      const victimId = knobs.scheme === 'naive' && !knobs.atlauncher
        ? String(knobs.napp).replace(/-/g, '~') // collide with the evil napp's label
        : 'victim';
      await launchNapp({
        nappId: victimId, nappDir: 'victim', title: 'Victim Notes', target: victimWinEl, isVictim: true,
      });
    }
    if (knobs.napp) {
      await launchNapp({ nappId: knobs.napp, nappDir: knobs.napp, target: evilWinEl });
      evilLaunched = true;
    }
    meta.textContent =
      'napp: ' + knobs.napp + (evilLaunched ? '' : ' (not loaded)') +
      ' · preset: ' + knobs.preset +
      ' · origin scheme: ' + knobs.scheme +
      ' · served at launcher origin: ' + (knobs.atlauncher ? 'YES (mistake armed)' : 'no') +
      ' · victim: ' + (knobs.victim ? 'open' : 'closed') +
      ' · referrer: ' + knobs.referrer +
      ' · metadata render: ' + (knobs.render === 'unsafe' ? 'innerHTML (UNSAFE)' : 'textContent (safe)') +
      ' · launcher CSP: ' + knobs.lcsp +
      ' · router: ' + knobs.router +
      ' · prompts: ' + knobs.prompts +
      (window.__navProbe ? ' · ⚠ NAVIGATED BY A NAPP (top-nav open)' : '');
    dumpStore();
  }

  // ── boot ──────────────────────────────────────────────────────────────────
  async function boot() {
    const saved = restoreKnobs();

    // The launcher-CSP knob is a real response header (set by the test
    // server) — sync the URL to it and reload once on a change.
    const wantStrict = saved.lcsp === 'strict';
    const params = new URLSearchParams(location.search);
    const haveStrict = params.get('lcsp') === 'strict';
    if (wantStrict !== haveStrict) {
      if (wantStrict) params.set('lcsp', 'strict');
      else params.delete('lcsp');
      const q = params.toString();
      location.replace(location.pathname + (q ? '?' + q : '') + location.hash);
      return;
    }

    try {
      const manifest = await fetch('/napps/manifest.json').then(r => r.json());
      for (const m of manifest) {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = m.title;
        nappSel.appendChild(opt);
      }
      if (saved.napp && [...nappSel.options].some(o => o.value === saved.napp)) nappSel.value = saved.napp;
    } catch (e) {
      log('manifest fetch failed: ' + e);
    }
    document.getElementById('loadBtn').addEventListener('click', () => { void load(); });
    void load();
  }
  void boot();
})();
