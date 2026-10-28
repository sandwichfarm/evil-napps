# evil-napps

**A NAPP (eskema/nostrapps) red team.** A suite of deliberately hostile NAPP
apps whose job is to break out of — or prove the integrity of — NAPP launchers
(nostrapps-style hosts that hand each app a bridge of real authority). Every
napp here is a legitimate, spec-shaped NAPP artifact (`metadata.json` +
`index.html`, its own origin, sandboxed iframe, service-worker file serving)
that attacks its launcher the way a real adversary would, so launcher authors
can find and fix their gaps *before* an adversary does.

The NAPP trust model is nearly the inverse of NIP-5D's: the launcher hands the
app real authority up front — `window.nostr` (NIP-07 signing/encrypt bridge),
`window.nostrdb` (a launcher-wide event store shared by every app),
`napp.registerAction` (cross-app action dispatch), `utils.*` (direct relay
subscriptions, publishing), per-origin `localStorage`, and service workers.
The ladder therefore starts at misconfigured launchers and climbs to what
even a perfect launcher cannot stop.

Each napp targets one attack class, ordered from the lowest-hanging fruit
(misconfigured or lazy launchers) up to attacks inherent to the protocol
itself (hardened launchers). See [ROADMAP.md](ROADMAP.md).

## Rules of engagement

**Demo by default.** A loaded evil napp only *probes* and *reports*. It proves
each attack primitive is available — with masked, non-actionable evidence —
and then stops:

- no writes outside its own frame (demo mode may write one immediately-cleaned
  marker key to its own origin, nothing more)
- no network egress (no fetch, no WebSocket, no beacons, no popups)
- no signing, no dispatch, no store mutation, no persistence, no destruction
- one documented exception: a probe that *must* navigate to detect
  (ancestor-navigation permission) navigates the launcher to **its own current
  URL** with a marker query param — reversible, nothing leaves the launcher's
  URL (query params, unlike fragments, survive into referrers, so the relaunched
  frame can confirm the navigation without ever repeating it)

**"VERY EVIL" mode.** Each napp can be armed from inside the napp. Arming
requires a stern confirmation dialog that lists **every armed attack and
exactly what executing it will do** — payload, destination, and destructive
consequences — and a typed confirmation (`EXECUTE EVIL`, case-sensitive). Only
after that does it actually execute the evil payloads, in a safe order
(destructive payloads last), logging what happened as evidence.

Default exfiltration destination is `https://evil.example.invalid/collect` — a
non-resolving RFC-2606 host. Even in VERY EVIL mode nothing leaves the
machine; operators point it at their own collector to test real egress.

**Not a weapon.** These are QA tools for launcher authors. The evil payloads
are deliberately loud (marker keys, marker notes, visible defacement banner)
rather than quiet. They demonstrate harm; they don't optimize for it.

**Honest verdicts.** A probe that cannot prove a primitive reports `n/a` with
the reason — the suite never overclaims. Findings against the *reference
launcher* (eskema/nostrapps) are validated by reading its source and are
marked as such in [ROADMAP.md](ROADMAP.md).

## The ladder

| Tier | Target | Napps |
|------|--------|-------|
| 0 | Launcher misconfig — iframe sandbox/origin mistakes, unsigned `metadata.json` rendered as HTML, unvalidated action routing, missing launcher CSP | `evil-01` frame escape ✅, `evil-02` launcher XSS ✅ |
| 1 | Bridge confusion — forged postMessage envelopes, reply injection, `registerAction` namespace squatting | `evil-03` bridge forge, `evil-04` action squat |
| 2 | Shared state & authority abuse — `nostrdb` poisoning, silent signing, nip04/nip44 exfil, direct-relay egress, service-worker persistence | `evil-05` store poison, `evil-06` signer abuse, `evil-07` persistence |
| 3 | Well-hardened launchers — what even a perfect launcher can't stop: cross-app traffic analysis, signing-latency oracles, URL-hosted TOCTOU, metadata impersonation, registry spoofing | `evil-08` hardened oracles |

Each rung is a self-contained NAPP artifact folder
(`napps/<id>/{index.html,metadata.json}`) you can install into **any** NAPP
launcher, or into the included victim harness. Artifacts are built from
`src/` (shared chrome + per-napp attack definitions) via `node build.mjs`.

## Running locally

```bash
node build.mjs                        # build napps/<id>/ from src/
node tests/evil-01.spec.mjs           # self-contained: starts its own server + Chromium
node tests/evil-02.spec.mjs
node tests/_server.mjs 8899            # or serve manually → http://localhost:8899/harness/
```

The specs spin up their own static server (`tests/_server.mjs` — node, not
python, because rungs need per-request header control, e.g. the launcher-CSP
knob serving `script-src 'self'` on the harness page).

The [harness](harness/index.html) is a deliberately misconfigurable victim
launcher — a faithful miniature of the reference architecture (per-origin
`<label>.localhost` subdomains, hidden `boot.html` iframe registering a
service worker, files served from per-origin IndexedDB, `bridge.js` injected
into the app's HTML, `window.name` instance ids). Every knob re-arms a
different subset of the attacks:

- **sandbox preset** — `napp` (`allow-scripts allow-same-origin allow-forms`,
  the reference baseline), `no-sandbox`, `top-nav` (+`allow-top-navigation`),
  `popups` (+`allow-popups allow-modals`) — arms the evil-01 escape tree.
- **serve at launcher origin** — the lazy-launcher mistake: the napp's bytes
  are served from the launcher's own origin (same-origin escape, scriptable
  siblings).
- **origin scheme** — `hashed` (readable head + hash of the whole nappId, the
  reference's collision-proof scheme) vs `naive` (slug of the id, the
  reference's *retired* scheme — `victim-one` and `victim~one` collide into
  one origin, cross-napp storage and file theft).
- **victim napp** — opens a benign victim app beside the evil one (seeds
  per-origin secrets, registers actions) — arms cross-napp probes.
- **referrer policy** — `strict` (default: origin only) vs `full-url` (the
  launcher URL and its share-link payloads leak into every napp's
  `document.referrer`).
- **metadata render** — `safe` (textContent — the reference behavior) vs
  `unsafe` (innerHTML — a launcher card rendering unsigned `metadata.json`
  bytes as HTML in the launcher origin) — arms evil-02's XSS tree.
- **launcher CSP** — `none` (no header — common) vs `strict`
  (`script-src 'self'`, the last line of defense; the harness's own script is
  externalized so a hardened launcher keeps working) — the green gate under
  an unsafe render.
- **router discipline / prompts** — message-demux policy (strict source-check
  vs the reference's origin+declared-instanceId vs declared-only) and the
  permission-prompt policy — exercised by the tier 1–2 rungs.

Later rungs add knobs for the bridge surface they attack (boot-channel sender
checks, store mutation gates, registry/manifest behavior).

It also seeds launcher canaries (fake `nsec` and grant records in launcher
`localStorage`), logs every ACCEPTED/DROPPED bridge message, and dumps the
launcher store. The **`napp` preset + `hashed` origins + strict referrer is the
green gate** your launcher's CI should hold.

## Repo layout

```
build.mjs                             # assembles src → napps/<id>/
src/
  chrome.template.html                # shared napp chrome: probes UI, arm gate, report
  napps/<id>/{attacks.js,meta.json}   # the ONLY per-napp code
napps/
  <id>/{index.html,metadata.json}     # built single-folder NAPP artifacts (committed)
  victim/{index.html,metadata.json}   # static benign victim app (harness fixture)
boot.html                             # per-origin boot frame (SW registration + IDB install)
sw.js                                 # per-origin service worker (file serving, bridge injection)
bridge.js                             # the NAPP bridge injected into napps
harness/
  index.html + index.js               # configurable victim launcher (externalized script
                                      #   so the strict-CSP knob can hold inline handlers)
tests/
  _server.mjs                        # node static server with per-request header control
  _helper.mjs + evil-NN.spec.mjs      # Playwright checks vs real Chromium
ROADMAP.md                            # attack ladder + validated NAPP protocol findings
```

Evil napps use their own dark palette (a red-team tool must stay legible even
in a hostile launcher) and otherwise stay small, quiet and legible at any
window size.
