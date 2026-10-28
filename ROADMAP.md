# Attack ladder — evil napps

Ordered from lowest hanging fruit (misconfigured / lazy launchers) to the most
nuanced (assaults on well-hardened launchers, and on what the NAPP protocol
itself does not specify). One napp per rung, validated against real Chromium
(`tests/`). Each rung names the surface it attacks, what arms it, and what
validation proved.

Protocol sources read for this ladder: [NAPP.md] (kind 35130, the launcher
bridge, actions, permissions, runtime), [napp-env.d.ts], and the reference
launcher implementation (eskema/nostrapps: `bridge.js`, `sw.js`, `boot.html`,
`src/sandbox/host.ts`, `src/sandbox/napp-window.ts`, `src/handlers.ts`,
`src/store.ts`, `src/nsite/fetch.ts`).

[NAPP.md]: https://github.com/eskema/nostrapps/blob/main/NAPP.md
[napp-env.d.ts]: https://github.com/eskema/nostrapps/blob/main/napp-env.d.ts

## Tier 0 — launcher misconfig (poorly implemented launchers)

These land whenever a launcher gets an isolation *must* wrong. A
well-implemented launcher passes every probe; the evil napp's job is to show
what each mistake costs, with a real payload behind the gate.

### ✅ `evil-01-frame-escape` — frame & origin isolation

Status: **built + validated** — 38/38 (`tests/evil-01.spec.mjs`)

NAPP.md says each napp runs at its own origin in a sandboxed iframe, that
`window.parent` is cross-origin, and that "the bridge is its only channel to
the launcher." None of that is enforced by the protocol — it is all launcher
policy. Probes (validated results vs the harness's faithful `napp` preset):

| # | Attack | Arming misconfig | Validated result |
|---|--------|------------------|-------------------|
| 1 | Launcher-origin equivalence — read the launcher's DOM | serving napp bytes from the launcher's own origin with `allow-same-origin` | held under the `napp` preset; armed by the **serve-at-launcher-origin** knob — full parent DOM, launcher `localStorage` (permission grants!). VERY EVIL: canary `nsec` + grant record exfiltrated, launcher DOM defaced |
| 2 | Cross-napp origin collision — read another app's persisted secrets | origin label derived from a naive slug of the nappId | held under the **hashed** scheme (readable head + 48-bit hash of the whole id); armed by the **naive** scheme — `evil-01-frame-escape` and `evil~01~frame~escape` slug to one origin, and the victim's `localStorage` secret is readable (exfiltrated in VERY EVIL). The reference *retired* exactly this scheme (`a~b`/`a-b` collided) — the protocol still doesn't specify origin derivation |
| 3 | Ancestor navigation — shell hijack | `allow-top-navigation`, or a missing `sandbox` attr | held under the `napp` preset; armed by the **top-nav** and **no-sandbox** knobs, and validated end-to-end: the probe navigates the launcher to its own URL with a `?evil01nav=1` marker (query param — referrers never carry fragments), the launcher reloads, and the relaunched frame reports ARMED without navigating again (no loop). The destructive payload (hijack to collector) runs last |
| 4 | Popup escape — `window.open` | `allow-popups` | held under the `napp` preset (reference sandbox has no `allow-popups`); armed by the **popups** knob. **Nuance validated:** `allow-popups` *exempts* a frame from the browser's user-activation popup blocker — a sandboxed `allow-popups` frame can open popups without a gesture where even an unsandboxed frame cannot |
| 5 | Referrer leak — `document.referrer` carries the launcher URL | the *embedding page's* referrer policy (not the napp's response headers) | origin-only under the default `strict-origin-when-cross-origin`; armed by the **full-url** knob — the share-link payload in the launcher's query string lands in every napp's referrer. **Architectural note validated:** the referrer a napp iframe receives is governed by the launcher document's policy; headers on the napp's own response govern only what the *napp* sends onward. NAPP.md is silent on referrer policy |
| 6 | Frame census — `parent.length` + sibling scriptability | always readable cross-origin (count); scriptable only under origin mistakes | armed-by-spec-gap in every preset: the napp counts the launcher's frames (hidden boot frames included) from any origin. **Refinement validated:** the launcher's own boot frames live at the napp's origin, so they are scriptable by the napp *by design* — the boot channel must therefore sender-check (evil-03's target). Sibling *napps* become scriptable only under the same-origin/collision misconfigs |
| 7 | Per-origin storage granted (by design) | — | **by design** (NAPP.md: "Each napp has its own origin, so localStorage is its own") — the demo proves the persistence channel (marker written + cleaned) that `evil-07` weaponizes; an armed `info` row, not a misconfig |

Findings against the *reference* launcher, from reading its source
(no run-time exploit claimed):

- The reference sandbox (`allow-scripts allow-same-origin allow-forms`) holds
  top-navigation and popups. `allow-same-origin` is safe there **only because**
  each napp gets a unique hashed origin — origin derivation is the load-bearing
  wall, and it is launcher policy, not protocol.
- The reference's *retired* origin scheme is the tier-0 collision demo: the
  code comment in `src/sandbox/host.ts` documents that `a~b` and `a-b`
  sanitized to one label and served each other's files. Any launcher that
  slugs instead of hashing walks into this today.

### `evil-02-launcher-xss` — unsigned metadata rendered as HTML *(planned)*

`metadata.json` is attacker-controlled bytes (a local folder or an nsite the
launcher fetched). Probes: `title`/`description` rendered via `innerHTML` in
the launcher origin (the card list, the permission prompt, the handler
picker), icon URLs as injection vectors, and the launcher's own CSP as the
last line of defense. Evil payload: launcher-origin XSS → read the permission
grant store, forge grants, deface, exfil.

## Tier 1 — bridge confusion (lazy launchers)

### `evil-03-bridge-forge` — envelope forging & reply injection *(planned)*

The bridge is `postMessage` with `'*'` target origins; the only sender
identity is `MessageEvent.source` and the napp's origin. Probes: forged
`__nostrapps` envelopes with declared `instanceId` (the reference demuxes by
`origin + data.instanceId`, so *any frame at the napp origin* can impersonate
*any instance of that app* — validated from source: `napp-window.ts`'s
`messageHandler` checks `event.origin === origin && data.instanceId ===
instanceId`, never `event.source`); sequential-id reply injection; dispatch
result forgery (`napp-dispatch-result` settles the caller's promise with
attacker data); boot-frame command forgery (`napp-install`/`napp-wipe` posted
to the hidden boot iframe — the reference checks `event.origin === LAUNCHER`
in `boot.html`, a launcher that doesn't is one postMessage from a file swap).

### `evil-04-action-squat` — `registerAction` namespace squatting *(planned)*

NAPP.md: "There is no policing of what actions are allowed." Action names are
a global namespace any installed app can claim: `profile`, `view`, `view:1`,
`user-search`… Probes: registering the names a victim app dispatches to,
auto-pick policies (the reference auto-selects the sole handler with no
prompt — squatting `profile` receives the launcher's own profile dispatches),
pattern rules (`"view"` matches `view:<any>`), and auxiliary/headless modes.

## Tier 2 — shared state & authority abuse

### `evil-05-store-poison` — `nostrdb` poisoning *(planned)*

`window.nostrdb` is a launcher-wide store shared by every app. Probes:
`nostrdb.remove` censoring other apps' data — validated from source: the
reference's `nostrdb.remove` handler deletes by id with **no permission gate
and no author check** (`GATED_METHODS` doesn't list it) — any napp can
`query()` then `remove()` every event it dislikes; `add()` with crafted
well-signed-but-attacker-owned events (kind confusion for every app that reads
the store); `replaceable()` shadowing.

### `evil-06-signer-abuse` — silent signing & cipher exfiltration *(planned)*

The NIP-07 bridge hands the app the user's signing authority behind a
permission *prompt* — prompt quality is launcher policy. Probes: signEvent
without a meaningful prompt (auto-allow knobs, "allow always" residue), the
approval-detail fidelity (can the napp name one thing and sign another —
`created_at`/tag mutation between display and dispatch is TOCTOU the launcher
can't see), nip04/nip44 encrypt *to the attacker's pubkey* as a private-data
egress channel, and `utils.publish` to attacker relays as the drop point.

### `evil-07-persistence` — service-worker & origin persistence *(planned)*

Each napp owns a real origin forever: per-origin `localStorage`, IndexedDB,
and a service-worker slot (the reference's `sw.js` owns it and `bridge.js`
stubs `serviceWorker.register` — a launcher that doesn't stub, or whose origin
isn't SW-owned, hands the napp a persistent same-origin backdoor; the
reference's own `boot.html` `unregisterForeignSWs` exists precisely because a
napp *can* register one while `network` is granted). Probes: SW registration,
`caches` persistence, marker survival across launcher reloads, and
`napp.dev.installLocal` (the `dev` grant) as a persistence escalator.

## Tier 3 — well-hardened launchers (protocol-level)

What even a perfect launcher cannot stop. These arm in the fully hardened
preset — they are findings against the NAPP protocol, not the implementation.

### `evil-08-hardened-oracles` — what a perfect launcher can't stop *(planned)*

- **Cross-app traffic analysis:** `nostrdb.subscribe` observes every event
  *any* app inserts into the shared store (validated from source:
  `notifyStoreSubs` fans every saved event to every matching subscription,
  whatever saved it) — a napp learns what other apps fetch, sync and publish.
- **Signing-latency oracles:** timing `signEvent` approvals distinguishes
  prompt-types, "always" residue, and the user's presence — an activity
  oracle no prompt design fully closes.
- **TOCTOU of URL-hosted apps:** a napp is bytes fetched by manifest every
  load; there is no content addressing *in the protocol* (the reference
  hashes each blob against its manifest's `path` tags, but manifest selection
  is "newest `created_at` wins" from untrusted relays — rollback and
  withholding are relay policy, and any pinning is launcher policy).
- **Metadata impersonation / typosquatting:** `metadata.json` `id` → `d` tag
  → origin label; nothing binds a `title` to an author, so `Relays` by
  attacker and `relays` by victim are indistinguishable cards.
- **Registry/discovery spoofing:** discovery relays (`relay.nostrapps.com`
  is hard-coded in the reference's `NAPP_RELAYS`) decide which manifests
  exist; a hostile relay can seed look-alike manifests or withhold the
  newest one.
