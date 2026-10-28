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

### ✅ `evil-02-launcher-xss` — unsigned metadata rendered as HTML

Status: **built + validated** — 19/19 (`tests/evil-02.spec.mjs`)

`metadata.json` is attacker-controlled bytes (a local folder or an nsite the
launcher fetched from relays); NAPP.md never promises its fields are safe
HTML, and a launcher must put them into its own DOM somewhere — app cards,
permission prompts, handler pickers, window titles. The payloads live *in*
this napp's own metadata.json: the `description` carries an element-injection
implant (`<img src=x onerror=…>`), the `icon` an attribute-injection
breakout (`x" onerror="…"`). Each implant reports back to the napp over
postMessage and parks; demo mode does nothing else (validated: zero exfil
requests under the unsafe preset).

Validated results:

- **safe render (the reference behavior) holds every row** — and the card
  shows the payload as inert text, which is what a user of a safe launcher
  would actually see.
- **`innerHTML` render arms both vectors** — element injection (description)
  and attribute injection (icon) execute at the launcher origin and call
  back. Two independent vectors, one lesson: every metadata field needs the
  same treatment.
- **the launcher's own CSP is the last line of defense — validated**: with
  `script-src 'self'` (and the launcher's own script externalized, which the
  harness now models), the same unsafe render holds every payload. A CSP that
  still allows inline handlers is no defense at all.
- **VERY EVIL: what launcher-origin XSS buys, end to end** — the armed implant
  reads the permission-decision store and the launcher canaries, **forges an
  allow-always `signEvent` decision**, exfiltrates all of it, and the
  `silent-sign` row then signs a marker note through the bridge **with no
  prompt ever shown** (prompt counter: 0, prompts knob still on `prompt`).
  The bridge's entire permission model inverts: grants become attacker
  state.

Reference-launcher note (from source): nostrapps renders names and cards via
`textContent`/element builders; its only `innerHTML` feeds a fixed icon set
(`system-napps/ui.ts`) — the reference holds this rung by construction. The
knob exists because the protocol can't make anyone else hold it.

## Tier 1 — bridge confusion (lazy launchers)
## Tier 1 — bridge confusion (lazy launchers)

### ✅ `evil-03-bridge-forge` — envelope forging & reply injection

Status: **built + validated** — 18/18 (`tests/evil-03.spec.mjs`)

The bridge is `postMessage` with `'*'` targets; the only sender identity is `MessageEvent.source` and the sender's origin. Validated results:

- **a source-checked router (strict) holds every forged envelope** — a child frame's rpc claiming the victim's instanceId is dropped.
- **a declared-instanceId router accepts cross-app forges**: the same envelope executes bound to the VICTIM's window — and a gated call then opens a dialog titled *"victim wants to signEvent"*: the forge charges the victim's approval record (validated via the dialog title).
- **the reference router (origin + declared instanceId) never checks `MessageEvent.source`** (validated from source and reproduced): a same-origin srcdoc child of the napp — source ≠ any known window, origin = the napp's, declared instanceId = the napp's own — is accepted. Every frame at a napp's origin is every instance of that app: instance A can hijack instance B's dispatches, registrations and closes.
- **the reference bridge.js resolves `rpc-result` / `napp-sub-callback` by id/callbackId alone — no source check** (validated from source): a forged subscription callback posted straight to the victim's Window (any sibling, via `parent.frames`) injects attacker events into its live feed. **Arms in every preset** — a reference-bridge finding, below every router.
- **the boot channel's one check holds by default**: `event.origin === LAUNCHER` refuses the napp's commands. With it skipped (the knob), any napp sprays `napp-install` to the boot frames in the launcher's DOM and swaps any origin's bytes — VERY EVIL's read-back proves the takeover page is served at the victim's origin under the victim's window title.
- **NEW finding (validated + reproduced): the reference sw.js's ready-tag injection uses `result.indexOf("</html>")`** — string surgery on napp bytes. A napp whose script contains that literal sequence gets its main script split mid-parse by the injected tag (this suite's own payload tripped it). Launcher fix: parse-based injection, not string surgery.

### ✅ `evil-04-action-squat` — `registerAction` namespace squatting

Status: **built + validated** — 16/16 (`tests/evil-04.spec.mjs`)

NAPP.md: "There is no policing of what actions are allowed." Validated:

- **sole-auto (the reference policy) asks on ambiguity** — the picker opened and nothing was routed without an answer. But close the legit app and the squatter becomes the SOLE handler: the launcher's own `profile` dispatch routes to it **silently, no prompt** (validated — the reference's auto-pick, from source). Ambiguity is a social attack, not a boundary.
- **silent pick policies (first/newest) hand the namespace over without a dialog** (newest = the last-mounted app wins every name it registers).
- **the `"view"` wildcard matches every `view:<kind>` dispatch** — one registered string collects all of them (validated via `view:1`).
- **poisoned results round-trip into the caller's code**: the victim dispatched `profile`, the squatter answered, and the victim's own callback received the attacker's object as the action result.

## Tier 2 — shared state & authority abuse

### ✅ `evil-05-store-poison` — `nostrdb` poisoning

Status: **built + validated** — 15/15 (`tests/evil-05.spec.mjs`)

`window.nostrdb` is a launcher-wide store shared by every app. Validated:

- **the reference's `nostrdb.remove` deletes by id with no permission gate and no author check** (validated from source): the demo removes and immediately restores the victim's event in one breath — cross-app censorship of the shared store, with the bridge's own blessing. A gated remove (the knob) + a prompt policy holds it.
- **`add()` holds attribution, not intent** (id+sig verified — forged attribution is held): the poison is legitimately-signed attacker content — a lookalike kind 0, an attacker kind 10002 relay list, bait in kind 1 — all landing in what every store reader renders.
- **one `remove(allIds)` wipes the launcher-wide store** for every app at once (VERY EVIL, destructive payload, runs last — validated empty).

### ✅ `evil-06-signer-abuse` — silent signing & cipher exfiltration

Status: **built + validated** — 22/22 (`tests/evil-06.spec.mjs`)

The NIP-07 bridge's only boundary is the launcher's prompt policy. Validated across the whole policy space:

- **pubkey handout** arms with the `identity` grant — no prompt, by design.
- **deny-all holds; prompt = the dialog is all that stands** (its ~4s stale-dismissal is measurable from inside the napp — the latency is an oracle of the policy); **auto-allow = silent signing**: a marker note signed as the user, zero prompts, zero latency.
- **nip44.encrypt to the attacker's key is a private-data drop**: the full chain validated — the victim's note read out of the shared store, encrypted to the attacker's pubkey through the user's own cipher authority, published toward attacker relays (RELAY-PUBLISH logged), ciphertext exfiltrated. The user's bridge did all the work.
- **`utils.subscribe` never prompts (reads don't) and the REQ's filter travels verbatim**: the victim's note content carried out in a NIP-50 search term toward the attacker's relay (RELAY-REQ logged with the payload).

### ✅ `evil-07-persistence` — service-worker & origin persistence

Status: **built + validated** — 18/18 (`tests/evil-07.spec.mjs`)

Each napp owns a real origin — durable state the protocol never mentions wiping. Validated:

- **the reference holds the SW slot by STUBBING registration in bridge.js** (validated from source: unconditional stub + boot.html `unregisterForeignSWs` + `worker-src 'none'` while locked). Stubbed: `register()` resolves with a fake registration — the tell the probe uses.
- **unstubbed, registration is attempted for real** — only the missing bytes at the origin hold it (SW script fetches bypass the controlling worker).
- **under the at-launcher mistake the shipped, committed SW registers at the LAUNCHER origin**: a live persistent worker in the launcher's own origin, serving its own bytes through its scope (validated end-to-end: registration, scope, served-by-evil-SW response, `getRegistration`).
- **per-origin storage survives a launcher reload** (same tab — validated); the Cache API is a durable origin store no permission system names.
- **nuance**: `napp.dev.installLocal` (the `dev` grant) remains an unprobed persistence escalator — deferred.

## Tier 3 — well-hardened launchers (protocol-level)

What even a perfect launcher cannot stop. These arm in the fully hardened preset — findings against the NAPP protocol, not the implementation.

### ✅ `evil-08-hardened-oracles` — what a perfect launcher can't stop

Status: **built + validated** — 18/18 (`tests/evil-08.spec.mjs`)

- **Cross-app traffic analysis arms in every preset** (protocol property, validated from source: `notifyStoreSubs` fans every saved event to every matching subscription, whatever saved it): a plain `nostrdb.subscribe` profiles what every app inserts — counts, kinds, samples — no launcher can close it without splitting the store NAPP.md hands out.
- **The approval/presence oracle reads the policy off the store**: if another app's gated publishes land, the launcher auto-allows (or a human keeps clicking allow — a presence signal); if its attempts (visible in its result echoes) never land, prompts hold. Either way the napp learns the answer — validated in both directions (auto-allow and prompt).
- **TOCTOU / unverified bytes, demonstrated**: the harness's debug control re-installs modified bytes mid-session and reloads the window — the relaunched frame detects the change ONLY because this rung hashes its own metadata; nothing in the protocol would. No content addressing anywhere in NAPP.md; manifest selection is newest-`created_at`-wins from untrusted relays (the reference's `fetchManifest`), so a relay withholding the newest version serves a valid, signed, older one; file hashes are launcher practice, not protocol.
- **Metadata impersonation is an honest `na` in-frame** (nothing to detect — the launcher renders whatever the metadata claims) with the lookalike pair in the kit: `relays`/`reIays` differ by nothing the protocol can check.
- **Bonus nuance validated**: Chromium's partitioned third-party storage scopes a napp's "own localStorage" per launcher tab — the persistence promise is weaker across multiple launcher tabs than NAPP.md implies (same-tab persistence holds; cross-tab does not).
- **Deferred**: registry/discovery spoofing end-to-end (the reference's hard-coded `NAPP_RELAYS`) — the mock-relay plumbing exists in the harness for a future rung; the rollback manifest is in the kit.
