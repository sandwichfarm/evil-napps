# NAPP spec gap inventory — impossible-to-close findings

Every gap below is a property of the **NAPP specification** (NAPP.md, kind
35130, the launcher bridge, actions, permissions, runtime) such that **even a
perfect launcher cannot close it** — it arms in the fully hardened preset.
Where a launcher *can* close a spec silence, the gap is **excluded** and listed
honestly at the bottom: the suite never overclaims.

Per-gap PRs live next to this file as `GAP-0N-<slug>.md`. Evidence citations
point at the validated rungs (`napps/evil-01`…`evil-08`, `tests/`, ROADMAP.md)
and at the reference launcher's source (eskema/nostrapps, read from
`main`: `src/nsite/fetch.ts`, `src/sandbox/host.ts`, `bridge.js`).

Classes follow the harm taxonomy: **exfiltration**, **privacy** (spyware),
**security**, **malware/spyware** (persistence & distribution).

| # | Gap | Class | Evidence | Deliverable |
|---|-----|-------|----------|-------------|
| GAP-01 | Cross-app store traffic analysis | privacy / spyware | evil-08 (validated, every preset) | docs PR |
| GAP-02 | Approval & presence oracle | privacy / spyware | evil-08 (validated, both directions) | docs PR |
| GAP-03 | Shared store = cross-app data exposure | privacy / exfiltration | evil-06 + evil-05 (validated chain) | docs PR |
| GAP-04 | Reads never prompt; filter-as-payload exfil channel | exfiltration / security | evil-06 (validated, NIP-50 payload) | docs PR |
| GAP-05 | One-time, unscoped authority grants | security / exfiltration | evil-06 (validated nip44 drop) | docs PR |
| GAP-06 | Unpoliced action namespace, unauthenticated results | security | evil-04 (validated round-trip) | docs PR |
| GAP-07 | Metadata impersonation | security (phishing) | evil-08 (validated, honest n/a) | docs PR |
| GAP-08 | Unspecified publication trust model (manifest rollback / TOCTOU) | security / malware | evil-08 (TOCTOU demo + source) — **relay rollback end-to-end not yet demonstrated** | new rung (evil-09) + PR |
| GAP-09 | No revocation or lifecycle semantics | malware / persistence | evil-07 (validated persistence) | docs PR |
| GAP-10 | Partitioned storage breaks the storage promise | privacy / persistence | evil-08 (validated nuance) | docs PR |

---

## GAP-01 — Cross-app store traffic analysis — privacy / spyware

**Spec text that leaves it open** (NAPP.md, Launcher bridge):

> `window.nostrdb.subscribe(filters) // async iterator … Every event saved to
> the store from now on that matches filters, one by one.`
> (napp-env.d.ts: "Every event saved to the store from now on that matches
> filters … What is already stored comes from query().")

> "Every event it brings is also saved to the store, where
> `nostrdb.subscribe` sees it." (napp.outbox; same wording for
> napp.sync and napp.utils.subscribe)

**The gap.** The store is launcher-wide by design, and *every* fetch path
auto-saves into it. Any app with `identity` can hold a broad subscription and
observe every event every other app inserts: counts, kinds, timing, senders,
content.

**Why no launcher can close it.** Closing it means splitting or muting the
store — but the shared store **is the protocol's data bus** (the spec hands
`query`/`count`/`event`/`subscribe` on "everything stored" to every app, and
every helper that fetches writes into it). A perfect launcher that keeps the
bridge as specified still fans each saved event to each matching subscription
(reference source: `notifyStoreSubs`).

**Evidence.** evil-08, row "Cross-app traffic analysis arms in every preset"
(validated from source + in Chromium; ROADMAP Tier 3).

**Closure requires a protocol change**, e.g. per-app store partitions with an
explicit cross-app sharing vocabulary, or delivery-scoped subscriptions.

## GAP-02 — Approval & presence oracle — privacy / spyware

**Spec text that leaves it open** (NAPP.md, Permissions):

> "The launcher asks for permission on first launch and stores the grant."

plus GAP-01's auto-save into the shared store.

**The gap.** Whether another app's gated publishes land in the store is a
readable signal: if they land unprompted, the policy is auto-allow; if they
land after delays, a human keeps clicking allow (a **presence** signal); if
its attempt echoes never land, prompts hold. The napp learns the answer
either way — and even a store split doesn't close it, because the user's
public writes are observable via `napp.sync`/`napp.outbox` anyway.

**Why no launcher can close it.** The signal is carried by events the
protocol already hands every app. Hiding it would mean hiding publishes
from the user's own other apps — a protocol change, not a launcher flag.

**Evidence.** evil-08, approval/presence oracle, validated in both
directions (auto-allow and prompt presets).

**Closure requires a protocol change** (per-app fetch namespaces; policy
outcomes not observable in the shared bus).

## GAP-03 — Shared store = cross-app data exposure — privacy / exfiltration

**Spec text that leaves it open** (NAPP.md, Launcher bridge):

> `window.nostrdb.query(filters)` / `count` / `event(id)` — no scoping
> qualifier anywhere.

> `window.napp.utils.loadDmRelays(pubkey) // kind 10050, NIP-17` — DM fetch
> paths exist, and "Every event is also saved to the store".

**The gap.** Everything any app fetches lands in a store every other app can
read wholesale: NIP-17 DM envelopes (ciphertext + correspondent metadata),
gift wraps, private-app content, other apps' working data. A second app reads
it all with `nostrdb.query` — no prompt, by design.

**Why no launcher can close it.** The store is shared by spec; read scoping
does not exist in the bridge vocabulary. A perfect launcher implementing the
bridge as specified exposes every saved event to every app.

**Evidence.** evil-06 validated the read half of this end to end (victim's
note read out of the shared store → encrypted to the attacker's key →
exfiltrated); evil-05 validated the write half (poisoned inserts land in what
every reader renders).

**Closure requires a protocol change** (per-app partitions / explicit
cross-app grant for reads) — same vocabulary GAP-01 needs.

## GAP-04 — Reads never prompt; filter-as-payload exfil channel — exfiltration / security

**Spec text that leaves it open** (NAPP.md, Permissions / Launcher bridge):

> "Clipboard access and file saving always prompt." — the only always-prompt
> rows; nothing else does.

> `window.napp.utils.subscribe(relays, filter, opts?) // a plain REQ to
> exactly these relays` — arbitrary relays, arbitrary filter, no prompt, and
> the `Filter` type carries `search` (NIP-50).

**The gap.** Any data an app holds can be encoded into a filter (a NIP-50
`search` term, an `#e` tag list) and delivered verbatim to any relay URL the
app names. The filter *is* the payload; the relay URL *is* the destination.
`utils.loadRelayInfo(url)` extends the same channel: the launcher itself
connects to an arbitrary URL the napp names (an internal-network reachability
oracle, same class).

**Why no launcher can close it.** Distinguishing "legitimate query" from
"exfiltration" is content inspection on arbitrary filters — impossible
without breaking the protocol's purpose (arbitrary relays and filters are the
feature). Per-call prompts with a raw filter dump are still unevaluatable by
users.

**Evidence.** evil-06: victim's note content carried in a NIP-50 search term
toward the attacker's relay, `RELAY-REQ` logged with the payload; reads never
prompt (validated across the prompt-policy space).

**Closure requires a protocol change** (destination-bound grants — the
vocabulary GAP-05 proposes).

## GAP-05 — One-time, unscoped authority grants — security / exfiltration

**Spec text that leaves it open** (NAPP.md, Development / Permissions):

> "`signEvent` comes with `write`, and `nip04`/`nip44` carry `encrypt` and
> `decrypt` as granted."

> "The launcher asks for permission on first launch and stores the grant. A
> row can be set to ask on every call."

**The gap.** The grant vocabulary is *domains only*. `encrypt` granted once
silently encrypts to **any** pubkey — including the attacker's — forever.
`write` signs and publishes **anything** toward **any** relays. "Ask on every
call" can surface the call, but the protocol has no recipient/destination
vocabulary to show: a prompt can only present an opaque hex pubkey the user
cannot evaluate.

**Why no launcher can close it.** The uncloseable core is grant-time
semantics: at first launch the user cannot know what the authority will be
used *for*, and the spec provides no binding (recipient key allowlists,
destination relays, content classes) that would make per-call prompts
meaningful.

**Evidence.** evil-06: the full nip44 private-data drop validated (store read
→ `nip44.encrypt` to attacker key through the user's own cipher authority →
publish toward attacker relays → exfil); the prompt-policy space mapped
(deny / prompt-with-latency-oracle / auto-allow silent signing).

**Closure requires a protocol change**: parameterized grants (recipient-key
sets, relay allowlists, per-call parameter display with name resolution).

## GAP-06 — Unpoliced action namespace, unauthenticated results — security

**Spec text that leaves it open** (NAPP.md, Actions):

> "There is no restriction on what actions are allowed"

> "A generic `view` whose event resolves is routed as `view:<kind-number>`,
> so the apps handling that kind are offered it alongside those handling
> `view`" — and the action table's "Returns" column: results flow back to
> callers.

**The gap.** Any app claims any action name (including generic `view`
collecting every resolved kind). Results round-trip into callers' code with
no attribution or authenticity the launcher could check — and even *with*
attribution the squatter genuinely produced the result; the caller has no
trust vocabulary to judge the handler.

**Why no launcher can close it.** Asking on ambiguity is launcher policy
(the reference does), but two claimants to `profile` are indistinguishable
(see GAP-07), sole-handler routing needs no question at all, and nothing in
the protocol can certify a result.

**Evidence.** evil-04: `"view"` wildcard collects every `view:<kind>`
dispatch (validated via `view:1`); sole-handler silent auto-pick (reference
policy, from source); poisoned action result received by the victim's own
callback (validated round-trip).

**Closure requires a protocol change** (handler identity surfaces, result
attribution tied to the identity vocabulary GAP-07 needs).

## GAP-07 — Metadata impersonation — security (phishing / spyware)

**Spec text that leaves it open** (NAPP.md, Local metadata):

> `title` — "Display name." / `icon` — "Icon URL or path." /
> `description` — "One-line card description."

> "The launcher asks for permission on first launch" — the prompt, the cards,
> the handler pickers are all rendered from these attacker-chosen bytes.

**The gap.** `relays` and `reIays` differ by nothing the protocol can check.
Titles, icons and descriptions are the *entire* identity surface a user gets,
and any app can claim any of it.

**Why no launcher can close it.** The protocol offers no identity signal
beyond the author pubkey (which users cannot evaluate), no verification, no
petname/allowlist vocabulary. A perfect launcher must render whatever the
metadata claims — that's what the metadata is *for*.

**Evidence.** evil-08: metadata impersonation probed as an honest in-frame
`n/a` (nothing to detect), lookalike pair shipped in the kit.

**Closure requires a protocol change** (publisher identity vocabulary:
verified authors, petnames, install-time pinning of what was approved).

## GAP-08 — Unspecified publication trust model (manifest rollback / TOCTOU) — security / malware

**Spec text that leaves it open** (NAPP.md, Runtime):

> "A napp is an app published as kind `35130`."
> "The launcher serves published files through a service worker backed by
> local storage."

That is the *entire* publication story. NAPP.md never says how a launcher
must select, verify, or pin a manifest — no author binding rule, no
signature requirement, no content addressing for the *napp identity*, no
pinning of what the user approved.

**The gap, two uncloseable halves.**
1. **Manifest rollback by relay withholding.** Reference practice
   (`src/nsite/fetch.ts`) binds by author (`{kinds:[kind], authors:[pubkey],
   "#d":[dTag]}`) but selects `latest()` — newest `created_at` wins from
   *untrusted* relays. A relay that simply withholds the newest version
   serves a valid, signed, older one. No launcher can detect withholding
   without a trusted newest-witness the protocol doesn't have.
2. **TOCTOU / no content-addressed napp identity.** The bytes the user
   approved are not the bytes that run next session: nothing in the protocol
   pins them. evil-08 demonstrated the swap; only the rung's *own* metadata
   hashing noticed.

**Why no launcher can close it.** The spec defines no trust model to be
perfect about. Even the hardened reference leaves half 1 open by design.

**Evidence.** evil-08 TOCTOU row (in-harness byte swap, validated); manifest
selection validated from source. **Not yet demonstrated end-to-end:** the
relay-withholding rollback — this gap gets a new probe rung (evil-09) that
stands up a mock relay serving an older signed manifest and proves the
launcher installs the old bytes.

**Closure requires a protocol change**: content-addressed napp identity
(manifest hash in the pointer/install record), install-time pinning, and a
defined manifest selection/verification algorithm.

## GAP-09 — No revocation or lifecycle semantics — malware / persistence

**Spec text that leaves it open** (NAPP.md):

> "Each napp has its own origin, so `localStorage` is its own."
> "The launcher asks for permission on first launch and stores the grant."

The spec's only deletion sentence is for `/dev`: "Closing the window erases
the napp's data." There is no uninstall, no eviction, no origin-wipe, no
grant-revocation lifecycle anywhere in NAPP.md.

**The gap.** A malicious app's durable per-origin state (storage, service
worker registration) outlives its card, its manifest, and the user's
decision, and grants never die. Malware keeps its beachhead; only `/dev`
apps are promised erasure.

**Why no launcher can close it.** The protocol defines no lifecycle
moment a perfect launcher could hook — "installed" has a meaning, "gone"
has none. Nothing tells a launcher it *should* wipe an origin, when, or
what "uninstall" even is.

**Evidence.** evil-07: per-origin markers survive launcher reloads
(validated); SW persistence channels mapped (the at-launcher SW variant is
the closeable misconfig — the durable own-origin state is the protocol gap).

**Closure requires a protocol change**: a lifecycle section (uninstall
semantics, origin wipe, grant revocation and re-prompting rules).

## GAP-10 — Partitioned storage breaks the storage promise — privacy / persistence

**Spec text that leaves it open** (NAPP.md):

> "Each napp has its own origin, so `localStorage` is its own."

**The gap.** Napp origins are third-party contexts: Chromium's partitioned
storage scopes the "own localStorage" per top-level site (and per tab, for
some storage), so the promise is weaker than the spec text — same-tab
persistence holds, cross-tab does not.

**Why no launcher can close it.** The launcher cannot un-partition the
browser's third-party storage. It can only document the reality the spec
currently misstates.

**Evidence.** evil-08 bonus nuance, validated both directions.

**Closure requires a protocol change** (spec text acknowledging partitioning
+ launcher guidance for first-party storage if durability is intended).

---

## Excluded — closeable by launcher policy (spec is silent, a hardened launcher closes)

Honest verdicts; the suite validates these as misconfig-armed, not
protocol-armed. Listed so nobody mistakes them for the set above.

| Spec silence | Closure | Evidence |
|---|---|---|
| Origin derivation unspecified | hash the whole id into the origin label | evil-01 r2 (`victim~one` ≡ `victim-one` collision; the reference retired its naive scheme) |
| Referrer policy unspecified | strict referrer policy on the launcher document | evil-01 r5 |
| Metadata fields rendered as HTML | `textContent`/element builders + strict CSP | evil-02 (reference holds by construction) |
| Bridge router identity checks | check `MessageEvent.source`, not origin/declared id alone | evil-03 (reference routers validated from source) |
| Boot-channel sender check | `event.origin === LAUNCHER` | evil-03 |
| Ungated `nostrdb.remove` | permission gate + prompt | evil-05 |
| SW registration slot | stub/unregister while locked | evil-07 (reference holds by stubbing) |
| Sandbox flags | no `allow-top-navigation`/`allow-popups` | evil-01 r3/r4 |

## Parked (noted, not PRed)

- `napp.dev.installLocal` (`dev` grant) as a persistence/install escalator —
  user-mediated at the permission screen; the uncloseable residue is GAP-07
  (the screen is impersonatable). Noted in evil-07.
- Self-keyed publishing (`utils.generateKey` + `signWithKey` + `publish`):
  apps can publish as their own keys — by design, no user authority involved;
  no gap claimed without evidence of an authority inversion.
- Registry relay hard-coding (`NAPP_RELAYS`): folds into GAP-08's rung —
  the mock-relay path is exactly where registry behavior gets exercised.

## Triage → PRs (verified against per-rung evidence)

Every "evidenced" mapping above was re-checked against the committed rung
docs (`napps/*/README.md`) before any PR was opened:

| Gap | Class | Verified evidence | Deliverable |
|---|---|---|---|
| GAP-01 | privacy/spyware | evil-08 `traffic-analysis` — arms in every preset | docs PR |
| GAP-02 | privacy/spyware | evil-08 approval/presence oracle — validated both directions | docs PR |
| GAP-03 | privacy/exfiltration | evil-06 nip44 chain (victim note read from store → encrypted to attacker key → exfil); evil-05 poison writes | docs PR |
| GAP-04 | exfiltration/security | evil-06 NIP-50 search-term payload to attacker relay (RELAY-REQ logged with payload) | docs PR |
| GAP-05 | security/exfiltration | evil-06 nip44 drop + the full prompt-policy space | docs PR |
| GAP-06 | security | evil-04 poisoned-result round-trip + `view` wildcard + sole-handler silent pick | docs PR |
| GAP-07 | security (phishing) | evil-08 metadata impersonation — honest in-frame n/a, lookalike pair in kit | docs PR |
| GAP-09 | malware/persistence | evil-07 markers survive launcher reloads; SW persistence map | docs PR |
| GAP-10 | privacy/persistence | evil-08 partitioned-storage nuance — same-tab holds, cross-tab does not | docs PR |
| GAP-08 | security/malware | evil-08 TOCTOU (in-harness byte swap) + source-validated newest-wins selection; **relay-withholding rollback NOT demonstrated** — the harness has no relay transport (its "mock relay" is bridge-level logging only) | **new rung `evil-09`** + PR |

**evil-09 design** (the only unevidenced gap): a minimal mock WebSocket relay
(node stdlib RFC6455 server under `tests/`), a faithful miniature of the
reference `fetchManifest` in the harness (author+d-bound REQ, newest
`created_at` wins), and a probe proving a relay withholding the newest
manifest makes the launcher install the older, valid, signed bytes.

**Honest n/a:** no inventoried gap failed the uncloseable test. Closeable
spec-silences sit in the Excluded table above; parked candidates (self-keyed
publishing, `installLocal`) stay parked.
