# evil-07 — persistence

**Tier 2 — origin durability.** NAPP.md: "Each napp has its own origin, so
`localStorage` is its own" — and a real origin is durable state: the
service-worker slot, IndexedDB, the Cache API, localStorage, all surviving
launcher reloads until a launcher-side wipe (launcher policy, not protocol).

The reference launcher holds the SW slot by **stubbing registration in
bridge.js** unconditionally, by `boot.html`'s `unregisterForeignSWs`, and by
`worker-src 'none'` while network-locked (all validated from source — three
launcher policies, zero protocol). This rung probes each.

This folder is the NAPP artifact: `index.html` + `metadata.json` plus
**`evil07-sw.js` — a real, committed service worker** (the VERY EVIL payload
registers it wherever the bytes are reachable). Built from
`src/napps/evil-07-persistence/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `sw-slot` | the origin's single service-worker slot | reference: stubbed in bridge.js | critical, **destructive** |
| `origin-persist` | per-origin storage survives the launcher | the origin grant is durable state | high |
| `caches-persist` | Cache API persistence | a durable origin store no permission system names | info |

## Arming (harness knobs)

- **SW stub on (the reference) is the green gate**: `register()` resolves with
  a fake registration — the probe's tell — and the slot stays owned by the
  launcher. The per-origin marker still survives a launcher reload (validated
  same-tab), and the Cache API is open by design.
- **SW stub off**: registration is attempted *for real* — only the missing
  bytes at the origin hold it (SW script fetches bypass the controlling
  worker; the napp's files live behind the launcher's SW).
- **at-launcher mistake**: the shipped `evil07-sw.js` is directly reachable at
  the launcher origin — registration succeeds and persists.

## ROE note specific to this rung

Demo mode registers **no real service worker** (the nonexistent-script probe
only observes the policy) but does write one documented localStorage marker
and one cache entry — persistence *is* the finding; wipe the app to clean
them.

## VERY EVIL

Registers the shipped service worker **at the launcher origin** (under the
at-launcher mistake), proves it serves its own bytes through its scope and
survives (`getRegistration`), and exfiltrates the origin's storage and cache
inventories. Destructive (a persisted worker) — runs last; the spec
unregisters it in cleanup.

## Validate

```bash
node tests/evil-07.spec.mjs     # 18 checks, self-contained
```

Validated findings: [ROADMAP.md](../../ROADMAP.md).
