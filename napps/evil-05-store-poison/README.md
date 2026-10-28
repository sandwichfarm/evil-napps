# evil-05 — store poison

**Tier 2 — shared state abuse.** `window.nostrdb` is the launcher-wide event
store NAPP.md hands every app. Validated from the reference source
(eskema/nostrapps, `src/sandbox/host.ts`): **`nostrdb.remove` deletes by id
with no permission gate and no author check** — any napp can censor any other
app's data out of the store the launcher itself reads. `add()` verifies
id+signature, but signature validity is not content safety.

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-05-store-poison/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `store-censor` | censor the shared store (remove another app's event) | `nostrdb.remove` — no gate, no author check | critical |
| `poison-add` | poison the shared store (crafted, legitimately-signed events) | `nostrdb.add` — attribution held, intent not | high |
| `store-wipe` | one `remove(allIds)` empties the launcher-wide store | the whole store is one call away | critical, **destructive** |

## Arming (harness knobs)

- **ungated removes (the reference behavior — the default) arm everything.**
  The censor demo removes and *immediately restores* the victim's event in one
  breath (the store's analog of the marker-key ROE clause); the spec asserts
  the store is intact afterwards.
- **gated removes (the `removegate` knob) + a prompt policy hold the censor
  and the wipe** — the dialog shows exactly what is being deleted and to whom
  it belongs. `poison-add` still arms: `add` is ungated by design, and the
  shared read is the blast radius either way.

## VERY EVIL

Real censorship (the victim's canary event deleted and verified gone), the
poison trio (a lookalike kind 0 metadata, an attacker kind 10002 relay list,
bait kind 1 content — all legitimately signed, all landing in what every store
reader renders), a full store dump exfiltrated — and the destructive
**store wipe** last: the launcher-wide store emptied for every app.

## Validate

```bash
node tests/evil-05.spec.mjs     # 15 checks, self-contained
```

Validated findings: [ROADMAP.md](../../ROADMAP.md).
