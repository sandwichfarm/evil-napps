# evil-04 — action squat

**Tier 1 — namespace squatting.** NAPP.md: "There is no restriction on what
actions are allowed." Action names (`profile`, `view`, `view:<kind>`, `feed`…)
are a global registry any installed app can claim any name in. The reference
launcher auto-picks the *sole* handler with no prompt (validated from source)
and asks only when the list is ambiguous — and an ambiguous list is a social
attack, not a security boundary.

This napp registers the victim's patterns (`profile`, `view`) at load and
records what arrives. Demo mode is passive: it only logs dispatches and
returns a clearly-labeled poisoned result (`handledBy: 'evil-04'`).

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-04-action-squat/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `name-squat` | profile name squat — dispatches and their payloads arrive at the squatter | the global action namespace | critical |
| `view-wildcard` | `"view"` matches every `view:<kind>` dispatch | NAPP.md's pattern wildcard rule | high |
| `result-poison` | poisoned action results round-trip into the caller's code | `napp.action` results are caller-trusted | high |

## Arming (harness knobs)

- **sole-auto (the reference policy) with the victim open is the green-ish
  gate** — the launcher *asks* on ambiguity and nothing is routed without an
  answer. But close the legit app and the squatter becomes the **sole
  handler: the launcher's own `profile` dispatch routes to it silently, no
  prompt** (the reference's auto-pick, validated).
- **first / newest pick policies hand the namespace over without any dialog**
  (newest = the last-mounted app wins every name it registers).
- Feed the probes with the launcher input bar (`dispatch profile`,
  `dispatch view:1`) or leave the victim open — it delegates `profile` every
  few seconds.

## VERY EVIL

Waits for the next `profile` / `view` dispatch, exfiltrates the **caller's
payload** (the victim's `VICTIM-DISPATCH-PAYLOAD` canary), and proves the
poisoned result round-trips into the victim's own callback. No destructive
payloads.

## Validate

```bash
node tests/evil-04.spec.mjs     # 16 checks, self-contained
```

Validated findings: [ROADMAP.md](../../ROADMAP.md).
