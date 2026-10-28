# evil-06 — signer abuse

**Tier 2 — authority abuse.** `window.nostr` is the NIP-07 bridge — the user's
signing and cipher authority — handed to every identity-granted napp with
"sensitive operations such as signing … prompt[ing] separately" (NAPP.md).
The prompt *is* the security boundary, and prompt quality is launcher policy:
one auto-allow setting (or one tired "allow always") makes every later call
silent. The cipher methods are a built-in private-data drop, and
`utils.subscribe` (reads never prompt) carries data out in the REQ itself.

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-06-signer-abuse/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `pk-handout` | pubkey handout via `getPublicKey` | the `identity` grant, no prompt | high |
| `silent-sign` | prompt-policy silent signing | `signEvent`'s only boundary is the prompt policy | critical |
| `nip-exfil` | cipher exfiltration — nip44 to the *attacker's* key | the user's own cipher authority as a private drop | critical |
| `relay-exfil` | relay-REQ exfiltration — data in the filter | `utils.subscribe` is ungated; the REQ travels verbatim | critical |

## Arming (harness knobs — the whole prompt-policy space)

- **deny-all** holds the gated channels; the pubkey handout and relay-REQ
  still arm (they are ungated by design).
- **prompt** is the reference policy: the dialog is *all* that stands — and
  its ~4s stale-dismissal is measurable from inside the napp (the latency is
  an oracle of the policy). The demo probes with a *cipher* call, never a
  signature: **no signature is ever produced in demo mode**.
- **auto-allow** makes everything silent: the gated probe resolves in
  single-digit milliseconds — exactly what signing will do.

## VERY EVIL

A loud marker note **signed as the user** (signature exfiltrated), the victim
store-note read out of the shared store, **encrypted to the attacker's pubkey
through the user's own bridge**, published toward attacker relays
(observable in the launcher's RELAY-PUBLISH log), the ciphertext exfiltrated —
and a REQ whose NIP-50 `search` field *is* the victim's private note content,
sent to the attacker's relay (RELAY-REQ log). No destructive payloads.

## Validate

```bash
node tests/evil-06.spec.mjs     # 22 checks, self-contained
```

Validated findings: [ROADMAP.md](../../ROADMAP.md).
