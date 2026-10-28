# evil-08 — hardened oracles

**Tier 3 — what even a perfect launcher can't stop.** These findings arm in
the fully hardened preset: they are findings against the NAPP *protocol*, not
any implementation. A perfect launcher holds every row here except the ones
that are protocol properties.

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-08-hardened-oracles/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `store-traffic` | cross-app traffic analysis via `nostrdb.subscribe` | the shared store is a broadcast channel (validated from source: `notifyStoreSubs` fans every saved event to every matching sub) | critical — **arms in every preset** |
| `policy-oracle` | approval/presence oracle — which of another app's gated calls land in the store | approval outcomes are observable from outside the dialog | high — **arms in every preset (with the noisy victim)** |
| `byte-swap` | unverified bytes (TOCTOU) — a mid-session byte swap is undetectable in-frame | no content addressing anywhere in NAPP.md; manifest selection is newest-wins from untrusted relays | critical |
| `name-squat-card` | metadata impersonation / typosquatting (`relays` vs `reIays`) | nothing binds a title or id to an author | info — honest `na` |

## Arming (harness knobs)

- The **hardened baseline** (default preset, victim open) already arms
  `store-traffic` — the store's broadcast behavior is a protocol property.
- **victimNoisy on** feeds the policy oracle: under **auto-allow** the
  victim's gated publishes *land* (auto-allow — or an approving human: a
  presence signal); under **prompt** its attempts (visible in its result
  echoes) never land — *the absence is the answer*, equally informative.
- **byte-swap**: first run records the served-metadata hash (`na`); the
  harness's debug control (`swap evil bytes + reload`) then changes the bytes
  underneath the napp — exactly what a hostile relay does in production — and
  the relaunched frame detects it *only because this rung hashes its own
  metadata*. Nothing in the protocol would.
- `name-squat-card` is an honest `na` in-frame (nothing to detect — the
  launcher renders whatever the metadata claims) with the lookalike pair in
  the attack kit.

## VERY EVIL

Holds a store subscription open and exfiltrates the cross-app traffic
profile (counts, kinds, samples), infers and exfiltrates the prompt policy,
and re-checks the byte hash. No destructive payloads.

## Validate

```bash
node tests/evil-08.spec.mjs     # 18 checks, self-contained
```

Validated findings, including the rollback-manifest kit entry and the
partitioned-storage nuance (a napp's "own localStorage" is scoped per launcher
tab in Chromium — same-tab persistence holds, cross-tab does not):
[ROADMAP.md](../../ROADMAP.md).
