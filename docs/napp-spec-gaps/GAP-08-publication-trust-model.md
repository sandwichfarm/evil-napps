# GAP-08 — Unspecified publication trust model (manifest rollback / TOCTOU)

**Class:** security / malware (supply chain)
**Status:** validated — `evil-09-manifest-rollback` (end-to-end relay rollback, real signed manifests) + `evil-08-hardened-oracles` (in-frame TOCTOU)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1). The only gap in the inventory
that needed a new rung: the rollback was source-validated (evil-08) but not
demonstrated — now it is, end to end, through two mock relays serving **real
BIP340-signed kind 35130 manifests**.

## Spec text that leaves it open

NAPP.md, Runtime — the *entire* publication story:

> "A napp is an app published as kind `35130`."
> "The launcher serves published files through a service worker backed by
> local storage."

No author-binding rule, no selection algorithm, no signature requirement, no
content addressing for the napp identity, no pinning of what the user
approved. A conforming launcher is free to invent any — or no — trust model.

## The gap, two uncloseable halves

1. **Manifest rollback by relay withholding.** The reference's practice
   (`src/nsite/fetch.ts`) binds by author (`{kinds:[kind], authors:[pubkey],
   "#d":[dTag]}`, plus a client-side `e.pubkey === pubkey` filter — so id
   takeover is *held*) but selects `latest()`: **newest `created_at` wins
   from untrusted relays**. A relay that simply withholds the newest version
   serves a valid, signed, older one. **Validated end to end by evil-09**:
   with the withholding knob on, the harness's faithful `fetchManifest`
   miniature — author-bound, newest-wins, sha-verified files — installs the
   older signed manifest, and only the rung's own embedded version marker
   notices. No forgery anywhere: the spec run re-verifies every manifest's
   id and BIP340 signature.
2. **TOCTOU / no content-addressed napp identity.** The bytes the user
   approved are not the bytes that run next session: nothing in the protocol
   pins them (validated by evil-08's byte-swap: the relaunched frame detects
   a mid-session swap *only because that rung hashes its own metadata*).

## Why no launcher can close it

The spec defines no trust model to be perfect about. Even the hardened
reference — author-bound, signature-verified, file-hash-verified — cannot
distinguish "the newest manifest is v1" from "a relay is withholding v2":
withholding looks exactly like absence, and the protocol provides no
trusted newest-witness, no content-addressed pointer, no pin.

## Evidence

- `evil-09-manifest-rollback` (31 checks): the rollback demonstrated
  end-to-end against two mock relays with real signed manifests; the honest
  counterpoint machine-checked in the same rung — the hostile clone (the
  NEWEST manifest of all, by a different key, served by the hostile relay
  anyway) is dropped by the author binding, so id takeover is held while
  rollback arms.
- `evil-08-hardened-oracles`: the in-frame half — a mid-session byte swap is
  undetectable in-frame (no content addressing anywhere in NAPP.md).

## What would close it

A protocol change: content-addressed napp identity (the manifest's hash in
the pointer and the install record), install-time pinning, and a defined
manifest selection/verification algorithm — so "what the user approved" is a
durable fact instead of whatever relays serve next.
