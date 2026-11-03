# GAP-07 — Metadata impersonation

**Class:** security (phishing) / spyware
**Status:** validated — `evil-08-hardened-oracles` (honest in-frame n/a; lookalike pair in kit)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Local metadata:

> `title` — "Display name." / `icon` — "Icon URL or path." /
> `description` — "One-line card description."

NAPP.md, Permissions:

> "The launcher asks for permission on first launch" — the prompt, the app
> cards, the handler pickers are all rendered from these bytes.

## The gap

`relays` and `reIays` differ by nothing the protocol can check. Titles,
icons and descriptions are attacker-chosen display bytes, and they are the
*entire* identity surface a user gets: the permission prompt ("**Relays**
wants to sign events"), the card, the handler picker. Any app can claim any
name, any icon, any description — including a well-known app's.

## Why no launcher can close it

The protocol offers no identity signal beyond the author pubkey (which
users cannot evaluate — 64 hex chars), no verification mark, no petname or
allowlist vocabulary. A perfect launcher must render whatever the metadata
claims: that is what the metadata is *for*. The `n/a` is honest — there is
nothing in-frame to detect.

## Evidence

`evil-08-hardened-oracles`: metadata impersonation probed as an honest
in-frame `n/a` (nothing to detect — the launcher renders whatever the
metadata claims), with the lookalike pair shipped in the kit
(`relays`/`reIays`). See `napps/evil-08-hardened-oracles/README.md`.

## What would close it

A protocol change: a publisher identity vocabulary — verified authors,
user-assigned petnames, and install-time pinning of what was approved
(manifest hash + name together), so a later lookalike cannot silently reuse
a trusted surface. No launcher flag can do it.
