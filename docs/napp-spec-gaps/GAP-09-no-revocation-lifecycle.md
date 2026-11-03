# GAP-09 — No revocation or lifecycle semantics

**Class:** malware / persistence
**Status:** validated — `evil-07-persistence` (markers survive launcher reloads)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md:

> "Each napp has its own origin, so `localStorage` is its own."

> "The launcher asks for permission on first launch and stores the grant."

The spec's only deletion sentence is for `/dev`:

> "Closing the window erases the napp's data."

There is no uninstall, no eviction, no origin-wipe, no grant-revocation
lifecycle anywhere in NAPP.md.

## The gap

A malicious app's durable per-origin state — storage, service worker
registration — outlives its card, its manifest, and the user's decision.
Grants never die; nothing tells a launcher when or how an app's origin
should be wiped. Malware keeps its beachhead after the user "removes" it:
the origin persists, and a re-launch (share link, action dispatch) re-arms
it. Only `/dev` apps are promised erasure.

## Why no launcher can close it

The protocol defines no lifecycle moment a perfect launcher could hook:
"installed" has a meaning (permission grant, origin, storage), "gone" has
none. A launcher that invents a wipe policy is diverging from the spec, not
implementing it — and cross-launcher, users get inconsistent protection
with no norm to point at.

## Evidence

`evil-07-persistence`: per-origin markers survive launcher reloads
(validated, same tab); the SW persistence channels mapped (the
at-launcher-SW variant is the *closeable* misconfig — the durable
own-origin state is the protocol gap). See
`napps/evil-07-persistence/README.md`.

## What would close it

A protocol change: a lifecycle section in NAPP.md — uninstall semantics
(origin wipe: storage + SW + grants), grant revocation and re-prompting
rules, and what "removing an app" must mean across launchers.
