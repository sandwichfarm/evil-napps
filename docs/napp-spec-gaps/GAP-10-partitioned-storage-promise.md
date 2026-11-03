# GAP-10 — Partitioned storage breaks the storage promise

**Class:** privacy / persistence
**Status:** validated — `evil-08-hardened-oracles` (same-tab holds, cross-tab does not)
**Closable by launcher policy:** no — the browser's partitioning is not launcher-removable

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md:

> "Each napp has its own origin, so `localStorage` is its own."

## The gap

Napp origins are third-party contexts: Chromium's partitioned storage
scopes the "own localStorage" per top-level site (and per tab, for some
storage), so the promise is weaker than the spec text. Same-tab persistence
holds; **cross-tab does not** — and a launcher run at two origins (or a user
with the launcher open twice) hands the "same" napp two disjoint storage
partitions.

## Why no launcher can close it

The launcher cannot un-partition the browser's third-party storage — that
is a browser property, not launcher policy. The launcher can only know the
truth, and the spec currently misstates it: apps that rely on the promise
(remember-me state, cursors, caches) silently lose data, and security
reasoning built on "the app's storage is its own durable origin" is built on
sand.

## Evidence

`evil-08-hardened-oracles`, partitioned-storage nuance, validated both
directions: the marker survives a launcher reload in the same tab; a fresh
launcher tab gets a fresh partitioned store. See
`napps/evil-08-hardened-oracles/README.md`.

## What would close it

A protocol change: spec text acknowledging partitioned storage (what
"its own storage" actually means cross-tab/cross-site), plus launcher
guidance if durability is intended (first-party storage or explicit
bridge-managed state). The browser behavior itself cannot be closed.
