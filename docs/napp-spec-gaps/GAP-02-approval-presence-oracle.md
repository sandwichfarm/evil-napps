# GAP-02 — Approval & presence oracle

**Class:** privacy / spyware
**Status:** validated — `evil-08-hardened-oracles` (both directions)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Permissions:

> "The launcher asks for permission on first launch and stores the grant."

combined with GAP-01's auto-save: everything any app publishes or fetches
lands in the shared store, where any app can watch it.

## The gap

Whether another app's gated publishes land is a readable signal:

- landed unprompted → the policy is **auto-allow**;
- landed after delays → a human keeps clicking allow — a **presence**
  signal (someone is at the keyboard, and how attentive they are);
- its attempt echoes never land → prompts hold.

The napp learns the answer either way. This is a surveillance primitive:
from inside its frame, a hostile app can tell whether the user is watching,
and how much scrutiny future attacks will face.

## Why no launcher can close it

The signal is carried by events the protocol already hands every app. Even
splitting the store (GAP-01's closure) does not close it: the user's public
writes are observable via `napp.sync`/`napp.outbox` regardless, so an
attacker app can still detect "the user signed something via another app
just now". Hiding publish outcomes from the user's own other apps is a
protocol change, not a launcher flag.

## Evidence

`evil-08-hardened-oracles`, approval/presence oracle row — validated in
**both directions**: under auto-allow the policy reads straight off the
store; under prompt, another app's publishes never landing is the answer.
See `napps/evil-08-hardened-oracles/README.md`.

## What would close it

A protocol change: policy outcomes and cross-app fetch activity not
observable through the shared bus (per-app fetch namespaces, and no
store-visible side effects for denied/approved calls). No launcher flag
can do it.
