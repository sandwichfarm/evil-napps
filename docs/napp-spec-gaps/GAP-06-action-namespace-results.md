# GAP-06 — Unpoliced action namespace, unauthenticated results

**Class:** security
**Status:** validated — `evil-04-action-squat` (round-trip, wildcard, silent pick)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Actions:

> "There is no restriction on what actions are allowed"

> "A generic `view` whose event resolves is routed as `view:<kind-number>`,
> so the apps handling that kind are offered it alongside those handling
> `view`"

— and the action table's "Returns" column: results flow back to callers.

## The gap

Any app claims any action name — including generic `view`, which the spec's
own routing offers alongside every `view:<kind>` dispatch, so one registered
string collects them all. Worse: **handler results round-trip into callers'
code with no authenticity check**. The dispatcher cannot verify a result,
and even perfect attribution would not help: the squatter genuinely
produced the result; the caller has no trust vocabulary to judge the
handler by.

## Why no launcher can close it

Asking on ambiguity is launcher policy (the reference asks), but two
claimants to `profile` are indistinguishable to the user (GAP-07: the
identity surface is attacker-chosen metadata), and no question is asked at
all when the squatter is the *sole* handler. Nothing in the protocol can
certify a handler or a result — actions are, by spec, unpoliced.

## Evidence

`evil-04-action-squat`, validated: the `"view"` wildcard collected every
`view:<kind>` dispatch (via `view:1`); the sole-handler auto-pick routed the
launcher's own `profile` dispatch to the squatter silently once the legit
app closed; the poisoned action result round-tripped into the victim's own
callback as the action result. See `napps/evil-04-action-squat/README.md`.

## What would close it

A protocol change: a handler identity surface (which app answered, rendered
from verified identity — the vocabulary GAP-07 needs) and result attribution
bound to it. Namespace policing cannot work without it.
