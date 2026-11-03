# GAP-05 — One-time, unscoped authority grants

**Class:** security / exfiltration
**Status:** validated — `evil-06-signer-abuse` (nip44 private-data drop)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Development:

> "`signEvent` comes with `write`, and `nip04`/`nip44` carry `encrypt` and
> `decrypt` as granted."

NAPP.md, Permissions:

> "The launcher asks for permission on first launch and stores the grant. A
> row can be set to ask on every call."

## The gap

The grant vocabulary is *domains only*. `encrypt`, granted once on first
launch, silently encrypts to **any** pubkey — including the attacker's —
for the app's whole life. `write` signs and publishes **anything** toward
**any** relays. The user's one-time approval of a domain is an open-ended
delegation of a general-purpose authority.

## Why no launcher can close it

"Ask on every call" can surface each call — but the protocol has no
recipient/destination vocabulary to show in the prompt: all a launcher can
present is an opaque hex pubkey the user cannot evaluate (is it a contact?
an attacker? there is no way to know). The uncloseable core is grant-time
semantics: at first launch the user cannot know what the authority will be
used *for*, and the spec provides no binding — recipient-key allowlists,
destination relays, content classes — that would make any later prompt
meaningful. A perfect launcher still owns an authority it cannot scope.

## Evidence

`evil-06-signer-abuse`, validated end to end: the victim's note read out of
the shared store, encrypted **to the attacker's pubkey through the user's
own cipher authority**, published toward attacker relays (RELAY-PUBLISH
logged), ciphertext exfiltrated — "the user's bridge did all the work".
The full prompt-policy space mapped: deny holds, prompt = measurable dialog
latency oracle, auto-allow = silent signing. See
`napps/evil-06-signer-abuse/README.md`.

## What would close it

A protocol change: parameterized grants — recipient-key sets for
`encrypt`, relay allowlists for `publish`/`subscribe`, per-call parameter
display with name resolution (petnames) for the user to judge.
