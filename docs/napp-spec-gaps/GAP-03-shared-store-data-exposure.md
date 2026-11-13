# GAP-03 — Shared store = cross-app data exposure

**Class:** privacy / exfiltration
**Status:** validated — `evil-06-signer-abuse` (read half, end to end) + `evil-05-store-poison` (write half)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Launcher bridge:

> `window.nostrdb.query(filters)` / `count(filters)` / `event(id)` — no
> scoping qualifier anywhere in the spec.

> `window.napp.utils.loadDmRelays(pubkey) // kind 10050, NIP-17` — private
> fetch paths exist, and "Every event is also saved to the store".

## The gap

Everything any app fetches lands in a store **every other app can read
wholesale**: NIP-17 DM envelopes (ciphertext + correspondent metadata),
gift wraps, private-group content, other apps' working data. A second app
reads it all with `nostrdb.query` — no prompt, by design. The chat app the
user trusts with their DMs is not the only reader; every installed app is.

## Why no launcher can close it

The store is shared by spec. Read scoping does not exist in the bridge
vocabulary: `query`/`count`/`event`/`subscribe` all address the whole store,
and every `utils.load*`/`sync`/`outbox`/`subscribe` helper writes into it. A
perfect launcher implementing the bridge as specified exposes every saved
event to every app.

## Evidence

`evil-06-signer-abuse`: the full chain validated end to end — the victim's
note read out of the shared store, encrypted to the attacker's pubkey, and
exfiltrated. `evil-05-store-poison`: the write half — poisoned inserts land
in what every store reader renders. See
`napps/evil-06-signer-abuse/README.md` and `napps/evil-05-store-poison/README.md`.

## What would close it

A protocol change: per-app store partitions with an explicit cross-app read
grant (the same vocabulary GAP-01 needs). No launcher flag can do it.
