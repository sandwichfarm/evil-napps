# GAP-01 — Cross-app store traffic analysis

**Class:** privacy / spyware
**Status:** validated — `evil-08-hardened-oracles` (arms in every preset)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1). Even a perfect launcher — one
that implements every isolation rule the reference gets right — cannot close
it. Evidence: the validated evil-napps suite against real Chromium.

## Spec text that leaves it open

NAPP.md, Launcher bridge (and napp-env.d.ts):

> `window.nostrdb.subscribe(filters) // async iterator …`

> "Every event saved to the store from now on that matches filters, one by
> one. What is already stored comes from query()." (napp-env.d.ts)

> "Every event it brings is also saved to the store, where
> `nostrdb.subscribe` sees it." (napp.outbox — same wording for napp.sync and
> napp.utils.subscribe)

## The gap

The store is launcher-wide by design, and *every* fetch path auto-saves into
it. Any app with `identity` can hold a broad subscription and observe every
event every other app inserts: counts, kinds, timing, senders, content. A
single silent `nostrdb.subscribe` is a wiretap on every other app's Nostr
activity — what the user reads, who they reply to, what they publish.

## Why no launcher can close it

Closing it means splitting or muting the store — but the shared store **is
the protocol's data bus**: the spec hands `query`/`count`/`event`/`subscribe`
over "everything stored" to every app, and every helper that fetches
(`sync`, `outbox`, `utils.subscribe`) writes into it. A perfect launcher
implementing the bridge as specified still fans each saved event to each
matching subscription (reference source: `notifyStoreSubs`).

## Evidence

`evil-08-hardened-oracles`, cross-app traffic analysis row — validated in
**every preset**, including the fully hardened one: a plain
`nostrdb.subscribe` profiles what every app inserts (counts, kinds,
samples), source-validated from `notifyStoreSubs` and reproduced in
Chromium. See `napps/evil-08-hardened-oracles/README.md`.

## What would close it

A protocol change: per-app store partitions with an explicit cross-app
sharing vocabulary, or delivery-scoped subscriptions (an app sees only
events its own fetches brought in). No launcher flag can do it.
