# GAP-04 — Reads never prompt; filter-as-payload exfiltration channel

**Class:** exfiltration / security
**Status:** validated — `evil-06-signer-abuse` (NIP-50 payload, logged)
**Closable by launcher policy:** no — requires a protocol change

One of ten impossible-to-close gaps in the NAPP specification (see the
[spec gap inventory](00-INVENTORY.md), PR #1).

## Spec text that leaves it open

NAPP.md, Permissions:

> "Clipboard access and file saving always prompt."

— the only always-prompt rows. Reads never do.

NAPP.md, Launcher bridge:

> `window.napp.utils.subscribe(relays, filter, opts?) // a plain REQ to
> exactly these relays` — arbitrary relays, arbitrary filter, no prompt.

napp-env.d.ts, `Filter`: carries `search` (NIP-50), arbitrary `#tag` arrays,
ids, authors — everything a payload needs.

## The gap

Any data an app holds can be encoded into a filter and delivered verbatim to
any relay URL the app names: the filter **is** the payload (a NIP-50
`search` term containing the stolen data, an `#e` tag list carrying it), and
the relay URL **is** the destination. The launcher performs the delivery
itself, over its own connection, with no prompt — reads are exempt by
design. `utils.loadRelayInfo(url)` extends the same channel: the launcher
connects to an arbitrary URL a napp names, adding an internal-network
reachability oracle to the exfil channel.

## Why no launcher can close it

Distinguishing "legitimate query" from "exfiltration" means content
inspection of arbitrary filters — impossible without breaking the
protocol's purpose (arbitrary relays and filters *are* the feature). Even
per-call prompts dump a raw filter the user cannot evaluate.

## Evidence

`evil-06-signer-abuse`: the victim's note content carried out in a NIP-50
search term toward the attacker's relay — `RELAY-REQ` logged with the
payload; reads never prompt, validated across the whole prompt-policy space.
See `napps/evil-06-signer-abuse/README.md`.

## What would close it

A protocol change: destination-bound grants (relay allowlists attached to
the read/subscribe authority — the same parameterized-grant vocabulary
GAP-05 proposes). No launcher flag can do it.
