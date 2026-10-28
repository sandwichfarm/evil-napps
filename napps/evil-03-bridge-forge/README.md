# evil-03 — bridge forge

**Tier 1 — bridge confusion.** The bridge is `postMessage` with `'*'` targets;
the only sender identity is `MessageEvent.source` and the sender's origin —
and neither the reference launcher's router nor the reference bridge's reply
paths checks both. All findings below are validated against the eskema/nostrapps
source and reproduced against the harness.

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-03-bridge-forge/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `cross-app-forge` | declared-instanceId forgery (a child frame's rpc executes as the victim) | routers must bind identity to `MessageEvent.source`, never envelope fields | critical |
| `source-blindness` | same-origin child frame accepted under the reference router | the reference checks origin + declared instanceId — never `MessageEvent.source` | critical |
| `reply-injection` | forged subscription callbacks into the victim's live feed | the reference bridge resolves rpc-result / napp-sub-callback by id alone — no source check | high — **arms in every preset** |
| `boot-command-forgery` | boot-frame install-channel takeover | `boot.html` must accept the launcher origin only | critical, **destructive** |

## Arming (harness knobs)

- **strict router + checked boot channel is the green gate** — only the
  bridge-level `reply-injection` row arms (a reference-bridge finding, below
  every router).
- **declared-only router** accepts cross-app forges — and a gated forge then
  opens a dialog titled *"victim wants to signEvent"*: the victim's approval
  record is charged.
- **the reference router** accepts a same-origin srcdoc child posting as any
  instance of the app — `MessageEvent.source` is never compared.
- **unchecked boot channel** (`bootcheck` off): any napp commands any origin's
  boot frame — `napp-read-files` proves it in demo.

## ROE note specific to this rung

The `cross-app-forge` demo posts one immediately-removed marker event to the
shared store (the store's analog of the marker-key clause). The artifact's
bytes deliberately avoid literal `</html>` sequences — the reference `sw.js`'s
ready-tag injection is string surgery on the first such sequence (a validated
reference finding; see ROADMAP).

## VERY EVIL

Forged publish under the victim's identity; a forged `signEvent` through a
child frame; a phishing-looking note injected into the victim's live feed —
and the destructive **boot-channel file swap** last: a takeover page sprayed
to every boot frame, read-back-proven to be served at the victim's origin
under the victim's window title.

## Validate

```bash
node tests/evil-03.spec.mjs     # 18 checks, self-contained
```

Validated findings: [ROADMAP.md](../../ROADMAP.md).
