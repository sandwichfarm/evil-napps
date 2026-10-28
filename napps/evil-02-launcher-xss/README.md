# evil-02 — launcher XSS

**Tier 0 — launcher misconfig.** `metadata.json` is the napp's self-description
— unsigned, attacker-controlled bytes (a local folder or an nsite fetched from
relays) that the launcher interpolates into its own origin's DOM: app cards,
permission prompts, handler pickers, window titles. A launcher that renders
any field as HTML hands the napp script execution **at the launcher origin**.

The payloads live in this artifact's own `metadata.json`: the `description`
carries an element-injection implant (`<img src=x onerror=…>`), the `icon` an
attribute-injection breakout (`x" onerror="…" data-y="`). Each implant is an
inert callback: it reports `fired` to the napp and parks. **Demo mode does
nothing else** (no writes, no network — asserted by the spec).

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-02-launcher-xss/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `card-html` | metadata rendered as HTML (description element injection) | unsigned metadata.json in the launcher's DOM | critical |
| `icon-attr` | icon attribute injection (`src="…"` breakout) | same field-level discipline for icon URLs | high |
| `silent-sign` | forged grant → silent signing | the permission store is launcher-origin localStorage | critical |

## Arming (harness knobs)

- **safe render (textContent — the reference behavior) is the green gate**: all
  rows held, and the card shows the payload as inert text (what users of a
  safe launcher actually see).
- **unsafe render (innerHTML) + no launcher CSP** arms all rows — both vectors
  fire and call back from the launcher origin.
- **unsafe render + strict launcher CSP (`script-src 'self'`) holds every
  payload** — the last line of defense, and only usable because the harness's
  own script is externalized (`harness/index.js`); a CSP that still allows
  inline handlers is no defense at all.

## VERY EVIL

The armed implant reads the permission-decision store and the launcher
canaries, **forges an allow-always `signEvent` decision**, exfiltrates all of
it — and the `silent-sign` row then signs a marker note through the bridge
**with no prompt ever shown** (prompt counter 0, prompts knob still on
`prompt`). The bridge's permission model inverts: grants become attacker
state. No destructive payloads.

## Validate

```bash
node tests/evil-02.spec.mjs     # 19 checks, self-contained
```

Validated findings and the reference-launcher source note (nostrapps holds this
rung by construction — `textContent`/element builders everywhere, one fixed
icon set): [ROADMAP.md](../../ROADMAP.md).
