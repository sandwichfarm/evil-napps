# evil-01 — frame escape

**Tier 0 — launcher misconfig.** NAPP.md says each napp runs at its own origin
in a sandboxed iframe, that `window.parent` is cross-origin, and that "the
bridge is its only channel to the launcher." None of that is enforced by the
protocol — it is all launcher policy. This rung attacks every isolation
*must* a launcher can get wrong.

This folder is the NAPP artifact: `index.html` + `metadata.json`, built from
`src/napps/evil-01-frame-escape/` via `node build.mjs`.

## Rows

| id | attack | target | severity |
|----|--------|--------|----------|
| `launcher-origin` | launcher-origin equivalence — read the launcher's DOM + localStorage | never serve napp bytes from the launcher's own origin | critical |
| `origin-collision` | cross-napp origin collision — read another app's persisted secrets | origin derivation is launcher policy (naive slugs collide) | critical |
| `popup` | popup escape via `window.open` | the sandbox must not permit popups | high |
| `referrer` | referrer leak — `document.referrer` carries the launcher URL | NAPP.md is silent on Referrer-Policy | high |
| `frame-census` | frame census + sibling scriptability | `parent.length` is always readable cross-origin | high |
| `origin-storage` | per-origin storage granted | **by design** — the persistence channel evil-07 weaponizes | info |
| `top-nav` | ancestor navigation (shell hijack) | no `allow-top-navigation`, never a missing sandbox attr | critical, **destructive** |

## Arming (harness knobs)

- **`napp` preset + hashed origins + strict referrer is the green gate** — every
  critical/high row holds; only the two spec-gap rows (`frame-census`,
  `origin-storage`) arm.
- **serve-at-launcher-origin** arms `launcher-origin` (full parent DOM,
  launcher permission grants) and scriptable sibling napps.
- **naive origin scheme** arms `origin-collision` (`evil-01-frame-escape` and
  `evil~01~frame~escape` slug to one origin — the scheme the reference *retired*).
- **top-nav / no-sandbox presets** arm the ancestor-navigation row.
- **popups preset** arms `window.open`.
- **full referrer policy** leaks the launcher URL and its share-link payloads.

## ROE note specific to this rung

The top-nav probe is the suite's one documented navigation exception: it can
only detect permission by navigating, so it reloads the launcher at **its own
current URL** with a `?evil01nav=1` marker (query param — referrers never carry
fragments), and the relaunched frame reports the result without navigating
again. Demo mode writes one immediately-cleaned marker key on its own origin.

## VERY EVIL

Launcher-storage theft + canary exfil, cross-origin-collision theft, popup
exfil, referrer/census exfil, a persistent origin marker — and the destructive
**launcher hijack to the collector last**.

## Validate

```bash
node tests/evil-01.spec.mjs     # 38 checks, self-contained
```

Validated findings and reference-launcher source notes: [ROADMAP.md](../../ROADMAP.md).
