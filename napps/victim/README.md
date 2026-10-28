# victim — the benign fixture

**Harness fixture, not an evil napp.** The victim is what the rungs land on: a
small, deliberately boring NAPP that models what a real app does through the
bridge — and nothing else. It is a static artifact (not built from `src/`).

What it does:

- persists a per-origin secret (`__victim_secret__`) — evil-01's
  origin-collision target
- registers the `profile` and `view` actions — evil-04's namespace target
- polls the shared store (`nostrdb.query`, every 4s) and keeps a live
  subscription (`utils.subscribe`) — evil-03's reply-injection target
- posts activity pings into the shared store (every 5s) — evil-08's
  traffic-analysis target
- delegates `profile` actions to whatever app handles them (every 6s) and
  broadcasts the results — evil-04's squat/poison target
- attempts gated publishes when the harness's `victimnoisy` knob is on
  (every 6s) — evil-08's approval-oracle target

The `__victimEcho` broadcasts are harness instrumentation for the red team:
every bridge result is echoed to all sibling frames so an evil napp (and the
specs) can observe this app's bridge traffic from the outside. That channel
is clearly named in its source and exists only for the suite.

The launcher treats it like any other napp: per-origin boot + service worker,
its own `window.name` instance id, the same bridge.
