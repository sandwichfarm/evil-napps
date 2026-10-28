// evil-napps harness service worker — a faithful miniature of the reference
// launcher's sw.js (eskema/nostrapps). One instance per napp origin
// (<label>.localhost:<port>); serves the napp's files from that origin's
// IndexedDB, injects bridge.js into HTML responses, and applies the launcher's
// policy (capability domains → network lock CSP; referrer policy) via response
// headers — the layer the napp document itself can't reach.
const DB_NAME = `files-${self.location.origin.split('://')[1]}`
const DB_VERSION = 1
const STORE = 'files'

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()))

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin) return
  event.respondWith(handleFetch(event.request, url))
})

async function handleFetch(req, url) {
  let path = url.pathname
  if (path.endsWith('/')) path += 'index.html'

  // The policy record is internal — never serve it back to the napp.
  if (path === '/__policy__') return new Response('not found', { status: 404 })

  if (path === '/boot.html') return passthrough(req, BOOT_CSP)
  if (path === '/sw.js') return passthrough(req, LOCKED_CSP)
  if (path === '/bridge.js') return passthrough(req, LOCKED_CSP)

  const db = await openDB()
  const record = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly')
    const r = tx.objectStore(STORE).get(path)
    r.onsuccess = () => {
      const result = r.result ?? null
      try { db.close() } catch {}
      resolve(result)
    }
    r.onerror = () => { try { db.close() } catch {} ; reject(r.error) }
  })
  if (record) {
    const mime = record.mime || 'application/octet-stream'
    if (mime.startsWith('text/html')) {
      const text = typeof record.body === 'string' ? record.body : await record.body.text()
      const policy = await readPolicy()
      const grants = grantsFor(policy)
      return new Response(injectBridge(text, { domains: grants }), {
        status: 200,
        headers: htmlHeaders(policy)
      })
    }
    return new Response(record.body, {
      status: 200,
      headers: { 'Content-Type': mime }
    })
  }

  return new Response(`file ${url} not found`, {
    status: 404,
    headers: { 'Content-Security-Policy': LOCKED_CSP }
  })
}

// The launcher's own shared files, fetched from the server. Each carries a
// policy: the lock for sw.js/bridge.js, and for boot.html what it needs (its
// inline script) plus frame-ancestors pinned to the launcher.
async function passthrough(req, csp) {
  let res
  try {
    res = await fetch(req)
  } catch {
    return Response.error()
  }
  const headers = new Headers(res.headers)
  headers.delete('Content-Encoding')
  headers.delete('Content-Length')
  headers.set('Content-Security-Policy', csp)
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers })
}

// The Content-Security-Policy that seals a locked napp to its own origin:
// every off-origin load and connection blocked at once; the only route out is
// the bridge's postMessage rpc. worker-src 'none' is load-bearing (a worker's
// connections are bounded only by its own script's CSP). Granting network
// drops the lock entirely.
const LOCKED_CSP = [
  'default-src \'self\' blob: data:',
  'script-src \'self\' \'unsafe-inline\' blob:',
  'style-src \'self\' \'unsafe-inline\'',
  'img-src \'self\' data: blob:',
  'font-src \'self\' data:',
  'connect-src \'self\' blob: data:',
  'frame-src \'self\'',
  'child-src \'self\' blob:',
  'worker-src \'none\'',
  'form-action \'self\'',
  'base-uri \'self\''
].join('; ')

const LAUNCHER_ORIGIN = `${self.location.protocol}//${self.location.host.slice(
  self.location.host.indexOf('.') + 1
)}`

const BOOT_CSP = [
  'default-src \'none\'',
  'script-src \'unsafe-inline\'',
  'connect-src \'self\'',
  'worker-src \'self\'',
  `frame-ancestors ${LAUNCHER_ORIGIN}`
].join('; ')

function grantsFor(policy) {
  if (!policy) return ['identity', 'network']
  const domains = Array.isArray(policy.domains) ? [...policy.domains] : []
  return domains
}

function htmlHeaders(policy) {
  const headers = {
    'Content-Type': 'text/html',
    'Allow-CSP-From': LAUNCHER_ORIGIN
  }
  headers['Content-Security-Policy'] = grantsFor(policy).includes('network')
    ? 'upgrade-insecure-requests'
    : LOCKED_CSP + '; upgrade-insecure-requests'
  // Referrer policy is launcher policy NAPP.md never mentions: strict by
  // default (origin only), or the launcher can leak its full URL (and share
  // payloads) into every napp document.
  headers['Referrer-Policy'] = policy && policy.referrer === 'full' ? 'unsafe-url' : 'strict-origin-when-cross-origin'
  return headers
}

const UNREADABLE_POLICY = { domains: [], v: 2 }

function parsePolicy(text) {
  try {
    const p = JSON.parse(text)
    return p && typeof p === 'object' ? p : UNREADABLE_POLICY
  } catch {
    return UNREADABLE_POLICY
  }
}

async function readPolicy() {
  try {
    const db = await openDB()
    const rec = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly')
      const r = tx.objectStore(STORE).get('/__policy__')
      r.onsuccess = () => resolve(r.result ?? null)
      r.onerror = () => reject(r.error)
    })
    try { db.close() } catch {}
    if (!rec) return null
    const text = typeof rec.body === 'string' ? rec.body : await rec.body.text()
    return parsePolicy(text)
  } catch {
    return UNREADABLE_POLICY
  }
}

function injectBridge(html, { domains = [] } = {}) {
  // The shell declares the granted capability domains as window.__nappDomains
  // BEFORE bridge.js runs (the NAPP presence model); `<` is escaped so a
  // domain string can never break out of the inline script.
  const domainsScript =
    '<script>window.__nappDomains=' +
    JSON.stringify(domains).replace(/</g, '\\u003c') +
    '</script>'
  const headInject = domainsScript + '<script src="/bridge.js"></script>'
  const readyTag =
    '<script>window.parent.postMessage({ __nostrapps: "napp-ready", instanceId: window.name }, "*")</script>'

  let result = html
  const headMatch = result.match(/<head[^>]*>/i)
  if (headMatch) {
    const idx = headMatch.index + headMatch[0].length
    result = result.slice(0, idx) + headInject + result.slice(idx)
  } else {
    result = headInject + result
  }

  const endIdx = result.indexOf('</html>')
  if (endIdx >= 0) {
    result = result.slice(0, endIdx) + readyTag + result.slice(endIdx)
  } else {
    result = result + readyTag
  }

  return result
}

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'path' })
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}
