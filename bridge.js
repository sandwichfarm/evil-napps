// evil-napps harness bridge — a faithful miniature of the reference launcher's
// bridge.js (eskema/nostrapps). Injected by sw.js at the top of every napp
// document's <head>. It is the ONLY sanctioned channel to the launcher:
// everything below is postMessage rpc over window.parent with '*'.
;(() => {
  // ── Neutralize service-worker registration ──────────────────────────
  // The origin's single service-worker slot is owned by the launcher (its
  // sw.js serves the napp's files from IDB). A napp registering its own SW
  // can't work through this harness's server (the script fetch bypasses the
  // controlling SW), and if it did succeed it would evict the launcher's SW
  // and break file serving — and persistence. Stubbed so such napps degrade
  // gracefully (the reference does the same — unconditionally). The harness
  // knob `swstub` models a launcher that DOESN'T stub: evil-07 probes what
  // that hands out.
  const swStubbed = !(window.__nappFlags && window.__nappFlags.swstub === false);
  try {
    const swc = navigator.serviceWorker
    if (swc && swStubbed) {
      const stub = {
        scope: location.origin + '/',
        active: null,
        installing: null,
        waiting: null,
        update: () => Promise.resolve(stub),
        unregister: () => Promise.resolve(true),
        addEventListener() {},
        removeEventListener() {}
      }
      const def = (name, value) => {
        try {
          Object.defineProperty(swc, name, { configurable: true, value })
        } catch {}
      }
      def('register', () => {
        console.warn('[harness] service worker registration is unsupported in the sandbox; ignoring')
        return Promise.resolve(stub)
      })
      def('getRegistration', () => Promise.resolve(undefined))
      def('getRegistrations', () => Promise.resolve([]))
      try {
        Object.defineProperty(swc, 'ready', {
          configurable: true,
          get: () => Promise.resolve(stub)
        })
      } catch {}
    }
  } catch {}

  const pending = new Map()
  const storeSubCallbacks = new Map()
  const subCallbacks = new Map()
  let subSerial = 0
  let rpcSerial = 0

  function rpc(method, params) {
    const id = 'rpc' + rpcSerial++
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject })
      window.parent.postMessage(
        {
          __nostrapps: 'rpc',
          id,
          method,
          params,
          instanceId: window.name
        },
        '*'
      )
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id)
          reject(new Error('rpc timeout: ' + method))
        }
      }, 15000)
    })
  }

  function reply(requestId, ok, payload) {
    window.parent.postMessage(
      {
        __nostrapps: 'napp-dispatch-result',
        requestId,
        instanceId: window.name,
        ...(ok ? { result: payload } : { error: payload })
      },
      '*'
    )
  }

  const actionHandlers = []

  window.addEventListener('message', event => {
    const data = event.data
    if (!data) return

    switch (data.__nostrapps) {
      case 'rpc-result':
      case 'rpc-error': {
        const p = pending.get(data.id)
        if (!p) return
        pending.delete(data.id)
        if (data.__nostrapps === 'rpc-result') p.resolve(data.result)
        else p.reject(new Error(data.error))
        return
      }
      case 'nostrdb-sub-event': {
        storeSubCallbacks.get(data.callbackId)?.(data.event)
        return
      }
      case 'napp-sub-callback': {
        const cbs = subCallbacks.get(data.callbackId)
        const msg = data.msg
        if (!cbs || !msg) return
        try {
          if (msg.type === 'eose') cbs.eoseEventsCallback?.(msg.events || [])
          else if (msg.type === 'event') cbs.liveEventCallback?.(msg.event)
          else if (msg.type === 'closed') {
            subCallbacks.delete(data.callbackId)
            cbs.closedCallback?.(msg.reasons || {})
          }
        } catch (err) {
          console.error('[napp] subscription callback threw', err)
        }
        return
      }
      case 'napp-dispatch-action': {
        if (typeof data.idx === 'number') {
          const fn = actionHandlers[data.idx]?.[1]
          if (!fn) {
            reply(data.requestId, false, 'No registered action handler matched this dispatch')
          } else {
            Promise.resolve()
              .then(() => fn(data.name, data.payload))
              .then(
                result => reply(data.requestId, true, result ?? null),
                err => reply(data.requestId, false, String(err?.message ?? err))
              )
          }
        }
        return
      }
      case 'napp-theme-change': {
        document.documentElement.dataset.theme = data.theme
        return
      }
    }
  })

  const nostrShim = {
    getPublicKey: () => rpc('getPublicKey'),
    signEvent: evt => rpc('signEvent', evt),
    nip04: {
      encrypt: (pubkey, plaintext) => rpc('nip04.encrypt', { pubkey, plaintext }),
      decrypt: (pubkey, ciphertext) => rpc('nip04.decrypt', { pubkey, ciphertext })
    },
    nip44: {
      encrypt: (pubkey, plaintext) => rpc('nip44.encrypt', { pubkey, plaintext }),
      decrypt: (pubkey, ciphertext) => rpc('nip44.decrypt', { pubkey, ciphertext })
    }
  }
  // window.nostr (NIP-07) is GATED on the granted `identity` capability —
  // the shell declares the grant via window.__nappDomains before this runs.
  // ALWAYS pinned non-writable/non-configurable, granted or not: otherwise a
  // NIP-07 browser extension would inject its own window.nostr into the frame
  // and hand the site a signer anyway.
  const identityGranted =
    Array.isArray(window.__nappDomains) && window.__nappDomains.includes('identity')
  try {
    Object.defineProperty(window, 'nostr', {
      value: identityGranted ? nostrShim : undefined,
      writable: false,
      configurable: false,
      enumerable: true
    })
  } catch {
    if (identityGranted) {
      try {
        window.nostr = nostrShim
      } catch {}
    }
  }

  window.nostrdb = {
    add: event => rpc('nostrdb.add', { event }),
    query: filters => rpc('nostrdb.query', { filters }),
    count: filters => rpc('nostrdb.count', { filters }),
    event: id => rpc('nostrdb.event', { id }),
    remove: ids => rpc('nostrdb.remove', { ids }),
    replaceable: (kind, author, identifier) =>
      rpc('nostrdb.replaceable', { kind, author, identifier }),
    // Every event saved to the launcher-wide store from now on that matches
    // filters, one by one, whatever saved it (see evil-08: cross-app traffic
    // analysis). Async-iterator shape per napp-env.d.ts.
    subscribe: filters => {
      const callbackId = subSerial++
      const queue = []
      const waiting = []
      let done = false
      const end = () => {
        if (done) return
        done = true
        storeSubCallbacks.delete(callbackId)
        rpc('nostrdb.unsubscribe', { callbackId }).catch(() => {})
        for (const resolve of waiting.splice(0)) resolve({ value: undefined, done: true })
      }
      storeSubCallbacks.set(callbackId, event => {
        const resolve = waiting.shift()
        if (resolve) resolve({ value: event, done: false })
        else queue.push(event)
      })
      const started = rpc('nostrdb.subscribe', { filters, callbackId })
      started.catch(end)
      return {
        [Symbol.asyncIterator]() {
          return this
        },
        async next() {
          await started
          if (queue.length) return { value: queue.shift(), done: false }
          if (done) return { value: undefined, done: true }
          return new Promise(resolve => waiting.push(resolve))
        },
        async return() {
          end()
          return { value: undefined, done: true }
        }
      }
    },
    supports: async () => []
  }

  // Inter-app calling. Everything is an action.
  function hostSubscription(method, params, opts) {
    const { label, maxEoseTimeout, eoseEventsCallback, liveEventCallback, closedCallback } =
      opts || {}
    const callbackId = subSerial++
    subCallbacks.set(callbackId, { eoseEventsCallback, liveEventCallback, closedCallback })
    rpc(method, { ...params, label, maxEoseTimeout, callbackId }).catch(err => {
      const cbs = subCallbacks.get(callbackId)
      if (!cbs) return
      subCallbacks.delete(callbackId)
      console.error('[napp] subscription failed', err)
      const reason = 'error: ' + String(err?.message || err)
      try {
        const relays = params.relays || ['']
        cbs.closedCallback?.(Object.fromEntries(relays.map(url => [url, reason])))
      } catch {}
    })
    return () => {
      if (!subCallbacks.delete(callbackId)) return
      rpc('napp.unsubscribe', { callbackId }).catch(() => {})
    }
  }

  function subscribe(relays, filter, opts) {
    return hostSubscription('napp.subscribe', { relays, filter }, opts)
  }

  const napp = {
    instance: window.name,
    action: (name, payload, options) => rpc('napp.action', { name, payload, options }),
    registerAction(pattern, fn) {
      if (typeof pattern !== 'string' || !pattern) {
        throw new Error('window.napp.registerAction: pattern is required')
      }
      let idx
      if (typeof fn === 'function') {
        idx = actionHandlers.length
        actionHandlers.push([pattern, fn])
      }
      window.parent.postMessage(
        {
          __nostrapps: 'napp-action-registered',
          instanceId: window.name,
          idx,
          pattern
        },
        '*'
      )
    },
    close: () => {
      window.parent.postMessage({ __nostrapps: 'napp-close', instanceId: window.name }, '*')
    },
    link: url => {
      window.parent.postMessage({ __nostrapps: 'napp-link', url, instanceId: window.name }, '*')
    },
    log: message => {
      rpc('napp.log', { message: String(message ?? '') }).catch(() => {})
    },
    utils: {
      // A plain REQ to exactly these relays — the relays and the filter are
      // the napp's to choose (evil-06's exfil channel: the filter itself can
      // carry data toward an attacker relay).
      subscribe,
      publish: (event, relays) => rpc('napp.publish', { event, relays }),
      verifyEvent: event => rpc('napp.verifyEvent', event)
    }
  }

  window.napp = napp
})()
