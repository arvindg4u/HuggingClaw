/**
 * WhatsApp proxy preload script for HF Spaces.
 *
 * HF Spaces blocks outbound connections to WhatsApp domains.
 * This script intercepts:
 *   1. globalThis.fetch() for WhatsApp HTTP API calls → routes through Render proxy
 *   2. tls.connect() for WhatsApp WebSocket → routes through WebSocket TCP tunnel
 *      (/whatsapp-tcp on Render proxy, same pattern as Discord's /discord-ws)
 *
 * WHATSAPP_PROXY_BASE env var controls the HTTP proxy target (set by start.sh).
 * WHATSAPP_WS_PROXY_URL env var controls the WebSocket tunnel endpoint.
 * Loaded via: NODE_OPTIONS="--require /path/to/whatsapp-proxy.cjs"
 *
 * Must be loaded AFTER telegram-proxy.cjs so Telegram interception takes priority.
 */
'use strict';

const PROXY_BASE = (process.env.WHATSAPP_PROXY_BASE || '').replace(/\/+$/, '');
const WHATSAPP_DOMAINS = [
  'web.whatsapp.com',
  'wss.web.whatsapp.com',
  'g.whatsapp.net',
  'mmg.whatsapp.net',
  'pps.whatsapp.net',
  'static.whatsapp.net'
];

function isWhatsAppDomain(hostname) {
  if (!hostname) return false;
  const hn = hostname.toLowerCase().replace(/^wss?:\/\//, '').split('/')[0];
  return WHATSAPP_DOMAINS.some(d => hn === d || hn.endsWith('.' + d));
}

if (!PROXY_BASE) {
  console.log('[whatsapp-proxy] Loaded (no proxy configured — WHATSAPP_PROXY_BASE not set)');
  process.exit(0);
}

const proxyHost = (() => { try { return new URL(PROXY_BASE).hostname; } catch { return 'proxy'; } })();

// WebSocket TCP tunnel URL — derived from WHATSAPP_WS_PROXY_URL or WHATSAPP_PROXY_BASE
const WHATSAPP_WS_PROXY_URL = (process.env.WHATSAPP_WS_PROXY_URL || (PROXY_BASE.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:') + '/whatsapp-tcp')).replace(/\/+$/, '');

// ws library — available via NODE_PATH=/home/node/browser-deps/node_modules
const { Duplex } = require('stream');
let WebSocket;
try { WebSocket = require('ws'); } catch(e) { /* ws not available */ }

let logged = false;
function logOnce(msg) {
  if (!logged) { console.log(`[whatsapp-proxy] ${msg}`); logged = true; }
}

// ── Helper: wake-up call to prevent proxy sleep ─────────────────────────
function wakeProxy(wsUrl) {
  return new Promise((resolve) => {
    const httpUrl = wsUrl.replace(/^wss:/i, 'https:').replace(/^ws:/i, 'http:');
    try {
      const u = new URL(httpUrl);
      const mod = u.protocol === 'https:' ? require('https') : require('http');
      const wakeReq = mod.get(u, (res) => { res.resume(); resolve(); });
      wakeReq.setTimeout(5000, () => { try { wakeReq.destroy(); } catch(e) {} resolve(); });
      wakeReq.on('error', () => resolve());
    } catch(e) { resolve(); }
  });
}

// ── 1. Patch globalThis.fetch() for WhatsApp HTTP API calls ─────────────
const originalFetch = globalThis.fetch;
globalThis.fetch = function patchedWaFetch(input, init) {
  let urlStr;
  if (typeof input === 'string') urlStr = input;
  else if (input instanceof URL) urlStr = input.toString();
  else if (input && typeof input === 'object' && input.url) urlStr = input.url;
  else return originalFetch.call(this, input, init);

  try {
    const parsed = new URL(urlStr);
    if (isWhatsAppDomain(parsed.hostname)) {
      logOnce(`HTTP → ${proxyHost} (wa)`);
      const newUrl = PROXY_BASE.replace(/\/+$/, '') + '/whatsapp' + parsed.pathname + parsed.search;
      const headers = new Headers(input instanceof Request ? input.headers : (init?.headers || {}));
      headers.set('x-target-host', parsed.hostname);
      headers.set('x-hc', 'true');
      const newInit = {
        method: (input instanceof Request ? input.method : init?.method) || 'GET',
        headers,
        body: (input instanceof Request ? input.body : init?.body) || undefined,
        redirect: 'follow',
      };
      if (typeof input === 'string') return originalFetch.call(this, newUrl, newInit);
      return originalFetch.call(this, new Request(newUrl, newInit));
    }
  } catch {}
  return originalFetch.call(this, input, init);
};

// ── 2. WebSocket TCP tunnel for WhatsApp ────────────────────────────────
// Baileys creates TLS sockets via tls.connect() for WhatsApp WebSocket.
// Instead of HTTP rewrite (which breaks WebSocket upgrades at the proxy),
// use a raw TCP tunnel through Render proxy's /whatsapp-tcp endpoint.
// Pattern: same as discordWsConnect() in cloudflare-proxy.js.
//
// Flow:
//   Baileys → tls.connect("web.whatsapp.com", 443)
//     → waWsConnect() → WebSocket → Render /whatsapp-tcp
//       → net.connect("web.whatsapp.com", 443) [from Render]
//     → tls.connect({socket: duplex, host, servername}) [TLS over tunnel]
//     → WhatsApp WebSocket handshake ✅

function waWsConnect(targetHost, targetPort, timeout = 45000) {
  if (!WHATSAPP_WS_PROXY_URL) {
    return Promise.reject(new Error('WHATSAPP_WS_PROXY_URL not set'));
  }
  if (!WebSocket) {
    return Promise.reject(new Error('ws library not available — cannot create WhatsApp WS tunnel'));
  }

  return wakeProxy(WHATSAPP_WS_PROXY_URL).then(() => {
    return new Promise((resolve, reject) => {
      let settled = false;
      const effectiveTimeout = Math.max(timeout, 45000);
      const timer = setTimeout(() => {
        if (!settled) { settled = true; reject(new Error('WhatsApp WS tunnel timeout')); }
      }, effectiveTimeout);

      let ws;
      try {
        ws = new WebSocket(WHATSAPP_WS_PROXY_URL, { handshakeTimeout: 20000 });
      } catch(e) {
        clearTimeout(timer); reject(e); return;
      }

      let pendingWriteBuffer = [];
      let tunnelReady = false;

      const duplex = new Duplex({
        write(data, encoding, callback) {
          if (!tunnelReady) {
            pendingWriteBuffer.push(Buffer.from(data));
            callback(); return;
          }
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(data, { binary: true }, callback);
          } else {
            callback(new Error('WebSocket closed'));
          }
        },
        read(size) {},
        destroy(err, callback) {
          try { ws.close(); } catch(e) {}
          callback(err);
        }
      });
      duplex.setMaxListeners(0);
      duplex.on('error', () => {});

      ws.on('message', (data, isBinary) => {
        const str = !isBinary ? (typeof data === 'string' ? data : data.toString()) : '';
        if (str.length > 0 && str[0] === '{') {
          if (settled) return;
          try {
            const parsed = JSON.parse(str);
            if (parsed.status === 'connected' || parsed.type === 'connected') {
              tunnelReady = true;
              clearTimeout(timer);
              if (pendingWriteBuffer.length > 0) {
                const buf = Buffer.concat(pendingWriteBuffer);
                pendingWriteBuffer = [];
                if (ws.readyState === WebSocket.OPEN) ws.send(buf, { binary: true }, () => {});
              }
              if (!settled) { settled = true; duplex.emit('connect'); resolve(duplex); }
              return;
            }
            if (parsed.error) {
              clearTimeout(timer);
              if (!settled) { settled = true; reject(new Error(parsed.error)); }
              return;
            }
          } catch(e) {}
          return;
        }
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (buf.length > 0 && !duplex.push(buf)) {}
      });

      ws.on('open', () => {
        ws.send(JSON.stringify({ host: targetHost, port: targetPort }), { binary: false });
      });
      ws.on('error', (e) => {
        clearTimeout(timer);
        if (!settled) { settled = true; reject(e); }
      });
      ws.on('close', (code, reason) => {
        clearTimeout(timer);
        if (!tunnelReady && !settled) { settled = true; reject(new Error('WhatsApp WS closed before tunnel ready')); }
        duplex.push(null);
      });
    });
  });
}

// ── 3. Patch tls.connect() for WhatsApp WebSocket ──────────────────────
// The ws library (used by Baileys) creates TLS sockets via tls.connect.
// We intercept these for WhatsApp domains and use the WebSocket TCP tunnel.
const tls = require('tls');
const origTlsConnect = tls.connect;
const net = require('net');

tls.connect = function patchedWaTlsConnect(...args) {
  // Normalize arguments
  let opts, cb;
  if (typeof args[0] === 'object') {
    opts = args[0];
    cb = args[1];
  } else {
    opts = { host: args[0], port: args[1] || 443 };
    cb = typeof args[2] === 'function' ? args[2] : (typeof args[1] === 'function' ? args[1] : undefined);
  }

  const host = (opts.servername || opts.host || '').toLowerCase();

  // Non-WhatsApp domains pass through to the next layer (cloudflare-proxy.js patched tls.connect)
  if (!isWhatsAppDomain(host)) {
    return cb ? origTlsConnect.call(this, opts, cb) : origTlsConnect.call(this, opts);
  }

  logOnce(`WebSocket → ${proxyHost} (wa via tunnel ${host})`);

  // Use WebSocket TCP tunnel via /whatsapp-tcp
  // Create the tunnel, then do TLS over it
  const origHost = host;
  const origPort = opts.port || 443;

  if (cb) {
    // Callback mode: establish tunnel, then TLS, then call cb
    waWsConnect(origHost, origPort)
      .then((tunnel) => {
        const tlsSocket = origTlsConnect.call(this, {
          socket: tunnel,
          host: opts.host || origHost,
          servername: opts.servername || origHost,
          rejectUnauthorized: opts.rejectUnauthorized !== false,
        }, () => cb(null, tlsSocket));
        tlsSocket.on('error', (e) => cb(e));
      })
      .catch((e) => {
        try { if (typeof cb === 'function') cb(e); } catch(_) {}
      });
    // Return placeholder — real socket comes via callback
    const placeholder = new net.Socket();
    placeholder.setMaxListeners(0);
    process.nextTick(() => placeholder.emit('error', new Error('connecting')));
    return placeholder;
  }

  // Non-callback mode: tunnel then TLS via socket option
  const tunnelPromise = waWsConnect(origHost, origPort);
  const early = new net.Socket();
  early.setMaxListeners(0);
  let settled = false;
  tunnelPromise.then((tunnel) => {
    if (settled) return;
    settled = true;
    const tlsSocket = origTlsConnect.call(this, {
      socket: tunnel,
      host: opts.host || origHost,
      servername: opts.servername || origHost,
      rejectUnauthorized: opts.rejectUnauthorized !== false,
    });
    // Forward events from TLS socket to our early placeholder
    tlsSocket.on('secureConnect', () => { early.emit('connect'); early.emit('secureConnect'); });
    tlsSocket.on('data', (d) => { if (!early.destroyed) try { early.push(d); } catch(_) {} });
    tlsSocket.on('end', () => { if (!early.destroyed) early.push(null); });
    tlsSocket.on('error', (e) => { if (!early.destroyed) early.destroy(e); });
    tlsSocket.on('close', () => { if (!early.destroyed) early.push(null); });
  }).catch((e) => {
    if (!settled) { settled = true; early.destroy(e); }
  });
  return early;
};

console.log(`[whatsapp-proxy] Active: ${WHATSAPP_DOMAINS.join(', ')} → ${proxyHost} (WS tunnel: ${WHATSAPP_WS_PROXY_URL})`);
