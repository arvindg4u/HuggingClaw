/**
 * WhatsApp proxy preload script for HF Spaces.
 *
 * HF Spaces blocks outbound connections to WhatsApp domains.
 * This script intercepts:
 *   1. globalThis.fetch() for WhatsApp HTTP API calls → routes through Render proxy
 *   2. tls.connect() for WhatsApp WebSocket (ws library) → routes through Render proxy
 *
 * WHATSAPP_PROXY_BASE env var controls the target (set by start.sh).
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
let logged = false;
function logOnce(msg) {
  if (!logged) { console.log(`[whatsapp-proxy] ${msg}`); logged = true; }
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

// ── 2. Patch tls.connect() for WhatsApp WebSocket ──────────────────────
// The ws library (used by Baileys) creates TLS sockets via tls.connect.
// We intercept these for WhatsApp domains, connect to the Render proxy
// instead, then rewrite the WebSocket upgrade request on-the-fly.
const tls = require('tls');
const origTlsConnect = tls.connect;

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
  if (!isWhatsAppDomain(host)) {
    return cb ? origTlsConnect.call(this, opts, cb) : origTlsConnect.call(this, opts);
  }

  logOnce(`WebSocket → ${proxyHost} (wa via ${host})`);

  // Connect to Render proxy instead of WhatsApp
  const proxyUrl = new URL(PROXY_BASE);
  const waOpts = {
    ...opts,
    host: proxyUrl.hostname,
    servername: proxyUrl.hostname,
    port: parseInt(proxyUrl.port) || 443,
  };

  // Store original target info so we can rewrite the upgrade request
  const origHost = host;
  const origPort = opts.port || 443;

  const socket = origTlsConnect.call(this, waOpts, cb);
  const origWrite = socket.write.bind(socket);
  let upgraded = false;

  // Intercept the first write to rewrite the WebSocket upgrade request
  socket.write = function waWriteInterceptor(data, ...rest) {
    if (!upgraded) {
      const dataStr = typeof data === 'string' ? data : data.toString();
      if (dataStr.includes('Upgrade: websocket') || dataStr.includes('upgrade: websocket')) {
        upgraded = true;
        // Extract original WebSocket path from the upgrade request
        const pathMatch = dataStr.match(/^(?:GET|POST)\s+(\S+)/m);
        const origPath = pathMatch ? pathMatch[1] : '/';
        const wsUrl = `/whatsapp-ws?host=${encodeURIComponent(origHost)}&path=${encodeURIComponent(origPath)}`;

        // Rewrite: change path and Host header
        const rewritten = dataStr
          .replace(/^(?:GET|POST)\s+\S+/m, `GET ${wsUrl}`)
          .replace(/^Host:\s*.+$/im, `Host: ${proxyUrl.hostname}`)
          .replace(new RegExp(origHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), proxyUrl.hostname);

        return origWrite(rewritten, ...rest);
      }
    }
    return origWrite(data, ...rest);
  };

  return socket;
};

console.log(`[whatsapp-proxy] Active: ${WHATSAPP_DOMAINS.join(', ')} → ${proxyHost}`);
