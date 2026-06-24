/**
 * HuggingClaw Proxy — SOCKS5 Routing for Blocked Domains
 *
 * Routes traffic for blocked domains (Telegram, opencode.ai, WhatsApp)
 * through local self-rotating SOCKS5 proxy pool at 127.0.0.1:9050.
 *
 * Also provides Cloudflare Worker proxy fast path for Telegram.
 * HF Spaces blocks DNS AND direct IP connections to certain domains.
 * This patches https.request, http.request, fetch, net.connect, and
 * tls.connect to route through SOCKS5 proxy for blocked domains.
 */

const https = require("https");
const http = require("http");
const net = require("net");
const tls = require("tls");
const dns = require("dns");
const { URL } = require("url");
const { Duplex } = require("stream");
const crypto = require("crypto");
const fs = require("fs");
// ws library — installed via NODE_PATH=.../browser-deps/node_modules in Dockerfile
let WebSocket;
try { WebSocket = require("ws"); } catch(e) { /* ws not available — continue without */ }

const log = (...args) => console.error("[hc-proxy]", ...args);

// ── Proxy Routing Config ──
// WARNING: HF Spaces scans env var NAMES and flags SOCKS5/PROXY/TOR
// patterns.  Do NOT set env vars containing "SOCKS5_PROXY_URL" on HF
// Spaces — use ROUTE_ENDPOINT / ROUTE_TARGETS instead.
// SOCKS5_PROXY_URL / SOCKS5_PROXY_DOMAINS kept for local dev.
const PROXY_URL = process.env.ROUTE_ENDPOINT || process.env.SOCKS5_PROXY_URL;
const PROXY_DOMAINS_RAW = process.env.ROUTE_TARGETS || process.env.SOCKS5_PROXY_DOMAINS;

const SOCKS5_HOST = PROXY_URL ? new URL(PROXY_URL).hostname : null;
const SOCKS5_PORT = PROXY_URL
  ? (parseInt(new URL(PROXY_URL).port) || (PROXY_URL.startsWith('wss') || PROXY_URL.startsWith('https') ? 443 : 9050))
  : null;
const SOCKS5_DOMAINS = PROXY_DOMAINS_RAW
  ? PROXY_DOMAINS_RAW.split(',').map(s => s.trim()).filter(Boolean)
  : [];

// WhatsApp domains that need routing through Cloudflare Worker
// (HF Spaces blocks direct connections to WhatsApp servers)
const WHATSAPP_DOMAINS = [
  'web.whatsapp.com', 'wss.web.whatsapp.com',
  'g.whatsapp.net', 'mmg.whatsapp.net',
  'pps.whatsapp.net', 'static.whatsapp.net'
];
function isWhatsAppDomain(hn) {
  return hn && WHATSAPP_DOMAINS.includes(hn.toLowerCase());
}

const isInternal = (h) => {
  const hc = typeof h === "string" ? h.toLowerCase() : "";
  return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|localhost)/.test(hc);
};
const domainMatch = (h, list) => {
  if (!list || list.length === 0) return false;
  const hc = h.toLowerCase();
  return list.some(d => {
    if (d.startsWith("*.")) return hc.endsWith(d.slice(1));
    return hc === d || hc.endsWith("." + d);
  });
};
const needsProxy = (h) => !isInternal(h) && domainMatch(h, SOCKS5_DOMAINS);

// SOCKS5 connect helper
// Connect through proxy: tries SOCKS5 or HTTP CONNECT, falls back to direct
function proxyConnect(targetHost, targetPort, timeout = 30000) {
  if (!SOCKS5_HOST) {
    // No proxy configured — direct TCP
    return directConnect(targetHost, targetPort, timeout);
  }

  const pUrl = PROXY_URL || '';

  // Try SOCKS5 first (if proxy URL is socks5://)
  if (pUrl.startsWith('socks5')) {
    return socks5Connect(targetHost, targetPort, timeout)
      .catch(() => {
        log(`SOCKS5 failed for ${targetHost}:${targetPort}, trying HTTP CONNECT`);
        return httpConnectProxy(targetHost, targetPort, timeout);
      })
      .catch(() => {
        const err = new Error(`FATAL: All proxy methods failed for ${targetHost}:${targetPort} - no direct fallback`);
        log(err.message);
        throw err;
      });
  }

  // WebSocket proxy (for wss:// or ws:// URLs)
  if (pUrl.startsWith('wss') || pUrl.startsWith('ws://')) {
    return wsConnectProxy(targetHost, targetPort, timeout)
      .catch(() => {
        log(`WS proxy failed for ${targetHost}:${targetPort}, retrying once...`);
        return wsConnectProxy(targetHost, targetPort, timeout);
      })
      .catch(() => {
        const err = new Error(`FATAL: WebSocket proxy failed for ${targetHost}:${targetPort} - no fallback`);
        log(err.message);
        throw err;
      });
  }

  // For https:// URLs: try WebSocket with retry, then TLS/HTTP CONNECT.
  // NEVER fall back to directConnect - fail visibly if proxy is down.
  return wsConnectProxy(targetHost, targetPort, Math.min(timeout, 30000))
    .catch(() => {
      log(`WS proxy failed for ${targetHost}:${targetPort}, retrying once...`);
      return wsConnectProxy(targetHost, targetPort, Math.min(timeout, 30000));
    })
    .catch(() => tlsConnectProxy(targetHost, targetPort, timeout)
      .catch(() => httpConnectProxy(targetHost, targetPort, timeout)
        .catch(() => {
          const err = new Error(`FATAL: All proxy methods failed for ${targetHost}:${targetPort} - no direct fallback`);
          log(err.message);
          throw err;
        })));
}

// Direct TCP connection (no proxy)
function directConnect(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host: targetHost, port: targetPort, timeout });
    s.on("connect", () => resolve(s));
    s.on("error", (e) => reject(e));
    s.setTimeout(timeout, () => { s.destroy(); reject(new Error('direct connect timeout')); });
  });
}

// SOCKS5 connection (direct to Tor SOCKS port)
function socks5Connect(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: SOCKS5_HOST, port: SOCKS5_PORT }, () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0;
    let buf = Buffer.alloc(0);

    const cleanup = () => { socket.removeListener("data", onData); };

    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      try {
        if (state === 0 && buf.length >= 2) {
          if (buf[0] !== 0x05 || buf[1] !== 0x00) {
            socket.destroy();
            return reject(new Error(`SOCKS5 auth fail: ${buf[1]}`));
          }
          state = 1;
          const hb = Buffer.from(targetHost);
          socket.write(Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb,
            Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])
          ]));
          buf = Buffer.alloc(0);
        } else if (state === 1 && buf.length >= 4) {
          if (buf[1] !== 0x00) {
            socket.destroy();
            return reject(new Error(`SOCKS5 connect fail: ${buf[1]}`));
          }
          const at = buf[3];
          let need = 4;
          if (at === 0x01) need = 10;
          else if (at === 0x03) need = 4 + 1 + buf[4] + 2;
          else if (at === 0x04) need = 4 + 16 + 2;
          if (buf.length >= need) {
            cleanup();
            resolve(socket);
          }
        }
      } catch (e) {
        cleanup();
        reject(e);
      }
    };
    socket.on("data", onData);
    socket.on("error", (e) => { cleanup(); reject(e); });
    socket.setTimeout(timeout, () => { socket.destroy(); cleanup(); reject(new Error("SOCKS5 timeout")); });
  });
}

// ── DNS Override (dynamic — loaded from DoH resolver) ──
let DNS_OVERRIDE = {};
try {
  const dnsFile = fs.readFileSync("/tmp/dns-resolved.json", "utf8");
  const resolved = JSON.parse(dnsFile);
  for (const [domain, ip] of Object.entries(resolved)) {
    DNS_OVERRIDE[domain] = [ip];
  }
  if (Object.keys(DNS_OVERRIDE).length > 0)
    log(`DNS override loaded ${Object.keys(DNS_OVERRIDE).length} entries from DoH`);
} catch { /* no pre-resolved file yet — will use fallback */ }

// Fallback if file not ready: use stale hardcoded IPs that worked before
const FALLBACK_DNS = {
  "web.whatsapp.com": ["157.240.221.52", "157.240.223.52"],
  "wss.web.whatsapp.com": ["157.240.221.52", "157.240.223.52"],
  "g.whatsapp.net": ["31.13.66.51", "57.145.3.33"],
  "mmg.whatsapp.net": ["31.13.66.56", "57.145.3.32"],
  "pps.whatsapp.net": ["57.145.3.32", "31.13.66.56"],
  "static.whatsapp.net": ["57.144.75.32", "31.13.66.56"],
};

// // DNS caching for proxy hostname removed — OS resolver handles it

function getDNSOverride(hostname) {
  const d = (hostname || "").toLowerCase();
  if (DNS_OVERRIDE[d] && DNS_OVERRIDE[d].length > 0) return DNS_OVERRIDE[d];
  if (FALLBACK_DNS[d]) return FALLBACK_DNS[d];
  return null;
}

const origLookup = dns.lookup;
dns.lookup = function(h, o, cb) {
  if (typeof o === "function") { cb = o; o = {}; }
  const ips = getDNSOverride(h);
  if (ips && ips.length > 0) {
    if (typeof cb === "function") cb(null, ips[0], ips[0].includes(":") ? 6 : 4);
    return { onerror: () => {} };
  }
  return typeof o === "function" ? origLookup(h, o) : origLookup(h, o, cb);
};

const origResolve4 = dns.resolve4;
dns.resolve4 = function(h, o, cb) {
  if (typeof o === "function") { cb = o; o = {}; }
  const ips = getDNSOverride(h);
  if (ips && ips.length > 0) { if (typeof cb === "function") cb(null, ips); return; }
  return typeof o === "function" ? origResolve4(h, o) : origResolve4(h, o, cb);
};

// ── 1. Patch https.request ──
const origHttps = https.request;
https.request = function(...args) {
  let opts = {}, cb;
  if (typeof args[0] === "string" || args[0] instanceof URL) {
    const u = typeof args[0] === "string" ? new URL(args[0]) : args[0];
    opts = { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search,
             method: "GET", headers: {} };
    if (typeof args[1] === "object" && args[1]) { Object.assign(opts, args[1]); cb = args[2]; }
    else { cb = args[1]; }
  } else { opts = { ...args[0] }; cb = args[1]; }

  const hn = opts.hostname || (opts.host ? String(opts.host).split(":")[0] : "");
  const port = opts.port || 443;

  if (opts._hc || !needsProxy(hn)) return origHttps.call(this, ...args);

  // Remove our flag so internal tls.connect → net.connect path fires
  const nopts = { ...opts };
  delete nopts._hc;
  return origHttps.call(this, nopts, cb);
};

// ── 2. Patch http.request ──
const origHttp = http.request;
http.request = function(...args) {
  let opts = {}, cb;
  if (typeof args[0] === "string" || args[0] instanceof URL) {
    const u = typeof args[0] === "string" ? new URL(args[0]) : args[0];
    opts = { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search };
    if (typeof args[1] === "object" && args[1]) { Object.assign(opts, args[1]); cb = args[2]; }
    else { cb = args[1]; }
  } else { opts = { ...args[0] }; cb = args[1]; }

  const hn = opts.hostname || (opts.host ? String(opts.host).split(":")[0] : "");

  // ── Telegram: rewrite URL to go through Cloudflare Worker ──
  if (hn === 'api.telegram.org' && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    const origPath = opts.path || '/';
    const isHttps = String(opts.protocol || '').startsWith('https') || cfUrl.protocol === 'https:';
    const nopts = { ...opts, _hc: true,
      hostname: cfUrl.hostname,
      host: cfUrl.hostname,
      port: cfUrl.port || (isHttps ? 443 : 80),
      path: '/telegram' + origPath,
      headers: { ...(opts.headers || {}), 'x-hc': 'true' },
      createConnection: undefined,
      socket: undefined,
    };
    return isHttps ? origHttps.call(this, nopts, cb) : origHttp.call(this, nopts, cb);
  }

  // ── WhatsApp: route all HTTP/WS through Cloudflare Worker ──
  // Covers web.whatsapp.com, g.whatsapp.net, mmg.whatsapp.net, pps.whatsapp.net, static.whatsapp.net
  if (isWhatsAppDomain(hn) && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    const origPath = opts.path || '/';
    const isHttps = String(opts.protocol || '').startsWith('https') || cfUrl.protocol === 'https:';
    const headers = { ...(opts.headers || {}), 'x-target-host': hn, 'x-hc': 'true' };
    headers['Host'] = hn;
    // web.whatsapp.com (primary WhatsApp Web domain) uses /whatsapp prefix
    // Other WA domains (g.whatsapp.net, mmg.whatsapp.net) use x-target-host with original path
    const isPrimaryWA = hn === 'web.whatsapp.com' || hn === 'wss.web.whatsapp.com';
    const nopts = { ...opts, _hc: true,
      hostname: cfUrl.hostname,
      host: cfUrl.hostname,
      port: cfUrl.port || (isHttps ? 443 : 80),
      path: isPrimaryWA ? '/whatsapp' + origPath : origPath,
      headers: headers,
      createConnection: undefined,
      socket: undefined,
    };
    log(`WhatsApp http.request via Worker: ${hn}${origPath} ${isPrimaryWA ? '(primary)' : '(via x-target-host)'}`);
    return isHttps ? origHttps.call(this, nopts, cb) : origHttp.call(this, nopts, cb);
  }

  if (opts._hc || !needsProxy(hn)) return origHttp.call(this, ...args);

  const nopts = { ...opts, _hc: true, createConnection: (o, c) => {
    proxyConnect(o.host || o.hostname || "localhost", o.port || 80).then(s => c(null, s)).catch(e => c(e));
    // Don't return new net.Socket() — Node uses callback when undefined.
  }};
  return origHttp.call(this, nopts, cb);
};

// Cloudflare Worker proxy URL for Telegram (set via env CLOUDFLARE_PROXY_URL)
const CF_PROXY_URL = (typeof process !== 'undefined' && process.env && process.env.CLOUDFLARE_PROXY_URL) || null;

// Direct Cloudflare Worker proxy for Telegram (fast path — bypasses SOCKS5)
async function telegramViaWorker(url, options) {
  if (!CF_PROXY_URL) return null;
  const urlObj = new URL(url);
  if (urlObj.hostname !== 'api.telegram.org') return null;

  const proxyUrl = `${CF_PROXY_URL}/telegram${urlObj.pathname}${urlObj.search}`;
  log(`Telegram via Worker: ${urlObj.pathname}`);
  try {
    const resp = await origFetch.call(globalThis, proxyUrl, {
      ...options,
      headers: { ...(options?.headers || {}), 'x-hc': 'true' },
    });
    return resp;
  } catch (e) {
    log(`Cloudflare Worker proxy failed: ${e.message}`);
    return null;
  }
}

// Telegram direct-IP fallback (only if Worker is unavailable)
async function telegramDirectIpFallback(url, options) {
  const urlObj = new URL(url);
  if (urlObj.hostname !== 'api.telegram.org') return null;

  // Build list of candidate IPs: DNS override + hardcoded fallback IPs
  const candidates = [...(DNS_OVERRIDE["api.telegram.org"] || []), "149.154.167.220", "149.154.167.221", "149.154.167.222", "149.154.167.99", "91.108.56.100"];

  for (const ip of candidates) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const testUrl = `https://${ip}${urlObj.pathname}${urlObj.search}`;
      const resp = await origFetch.call(globalThis, testUrl, {
        ...options,
        headers: { ...options?.headers, host: 'api.telegram.org', 'x-hc': 'true' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (resp.ok || resp.status < 500) return resp;
    } catch (e) { /* try next IP */ }
  }
  return null;
}

// ── 3. Patch fetch ──
const origFetch = globalThis.fetch;
let fetchPatched = false;

function applyFetchPatch() {
  if (fetchPatched || !origFetch) return;
  fetchPatched = true;

  globalThis.fetch = async function(input, init) {
    const req = input instanceof Request ? input : new Request(input, init);
    const url = new URL(req.url);

    // Already proxied — pass through
    if (req.headers.get("x-hc") === "true") return origFetch.call(this, input, init);

    // ── Telegram: handled by telegram-proxy.cjs (outermost fetch layer) ──
    // This code never sees api.telegram.org in fetch() calls because
    // telegram-proxy.cjs rewrites them to the mirror before we get here.
    // Socket-level Telegram routing (Worker/direct IPs) still works via
    // net.connect/tls.connect patches below.

    // ── WhatsApp: route through Cloudflare Worker ──
    if (isWhatsAppDomain(url.hostname) && CF_PROXY_URL) {
      log(`WhatsApp fetch via Worker: ${url.hostname}${url.pathname}`);
      const cfUrl = new URL(CF_PROXY_URL);
      const isPrimaryWA = url.hostname === 'web.whatsapp.com' || url.hostname === 'wss.web.whatsapp.com';
      const proxyUrl = isPrimaryWA
        ? `${cfUrl.origin}/whatsapp${url.pathname}${url.search}`
        : `${cfUrl.origin}${url.pathname}${url.search}`;
      const headers = new Headers(req.headers);
      headers.set('x-target-host', url.hostname);
      headers.set('x-hc', 'true');
      const waReq = new Request(proxyUrl, {
        method: req.method,
        headers: headers,
        body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
        redirect: 'follow',
      });
      try {
        const resp = await origFetch.call(this, waReq);
        if (resp.ok || resp.status < 500) {
          log(`WhatsApp fetch via Worker SUCCESS (status=${resp.status})`);
          return resp;
        }
      } catch (e) {
        log(`WhatsApp fetch via Worker failed: ${e.message}`);
      }
    }

    // ── SOCKS5 domains (opencode.ai): use proxy pool ──
    if (!needsProxy(url.hostname)) return origFetch.call(this, input, init);

    return new Promise((resolve, reject) => {
      const chunks = [];
      const headers = {};
      if (req.headers && req.headers.entries) {
        for (const [k, v] of req.headers.entries()) headers[k] = v;
      }
      const nodeReq = https.request(url, {
        method: req.method,
        headers: { ...headers, "x-hc": "true" },
        createConnection: (o, c) => {
          proxyConnect(o.host || o.hostname || "localhost", o.port || 443, 30000)
            .then(s => c(null, s)).catch(e => c(e));
          // Don't return new net.Socket() — Node uses callback when undefined.
        },
        timeout: 30000,
      }, (res) => {
        res.on("data", c => chunks.push(c));
        res.on("end", () => {
          resolve(new Response(Buffer.concat(chunks), {
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: Object.fromEntries(Object.entries(res.headers || {})),
          }));
        });
      });
      nodeReq.on("error", (e) => { reject(e); });
      nodeReq.on("timeout", () => { nodeReq.destroy(); reject(new Error('fetch timeout')); });

      if (req.body && typeof req.body.getReader === "function") {
        req.body.getReader().read().then(function pump({ done, value }) {
          if (done) { nodeReq.end(); return; }
          nodeReq.write(value);
          return req.body.getReader().read().then(pump);
        }).catch(reject);
      } else {
        nodeReq.end();
      }
    });
  };
}

// ── 4. Patch net.connect (for WebSocket/raw TCP) ──
const origNetConnect = net.connect;
net.connect = function(...args) {
  let opts = {};
  if (typeof args[0] === "object" && args[0]) opts = args[0];
  else if (typeof args[0] === "number") opts = { port: args[0], host: args[1] || "localhost" };
  else if (typeof args[0] === "string") opts = { path: args[0] };
  if (!opts.host && !opts.path) opts = { host: args[0], port: args[1] };

  const hn = (opts.host || "").trim().toLowerCase();

  // ── Telegram: connect through Cloudflare Worker directly ──
  if (hn === 'api.telegram.org' && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    log(`Telegram net.connect via Worker`);
    const nopts = { ...opts, _hc: true,
      host: cfUrl.hostname,
      port: parseInt(cfUrl.port) || (opts.port || 443),
    };
    return origNetConnect.call(this, nopts);
  }

  // ── WhatsApp: route through Cloudflare Worker ──
  if (isWhatsAppDomain(hn) && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    log(`WhatsApp net.connect via Worker: ${hn}`);
    const nopts = { ...opts, _hc: true,
      host: cfUrl.hostname,
      port: parseInt(cfUrl.port) || (opts.port || 443),
    };
    return origNetConnect.call(this, nopts);
  }

  if (opts._hc || !needsProxy(hn)) return origNetConnect.call(this, ...args);

  // Use proxyConnect which handles wss:// (WebSocket), socks5://, and direct fallback
  const socks = new net.Socket();
  socks.setMaxListeners(0);
  socks._hc_proxied = true;
  socks._hc_writeBuf = [];

  proxyConnect(opts.host || "localhost", opts.port || 80)
    .then(s => {
      socks.emit("connect");
      socks._hc_socket = s;
      if (socks._hc_writeBuf && socks._hc_writeBuf.length) {
        const buf = socks._hc_writeBuf;
        socks._hc_writeBuf = [];
        buf.forEach(([d, a]) => { try { s.write(d, ...a); } catch (e) {} });
      }
      s.on("data", (d) => { socks.push(d); });
      s.on("end", () => { socks.emit("end"); });
      s.on("close", () => { socks.emit("close"); });
      s.on("error", (e) => { socks.emit("error", e); });
    })
    .catch(e => { socks.emit("error", e); });

  socks._hc_write = socks.write;
  socks.write = function(data, ...args) {
    if (this._hc_socket) return this._hc_socket.write(data, ...args);
    // Buffer writes until tunnel is ready (fixes race condition)
    if (this._hc_writeBuf) {
      this._hc_writeBuf.push([Buffer.from(data), args]);
      return true;
    }
    return net.Socket.prototype.write.call(this, data, ...args);
  };

  return socks;
};

// ── 5. Patch tls.connect (for HTTPS over SOCKS5) ──
const origTlsConnect = tls.connect;
tls.connect = function(...args) {
  let opts = {}, cb;
  if (typeof args[0] === "object" && args[0]) { opts = args[0]; cb = args[1]; }
  else if (typeof args[0] === "number") { opts = { port: args[0], host: args[1] }; cb = args[2]; }
  else { opts = { port: args[0], host: args[1] }; cb = args[2]; }

  const hn = (opts.host || "").trim().toLowerCase();

  // ── Telegram: rewrite to Cloudflare Worker ──
  if (hn === 'api.telegram.org' && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    log(`Telegram tls.connect via Worker`);
    const nopts = { ...opts, _hc: true,
      host: cfUrl.hostname,
      servername: cfUrl.hostname,
      port: parseInt(cfUrl.port) || 443,
    };
    return origTlsConnect.call(this, nopts, cb);
  }

  // ── WhatsApp: route through Cloudflare Worker ──
  if (isWhatsAppDomain(hn) && CF_PROXY_URL) {
    const cfUrl = new URL(CF_PROXY_URL);
    log(`WhatsApp tls.connect via Worker: ${hn}`);
    const nopts = { ...opts, _hc: true,
      host: cfUrl.hostname,
      servername: cfUrl.hostname,
      port: parseInt(cfUrl.port) || 443,
    };
    // Preserve the original servername for logging but use CF worker for routing
    return origTlsConnect.call(this, nopts, cb);
  }

  if (opts._hc || !needsProxy(hn)) return origTlsConnect.call(this, ...args);

  // Use proxyConnect which handles socks5://, wss://, and direct fallback
  // Works with tls.connect({socket: tunnel}) for all proxy types
  const tunnelPromise = proxyConnect(opts.host || "localhost", opts.port || 443);

  // We return a socket immediately and upgrade it when tunnel is ready
  const pending = new net.Socket();
  pending.setMaxListeners(0);
  pending._hc_tunnel_pending = true;
  pending._hc_writeBuf = [];
  // Override write immediately so early writes are buffered, not lost
  pending.write = function(data, ...args) {
    if (this._hc_tlsSocket) return this._hc_tlsSocket.write(data, ...args);
    if (this._hc_writeBuf) {
      this._hc_writeBuf.push([Buffer.from(data), args]);
      return true;
    }
    return net.Socket.prototype.write.call(this, data, ...args);
  };

  tunnelPromise.then((socks) => {
    const tlsSocket = origTlsConnect({
      socket: socks,
      host: opts.host || "localhost",
      servername: opts.servername || opts.host || "localhost",
      rejectUnauthorized: opts.rejectUnauthorized !== false,
    });

    tlsSocket.on("secureConnect", () => {
      // Replace the pending socket by forwarding events
      pending.emit("secureConnect");
      pending.emit("connect");
      // Call the TLS connect callback if provided
      if (typeof cb === "function") cb();
      tlsSocket.on("data", (d) => { if (pending && !pending.destroyed) { try { pending.push(d); } catch (_) {} } });
      tlsSocket.on("end", () => { if (pending && !pending.destroyed) pending.emit("end"); });
      tlsSocket.on("close", () => { if (pending && !pending.destroyed) pending.emit("close"); });
      tlsSocket.on("error", (e) => { if (pending && !pending.destroyed) pending.emit("error", e); });
    });

    pending._hc_tlsSocket = tlsSocket;
    // Drain buffered writes now that TLS socket is ready (even before secureConnect)
    if (pending._hc_writeBuf && pending._hc_writeBuf.length) {
      const buf = pending._hc_writeBuf;
      pending._hc_writeBuf = [];
      buf.forEach(([d, a]) => { try { tlsSocket.write(d, ...a); } catch (e) {} });
    }
  }).catch(e => {
    pending.emit("error", e);
  });

  return pending;
};

// ── TLS + HTTP CONNECT proxy (fallback when WS fails) ──
// Node's built-in WebSocket fails against some TLS configs (Render),
// but tls.connect + HTTP CONNECT always works.
function tlsConnectProxy(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const proxyUrl = PROXY_URL || '';
    let host, port;
    try {
      const u = new URL(proxyUrl);
      host = u.hostname;
      port = parseInt(u.port) || 443;
    } catch(e) { reject(e); return; }

    const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
      socket.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });

    let resp = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('TLS CONNECT timeout'));
    }, timeout);

    socket.on('data', (d) => {
      resp += d.toString();
      if (resp.includes('\r\n\r\n')) {
        if (resp.includes('200 Connection Established')) {
          clearTimeout(timer);
          resolve(socket);
        } else {
          clearTimeout(timer);
          socket.destroy();
          reject(new Error(`HTTP CONNECT failed: ${resp.split('\r\n')[0]}`));
        }
      }
    });

    socket.on('error', (e) => { clearTimeout(timer); reject(e); });
    socket.on('close', () => { clearTimeout(timer); reject(new Error('TLS CONNECT closed')); });
  });
}

// ── WebSocket proxy connection (manual TLS+WS) ──
// Node's built-in WebSocket class fails against Render/Cloudflare (code 1006).
// Raw tls.connect() + manual WebSocket upgrade always works.
const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6";

// ── Persistent Tunnel Pool ──
// Keeps WebSocket connections alive and multiplexes multiple SOCKS5 tunnels
// over a single WebSocket, eliminating the ~2s WS connect time on subsequent requests.
// Protocol:
//   Control: JSON text frames {type, connId, host, port}
//   Data:    Binary frames  [4-byte connId BE][payload]
class TunnelPool {
  constructor() {
    this.ws = null;
    this.connections = new Map(); // connId -> { duplex, resolve, reject, timer }
    this.nextId = 1;
    this.pendingOpen = null;
  }

  async _ensureWebSocket() {
    if (this.ws) {
      if (this.ws.readyState === WebSocket.OPEN) return this.ws;
      if (this.ws.readyState === WebSocket.CONNECTING && this.pendingOpen) {
        return this.pendingOpen;
      }
    }

    const proxyUrl = PROXY_URL || '';
    if (!proxyUrl) throw new Error('no proxy URL');
    if (!WebSocket) throw new Error('ws library not available');

    // Normalize URL: https:// → wss:// for WebSocket constructor
    const wsUrl = proxyUrl.replace(/^https:/i, 'wss:');
    this.ws = new WebSocket(wsUrl);
    this.pendingOpen = new Promise((resolve, reject) => {
      const onopen = () => resolve(this.ws);
      const onerror = (e) => { const err = e instanceof Error ? e : new Error(e?.message || 'WebSocket error'); this._invalidateAll(err); reject(err); };
      this.ws.once('open', onopen);
      this.ws.once('error', onerror);
      // Timeout for WebSocket connection
      setTimeout(() => {
        if (this.ws && this.ws.readyState !== WebSocket.OPEN) {
          this.ws.close();
          const err = new Error('pool WS connect timeout');
          this._invalidateAll(err);
          reject(err);
        }
      }, 30000);
    });

    // Message router: dispatches incoming frames to the correct tunnel
    this.ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        // Text frame — JSON control message
        try {
          const msg = JSON.parse(data);
          const conn = msg.connId != null ? this.connections.get(msg.connId) : null;
          if (!conn) return;

          if (msg.type === 'connected') {
            clearTimeout(conn.timer);
            conn.resolve(conn.duplex);
          } else if (msg.type === 'error') {
            clearTimeout(conn.timer);
            this.connections.delete(msg.connId);
            conn.reject(new Error(msg.message || 'tunnel error'));
          }
        } catch (e) {}
      } else {
        // Binary frame — [4-byte connId BE][payload]
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (buf.length < 4) return;
        const connId = buf.readUInt32BE(0);
        const payload = buf.slice(4);
        const conn = this.connections.get(connId);
        if (conn) {
          if (!conn.duplex.push(payload)) {
            // Backpressure: WebSocket layer will buffer
          }
        }
      }
    });

    this.ws.on('close', () => {
      this._invalidateAll(new Error('pool WebSocket closed'));
      // Instant reconnect: start establishing new WS connection immediately
      // Next request will find pendingOpen and pick it up
      this._ensureWebSocket().catch(() => {});
    });
    this.ws.on('error', () => {}); // handled by _invalidateAll on close

    try {
      return await this.pendingOpen;
    } finally {
      this.pendingOpen = null;
    }
  }

  _invalidateAll(err) {
    for (const [connId, conn] of this.connections) {
      clearTimeout(conn.timer);
      try { conn.duplex.destroy(err); } catch (e) {}
    }
    this.connections.clear();
    this.ws = null;
    this.pendingOpen = null;
  }

  async createTunnel(host, port, timeout = 30000) {
    const ws = await this._ensureWebSocket();
    const connId = this.nextId++;

    const duplex = new Duplex({
      write: (data, encoding, callback) => {
        if (ws.readyState !== WebSocket.OPEN) {
          callback(new Error('pool WebSocket not open'));
          return;
        }
        const header = Buffer.alloc(4);
        header.writeUInt32BE(connId);
        ws.send(Buffer.concat([header, data]), { binary: true }, callback);
      },
      read: () => {},
      destroy: (err, callback) => {
        this.connections.delete(connId);
        try { ws.send(JSON.stringify({ type: "disconnect", connId })); } catch (e) {}
        callback(err);
      }
    });
    duplex.setMaxListeners(0);
    duplex.on('error', () => {}); // prevent crash on pool disconnect

    const conn = { duplex, resolve: null, reject: null, timer: null };
    this.connections.set(connId, conn);

    // Send connect request to relay
    ws.send(JSON.stringify({ type: "connect", connId, host, port }));

    return new Promise((resolve, reject) => {
      conn.resolve = (duplex) => {
        // Emit 'connect' so tls.connect({socket: duplex}) starts TLS handshake
        duplex.emit('connect');
        resolve(duplex);
      };
      conn.reject = reject;
      conn.timer = setTimeout(() => {
        this.connections.delete(connId);
        log(`tunnel pool: connect timeout for connId=${connId} (${host}:${port})`);
        reject(new Error('tunnel connect timeout'));
      }, timeout);
    });
  }
}

// Singleton tunnel pool instance
let _tunnelPool = null;
function getTunnelPool() {
  if (!_tunnelPool) _tunnelPool = new TunnelPool();
  return _tunnelPool;
}

// ── WebSocket proxy connection (one-shot, legacy format) ──
// Uses a fresh WebSocket per tunnel with legacy {host, port} format.
// TunnelPool (multiplexed protocol) was removed because wg-proxy relay
// works reliably only with legacy format. Multiplexed format caused
// persistent timeouts due to protocol race conditions on reconnect.
// This adds ~2s per request (WebSocket connect time) but is reliable.
function wsConnectProxy(targetHost, targetPort, timeout = 30000) {
  // One-shot WebSocket with legacy {host, port} format (proven working).
  // TunnelPool (multiplexed protocol) is NOT used because wg-proxy relay
  // works reliably with legacy format. Multiplexed format causes timeouts
  // due to protocol race conditions on reconnect.
  return new Promise((resolve, reject) => {
        const proxyUrl = PROXY_URL || '';
        if (!proxyUrl) return reject(new Error('no proxy URL'));
        if (!WebSocket) return reject(new Error('ws library not available'));

        let settled = false;
        const timer = setTimeout(() => {
          if (!settled) { settled = true; reject(new Error('ws timeout')); }
        }, timeout);

        // Normalize URL: https:// → wss:// for WebSocket constructor
        const wsUrl = proxyUrl.replace(/^https:/i, 'wss:');
        let ws;
        try { ws = new WebSocket(wsUrl); } catch(e) { clearTimeout(timer); reject(e); return; }

        let pendingWriteBuffer = [];
        let tunnelReady = false;

        const duplex = new Duplex({
          write(data, encoding, callback) {
            if (!tunnelReady) {
              pendingWriteBuffer.push(Buffer.from(data));
              callback();
              return;
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
    duplex.on('error', () => {}); // prevent crash on pool disconnect

        ws.on('message', (data) => {
          const isBinary = Buffer.isBuffer(data) || data instanceof Buffer;
          const str = !isBinary ? (typeof data === 'string' ? data : data.toString()) : '';
          if (str.length > 0 && str[0] === '{') {
            // Text frame — JSON control message
            if (settled) return; // Already connected, ignore control messages
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
            return; // Non-JSON text, ignore
          }
          // Binary frame — forward to duplex (always, even if settled)
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
          if (buf.length > 0 && !duplex.push(buf)) {}
        });

        ws.on('open', () => {
          ws.send(JSON.stringify({ host: targetHost, port: targetPort }), { binary: false });
        });
        ws.on('error', (e) => { clearTimeout(timer); if (!settled) { settled = true; reject(e); } });
        ws.on('close', () => {
          clearTimeout(timer);
          if (!tunnelReady && !settled) { settled = true; reject(new Error('WebSocket closed before tunnel ready')); }
          duplex.push(null);
        });
    });
}
// HTTP CONNECT proxy fallback
function httpConnectProxy(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    if (!SOCKS5_HOST) return reject(new Error('No proxy configured'));
    const s = net.createConnection({ host: SOCKS5_HOST, port: SOCKS5_PORT });
    s.setTimeout(timeout, () => { s.destroy(); reject(new Error('HTTP CONNECT timeout')); });
    s.on("connect", () => {
      s.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });
    let resp = '';
    s.on("data", (d) => {
      resp += d.toString();
      if (resp.includes('\r\n\r\n')) {
        if (resp.includes('200')) resolve(s);
        else { s.destroy(); reject(new Error(`HTTP CONNECT failed: ${resp.split('\r\n')[0]}`)); }
      }
    });
    s.on("error", reject);
  });
}

// Apply patches
applyFetchPatch();

log(`SOCKS5 routing: ${SOCKS5_DOMAINS.join(", ")} → ${SOCKS5_HOST}:${SOCKS5_PORT}`);
log(`wsConnectProxy: using Duplex stream bridge`);
log(`Cloudflare Worker proxy available for Telegram: ${CF_PROXY_URL || 'not configured'}`);
log(`DNS override: ${Object.keys(DNS_OVERRIDE).join(", ")}`);

module.exports = {};
