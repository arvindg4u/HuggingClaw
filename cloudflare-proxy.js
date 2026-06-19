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

const log = (...args) => console.error("[hc-proxy]", ...args);

// ── SOCKS5 Proxy Pool Config ──
const SOCKS5_HOST = process.env.SOCKS5_PROXY_URL ? new URL(process.env.SOCKS5_PROXY_URL).hostname : null;
const SOCKS5_PORT = process.env.SOCKS5_PROXY_URL
  ? (parseInt(new URL(process.env.SOCKS5_PROXY_URL).port) || (process.env.SOCKS5_PROXY_URL.startsWith('https') || process.env.SOCKS5_PROXY_URL.startsWith('wss') ? 443 : 9050)) : null;

// Domains routed through SOCKS5 proxy (set by env var).
// SOCKS5_PROXY_URL = "socks5://host:port" (e.g. your Render Tor proxy)
// SOCKS5_PROXY_DOMAINS = "opencode.ai,api.telegram.org" (comma-separated)
// When SOCKS5_PROXY_URL is unset (default): direct connection, no proxy.
const SOCKS5_DOMAINS = process.env.SOCKS5_PROXY_DOMAINS
  ? process.env.SOCKS5_PROXY_DOMAINS.split(',').map(s => s.trim()).filter(Boolean)
  : [];

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

  const pUrl = (typeof process !== 'undefined' && process.env && process.env.SOCKS5_PROXY_URL) || '';

  // Try SOCKS5 first (if proxy URL is socks5://)
  if (pUrl.startsWith('socks5')) {
    return socks5Connect(targetHost, targetPort, timeout)
      .catch(() => directConnect(targetHost, targetPort, timeout));
  }

  // WebSocket proxy (for wss:// or ws:// URLs) — directly, no HTTP CONNECT attempt
  if (pUrl.startsWith('wss') || pUrl.startsWith('ws://')) {
    return wsConnectProxy(targetHost, targetPort, timeout)
      .catch(() => directConnect(targetHost, targetPort, timeout));
  }

  // For https:// URLs: try WebSocket first with quick timeout (bypasses Cloudflare TCP blocks),
  // then HTTP CONNECT, then direct
  // Allow 30s for WebSocket proxy — cold Tor + cold Render free tier
  // can take 10-20s to bootstrap. 8s was too short and caused fallback to
  // direct TCP, which bypassed Tor and lost IP rotation.
  return wsConnectProxy(targetHost, targetPort, Math.min(timeout, 30000))
    .catch(() => httpConnectProxy(targetHost, targetPort, timeout)
      .catch(() => directConnect(targetHost, targetPort, timeout)));
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

// ── DNS Override (for domains where direct IPs are not firewalled) ──
const DNS_OVERRIDE = {
  "web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
  "wss.web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
};

const origLookup = dns.lookup;
dns.lookup = function(h, o, cb) {
  if (typeof o === "function") { cb = o; o = {}; }
  const d = (h || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE[d];
  if (ips && ips.length > 0) {
    if (typeof cb === "function") cb(null, ips[0], ips[0].includes(":") ? 6 : 4);
    return { onerror: () => {} };
  }
  return typeof o === "function" ? origLookup(h, o) : origLookup(h, o, cb);
};

const origResolve4 = dns.resolve4;
dns.resolve4 = function(h, o, cb) {
  if (typeof o === "function") { cb = o; o = {}; }
  const d = (h || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE[d];
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

  const nopts = { ...opts, _hc: true, createConnection: (o, c) => {
    proxyConnect(o.host || o.hostname || "localhost", o.port || 443)
      .then(s => c(null, s)).catch(e => c(e));
    // Must NOT return new net.Socket() — Node would use that instead
    // of the callback socket. Return undefined → Node uses callback.
  }};
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
    // HTTP for Telegram is unlikely but handle it
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

    // ── Telegram: use Cloudflare Worker proxy directly (fast path, no SOCKS5) ──
    if (url.hostname === 'api.telegram.org') {
      log(`Telegram fetch intercepted, CF_PROXY_URL=${CF_PROXY_URL ? 'set' : 'not set'}`);
      return new Promise((resolve, reject) => {
        telegramViaWorker(url, { method: req.method, headers: Object.fromEntries(req.headers.entries()) })
          .then(r => {
            if (r) {
              log(`Telegram via Worker SUCCESS (status=${r.status})`);
              resolve(r);
              return;
            }
            log('Telegram Worker returned null, trying direct IPs...');
            telegramDirectIpFallback(url, { method: req.method, headers: Object.fromEntries(req.headers.entries()) })
              .then(r2 => {
                if (r2) { log(`Telegram via direct IP SUCCESS`); resolve(r2); }
                else reject(new Error('Telegram unreachable'));
              })
              .catch(reject);
          })
          .catch(reject);
      });
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

  if (opts._hc || !needsProxy(hn)) return origNetConnect.call(this, ...args);

  // Create a proxy socket
  const socks = new net.Socket();
  socks._hc_proxied = true;

  socks5Connect(opts.host || "localhost", opts.port || 80)
    .then(s => {
      // Replace the socket's underlying connection by re-emitting
      socks.emit("connect");
      socks._hc_socket = s;
      // Forward data
      s.on("data", (d) => { socks.emit("data", d); });
      s.on("end", () => { socks.emit("end"); });
      s.on("close", () => { socks.emit("close"); });
      s.on("error", (e) => { socks.emit("error", e); });
    })
    .catch(e => { socks.emit("error", e); });

  socks._hc_write = socks.write;
  socks.write = function(data, ...args) {
    if (this._hc_socket) return this._hc_socket.write(data, ...args);
    return this._hc_write.call(this, data, ...args);
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

  if (opts._hc || !needsProxy(hn)) return origTlsConnect.call(this, ...args);

  // Create a SOCKS5 connection and wrap TLS over it
  const tunnelPromise = socks5Connect(opts.host || "localhost", opts.port || 443);

  // We return a socket immediately and upgrade it when tunnel is ready
  const pending = new net.Socket();
  pending._hc_tunnel_pending = true;

  tunnelPromise.then((socks) => {
    const tlsSocket = origTlsConnect({
      socket: socks,
      host: opts.host || "localhost",
      servername: opts.servername || opts.host || "localhost",
      rejectUnauthorized: opts.rejectUnauthorized !== false,
    });

    tlsSocket.on("secureConnect", () => {
      // Replace the pending socket by forwarding events
      pending.emit("connect");
      tlsSocket.on("data", (d) => pending.emit("data", d));
      tlsSocket.on("end", () => pending.emit("end"));
      tlsSocket.on("close", () => pending.emit("close"));
      tlsSocket.on("error", (e) => pending.emit("error", e));
    });

    pending._hc_tlsSocket = tlsSocket;
    pending.write = function(data, ...args) {
      if (this._hc_tlsSocket) return this._hc_tlsSocket.write(data, ...args);
      return net.Socket.prototype.write.call(this, data, ...args);
    };
  }).catch(e => {
    pending.emit("error", e);
  });

  return pending;
};

// ── WebSocket proxy connection ──
function wsConnectProxy(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const proxyUrl = process.env.SOCKS5_PROXY_URL || '';
    let wsUrl = proxyUrl;
    if (wsUrl.startsWith('http://')) wsUrl = wsUrl.replace(/^http:/, 'ws:');
    else if (wsUrl.startsWith('https://')) wsUrl = wsUrl.replace(/^https:/, 'wss:');
    wsUrl += '/proxy';

    let ws;
    try { ws = new WebSocket(wsUrl); } catch(e) { reject(e); return; }
    ws.binaryType = 'arraybuffer';
    const timer = setTimeout(() => { try { ws.close(); } catch(e){} reject(new Error('ws timeout')); }, timeout);

    ws.onopen = () => {
      // Send target info
      ws.send(JSON.stringify({ host: targetHost, port: targetPort }));
    };

    ws.onmessage = (event) => {
      let msg;
      if (typeof event.data === 'string') msg = event.data;
      else if (event.data instanceof ArrayBuffer) msg = Buffer.from(event.data).toString();
      else if (ArrayBuffer.isView(event.data)) msg = Buffer.from(event.data.buffer, event.data.byteOffset, event.data.byteLength).toString();
      else msg = event.data.toString();
      try {
        const json = JSON.parse(msg);
        if (json.error) { ws.close(); reject(new Error(json.error)); return; }
        if (json.status === 'connected') {
          clearTimeout(timer);
          // Create a proper Duplex stream wrapping the WebSocket.
          // tls.connect() requires a proper stream.Duplex for the `socket` option.
          // A plain object with on/write/end methods causes silent TLS failure.
          const tunnel = new Duplex({
            write(chunk, encoding, callback) {
              try { ws.send(chunk instanceof Buffer ? chunk : Buffer.from(chunk)); }
              catch(e) { callback(e); return; }
              callback();
            },
            final(callback) {
              try { ws.close(); } catch(e) {}
              callback();
            },
            read(size) {},
            destroy(err, callback) {
              try { ws.close(); } catch(e) {}
              callback(err);
            },
          });
          tunnel._ended = false;
          tunnel.setKeepAlive = tunnel.setTimeout = () => {};

          ws.onmessage = (e) => {
            let d;
            if (typeof e.data === 'string') d = Buffer.from(e.data);
            else if (e.data instanceof ArrayBuffer) d = Buffer.from(e.data);
            else if (ArrayBuffer.isView(e.data)) d = Buffer.from(e.data.buffer, e.data.byteOffset, e.data.byteLength);
            else d = Buffer.from(e.data);
            tunnel.push(d);
          };
          ws.onclose = () => {
            tunnel._ended = true;
            tunnel.push(null);
          };
          ws.onerror = () => {
            tunnel.destroy(new Error('WebSocket error'));
          };

          resolve(tunnel);
        }
      } catch(e) {
        if (!json) { /* binary data before connected? buffer it */ }
      }
    };

    ws.onerror = (e) => { clearTimeout(timer); reject(e); };
    ws.onclose = () => { clearTimeout(timer); reject(new Error('ws closed')); };
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
log(`Cloudflare Worker proxy available for Telegram: ${CF_PROXY_URL || 'not configured'}`);
log(`DNS override: ${Object.keys(DNS_OVERRIDE).join(", ")}`);

module.exports = {};
