/**
 * HuggingClaw Proxy — SOCKS5 Routing for Blocked Domains
 *
 * Routes traffic for blocked domains (Telegram, opencode.ai, WhatsApp)
 * through local self-rotating SOCKS5 proxy pool at 127.0.0.1:9050.
 *
 * HF Spaces blocks DNS AND direct IP connections to certain domains.
 * SOCKS5 pool solves both: proxy does DNS, egress is from free proxy IP.
 * Auto-rotates every 10 min for rate-limit bypass.
 */

"use strict";

const https = require("https");
const http = require("http");
const net = require("net");
const tls = require("tls");
const dns = require("dns");
const { URL } = require("url");

const log = (...args) => console.error("[hc-proxy]", ...args);

// ── SOCKS5 Proxy Pool Config ──
const SOCKS5_HOST = "127.0.0.1";
const SOCKS5_PORT = 9050;

const SOCKS5_DOMAINS = [
  "api.telegram.org",
  "opencode.ai",
  "web.whatsapp.com",
  "wss.web.whatsapp.com",
  "whatsapp.net",
];

const isInternal = (h) => {
  const n = String(h || "").trim().toLowerCase();
  return !n || n === "localhost" || n === "127.0.0.1" || n === "::1" || n === "0.0.0.0" ||
    n.endsWith(".hf.space") || n.endsWith(".huggingface.co");
};

const domainMatch = (h, list) => {
  const n = String(h || "").trim().toLowerCase();
  return list.some(d => n === d || n.endsWith(`.${d}`));
};

const needsProxy = (h) => !isInternal(h) && domainMatch(h, SOCKS5_DOMAINS);

// SOCKS5 connect helper
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
// Telegram direct IPs (bypass HF DNS block — IPs might also be firewalled)
const TELEGRAM_IPS = [
  "149.154.167.220", "149.154.167.221", "149.154.167.222",
  "149.154.167.223", "149.154.167.224", "149.154.167.225",
  "149.154.167.226", "149.154.167.227", "149.154.167.228",
  "149.154.167.229", "149.154.167.230", "149.154.167.231",
  "149.154.167.232", "149.154.167.233", "149.154.167.234",
  "149.154.175.50",  "91.108.56.100",   "91.108.56.101",
  "91.108.56.110",   "91.108.56.111",   "91.108.56.120",
  "91.108.56.121",   "91.108.56.130",   "91.108.56.131",
];

const DNS_OVERRIDE = {
  "web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
  "wss.web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
  "api.telegram.org": TELEGRAM_IPS,
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
    opts = { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search };
    if (typeof args[1] === "object" && args[1]) { Object.assign(opts, args[1]); cb = args[2]; }
    else { cb = args[1]; }
  } else { opts = { ...args[0] }; cb = args[1]; }
  
  const hn = opts.hostname || (opts.host ? String(opts.host).split(":")[0] : "");
  if (opts._hc || !needsProxy(hn)) return origHttps.call(this, ...args);
  
  const nopts = { ...opts, _hc: true, createConnection: (o, c) => {
    const h = o.host || o.hostname || "localhost";
    socks5Connect(h, o.port || 443).then(s => c(null, s)).catch(e => c(e));
    return new net.Socket();
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
  if (opts._hc || !needsProxy(hn)) return origHttp.call(this, ...args);
  
  const nopts = { ...opts, _hc: true, createConnection: (o, c) => {
    socks5Connect(o.host || o.hostname || "localhost", o.port || 80).then(s => c(null, s)).catch(e => c(e));
    return new net.Socket();
  }};
  return origHttp.call(this, nopts, cb);
};

// Cloudflare Worker proxy URL for Telegram fallback (set via env)
const CF_PROXY_URL = (typeof process !== 'undefined' && process.env && process.env.CLOUDFLARE_PROXY_URL) || null;

// Telegram direct-IP fallback fetch (bypass DNS without SOCKS)
async function telegramFallbackFetch(url, options) {
  const urlObj = new URL(url);
  if (urlObj.hostname !== 'api.telegram.org') return null;
  
  // Try direct IPs sequentially
  for (const ip of TELEGRAM_IPS.slice(0, 5)) {
    try {
      const directUrl = new URL(url);
      directUrl.hostname = ip;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const resp = await origFetch.call(globalThis, directUrl.toString(), {
        ...options,
        headers: { ...options?.headers, host: 'api.telegram.org', 'x-hc': 'true' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (resp.ok || resp.status === 400) return resp;
    } catch (e) {
      log(`Telegram IP fallback failed for ${ip}: ${e.message}`);
    }
  }
  
  // Try Cloudflare Worker proxy if configured
  if (CF_PROXY_URL) {
    try {
      const proxyUrl = `${CF_PROXY_URL}/telegram${urlObj.pathname}${urlObj.search}`;
      const resp = await origFetch.call(globalThis, proxyUrl, {
        ...options,
        headers: { ...options?.headers, 'x-hc': 'true' },
      });
      if (resp.ok || resp.status === 400) return resp;
    } catch (e) {
      log(`Cloudflare proxy fallback failed: ${e.message}`);
    }
  }
  
  return null;
}

// ── 3. Patch fetch ──
const origFetch = globalThis.fetch;
if (origFetch) {
  globalThis.fetch = async function(input, init) {
    const req = input instanceof Request ? input : new Request(input, init);
    const url = new URL(req.url);
    if (req.headers.get("x-hc") === "true" || !needsProxy(url.hostname)) return origFetch.call(this, input, init);
    
    return new Promise((resolve, reject) => {
      // Try SOCKS5 proxy first
      const chunks = [];
      const headers = {};
      if (req.headers && req.headers.entries) {
        for (const [k, v] of req.headers.entries()) headers[k] = v;
      }
      const doSocks5 = () => {
        const nodeReq = https.request(url, {
          method: req.method,
          headers: { ...headers, "x-hc": "true" },
          createConnection: (o, c) => {
            socks5Connect(o.host || o.hostname || "localhost", o.port || 443, 30000)
              .then(s => c(null, s)).catch(e => c(e));
            return new net.Socket();
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
        nodeReq.on("error", (e) => {
          log(`SOCKS5 fetch failed for ${url.hostname}: ${e.message}`);
          // Try fallback for Telegram
          if (url.hostname === 'api.telegram.org') {
            telegramFallbackFetch(url, { method: req.method, headers }).then(r => {
              if (r) resolve(r);
              else reject(e);
            }).catch(reject);
          } else {
            reject(e);
          }
        });
        nodeReq.on("timeout", () => { nodeReq.destroy(); nodeReq.emit('error', new Error('fetch timeout')); });
        
        if (req.body && typeof req.body.getReader === "function") {
          req.body.getReader().read().then(function pump({ done, value }) {
            if (done) { nodeReq.end(); return; }
            nodeReq.write(value);
            return req.body.getReader().read().then(pump);
          }).catch(reject);
        } else {
          nodeReq.end();
        }
      };
      doSocks5();
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
  if (opts._hc || !needsProxy(hn)) return origNetConnect.call(this, ...args);
  
  // Create a proxy socket
  const socks = new net.Socket();
  socks._hc_proxied = true;
  
  socks5Connect(opts.host || "localhost", opts.port || 80)
    .then(s => {
      socks._hc_socket = s;
      socks.emit("connect");
    })
    .catch(e => socks.destroy(e));
  
  socks.write = function(...wa) {
    if (socks._hc_socket) return socks._hc_socket.write(...wa);
    return false;
  };
  socks.end = function(...wa) {
    if (socks._hc_socket) return socks._hc_socket.end(...wa);
    socks.destroy();
    return socks;
  };
  socks.destroy = function(...wa) {
    if (socks._hc_socket) socks._hc_socket.destroy(...wa);
    return net.Socket.prototype.destroy.call(socks, ...wa);
  };
  
  const origOn = socks.on.bind(socks);
  socks.on = function(evt, cb) {
    if (socks._hc_socket) {
      if (evt === "data") socks._hc_socket.on("data", cb);
      else if (evt === "error") socks._hc_socket.on("error", cb);
      else if (evt === "close") socks._hc_socket.on("close", cb);
      else if (evt === "end") socks._hc_socket.on("end", cb);
      else origOn(evt, cb);
      return socks;
    }
    // Queue until SOCKS5 connects
    const check = setInterval(() => {
      if (socks._hc_socket) {
        clearInterval(check);
        if (evt === "data") socks._hc_socket.on("data", cb);
        else if (evt === "error") socks._hc_socket.on("error", cb);
        else if (evt === "close") socks._hc_socket.on("close", cb);
        else if (evt === "end") socks._hc_socket.on("end", cb);
      }
    }, 10);
    setTimeout(() => clearInterval(check), 15000);
    return origOn(evt, cb);
  };
  
  return socks;
};

// ── 5. Patch tls.connect (for WSS) ──
const origTls = tls.connect;
tls.connect = function(...args) {
  let opts = {};
  if (typeof args[0] === "object" && args[0]) opts = args[0];
  else if (typeof args[0] === "number") opts = { port: args[0], host: args[1] || "localhost" };
  
  const hn = (opts.host || opts.servername || "").trim().toLowerCase();
  if (opts._hc || !needsProxy(hn)) return origTls.call(this, ...args);
  
  const port = opts.port || 443;
  // Return a TLSSocket that connects via SOCKS5
  try {
    const tlsSocket = new tls.TLSSocket(null, { ...opts, _hc: true });
    
    socks5Connect(hn, port, 30000)
      .then(socks => {
        const wrapped = tls.connect({
          socket: socks,
          host: hn,
          servername: opts.servername || hn,
          rejectUnauthorized: opts.rejectUnauthorized !== false,
        });
        // Pipe events
        tlsSocket._hc_tls = wrapped;
        tlsSocket.emit("connect");
      })
      .catch(e => tlsSocket.destroy(e));
    
    tlsSocket.write = function(...wa) {
      if (tlsSocket._hc_tls) return tlsSocket._hc_tls.write(...wa);
      return false;
    };
    tlsSocket.end = function(...wa) {
      if (tlsSocket._hc_tls) return tlsSocket._hc_tls.end(...wa);
      tlsSocket.destroy();
      return tlsSocket;
    };
    tlsSocket.destroy = function(...wa) {
      if (tlsSocket._hc_tls) tlsSocket._hc_tls.destroy(...wa);
      return tls.TLSSocket.prototype.destroy.call(tlsSocket, ...wa);
    };
    
    const origTlsOn = tlsSocket.on.bind(tlsSocket);
    tlsSocket.on = function(evt, cb) {
      if (tlsSocket._hc_tls) {
        if (evt === "data") tlsSocket._hc_tls.on("data", cb);
        else if (evt === "error") tlsSocket._hc_tls.on("error", cb);
        else if (evt === "close") tlsSocket._hc_tls.on("close", cb);
        else if (evt === "end") tlsSocket._hc_tls.on("end", cb);
        else origTlsOn(evt, cb);
        return tlsSocket;
      }
      const check = setInterval(() => {
        if (tlsSocket._hc_tls) {
          clearInterval(check);
          if (evt === "data") tlsSocket._hc_tls.on("data", cb);
          else if (evt === "error") tlsSocket._hc_tls.on("error", cb);
          else if (evt === "close") tlsSocket._hc_tls.on("close", cb);
          else if (evt === "end") tlsSocket._hc_tls.on("end", cb);
        }
      }, 10);
      setTimeout(() => clearInterval(check), 15000);
      return origTlsOn(evt, cb);
    };
    
    return tlsSocket;
  } catch (e) {
    return origTls.call(this, ...args);
  }
};

log(`SOCKS5 routing: ${SOCKS5_DOMAINS.join(", ")} → ${SOCKS5_HOST}:${SOCKS5_PORT}`);
if (Object.keys(DNS_OVERRIDE).length) {
  log(`DNS override: ${Object.keys(DNS_OVERRIDE).join(", ")}`);
}

module.exports = {};
