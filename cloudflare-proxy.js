/**
 * HuggingClaw Proxy — SOCKS5 Routing for Blocked Domains
 *
 * Routes traffic for blocked domains (Telegram, opencode.ai, WhatsApp)
 * through a local self-rotating SOCKS5 proxy pool at 127.0.0.1:9050.
 *
 * HF Spaces blocks DNS AND direct IP connections to certain high-abuse
 * domains (api.telegram.org). The SOCKS5 proxy pool solves both:
 *   1. DNS resolution happens inside the SOCKS5 tunnel (proxy does DNS)
 *   2. Egress IP is from the free proxy, not the HF Space IP
 *   3. Auto-rotates every 10 min for rate-limit bypass
 *
 * Additionally patches Node.js DNS to return hardcoded IPs as fallback
 * for domains where direct connection works (WhatsApp WebSocket).
 */

"use strict";

const https = require("https");
const http = require("http");
const net = require("net");
const tls = require("tls");
const dns = require("dns");
const { URL } = require("url");

const log = (...args) => console.error("[hc-proxy]", ...args);

// ═══════════════════════════════════════════════════════════════
// DNS Override (for domains where direct IP works)
// ═══════════════════════════════════════════════════════════════
// api.telegram.org is NOT here — HF blocks its IPs directly.
// Only use DNS override for domains where IPs are not firewalled.

const DNS_OVERRIDE_DOMAINS = {
  // WhatsApp WebSocket hosts — HF may only block DNS, not IPs
  "web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
  "wss.web.whatsapp.com": ["157.240.3.52", "157.240.7.52"],
};

// Patch dns.lookup
const originalLookup = dns.lookup;
dns.lookup = function patchedLookup(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  const domain = (hostname || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE_DOMAINS[domain];
  if (ips && ips.length > 0) {
    const ip = ips[0];
    const family = ip.includes(":") ? 6 : 4;
    if (typeof callback === "function") callback(null, ip, family);
    return { onerror: () => {} };
  }
  if (typeof options === "function") return originalLookup(hostname, options);
  return originalLookup(hostname, options, callback);
};

// Patch dns.resolve4
const originalResolve4 = dns.resolve4;
dns.resolve4 = function patchedResolve4(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  const domain = (hostname || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE_DOMAINS[domain];
  if (ips && ips.length > 0) {
    if (typeof callback === "function") callback(null, ips);
    return;
  }
  if (typeof options === "function") return originalResolve4(hostname, options);
  return originalResolve4(hostname, options, callback);
};

if (Object.keys(DNS_OVERRIDE_DOMAINS).length > 0) {
  log("DNS override for:", Object.keys(DNS_OVERRIDE_DOMAINS).join(", "));
}

// ═══════════════════════════════════════════════════════════════
// SOCKS5 Routing (for ALL blocked domains via local proxy pool)
// ═══════════════════════════════════════════════════════════════

const SOCKS5_HOST = "127.0.0.1";
const SOCKS5_PORT = 9050;

const SOCKS5_DOMAINS = [
  "api.telegram.org",      // HF blocks DNS + IPs — route through proxy
  "opencode.ai",           // IP rotation for rate limits
  "web.whatsapp.com",      // WhatsApp WebSocket
  "wss.web.whatsapp.com",  // WhatsApp Secure WebSocket
  "whatsapp.net",          // WhatsApp media/CDN
];

const DEBUG = false;

const isInternalHost = (hostname) => {
  const n = String(hostname || "").trim().toLowerCase();
  if (!n) return true;
  return n === "localhost" || n === "127.0.0.1" || n === "::1" || n === "0.0.0.0" ||
    n.endsWith(".hf.space") || n.endsWith(".huggingface.co") || n === "huggingface.co";
};

const matchesDomain = (hostname, domainList) => {
  const n = String(hostname || "").trim().toLowerCase();
  return domainList.some(d => n === d || n.endsWith(`.${d}`));
};

const shouldProxyViaSOCKS5 = (hostname) =>
  !isInternalHost(hostname) && matchesDomain(hostname, SOCKS5_DOMAINS);

// SOCKS5 Tunnel
function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: SOCKS5_HOST, port: SOCKS5_PORT }, () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0;
    let buf = Buffer.alloc(0);

    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      if (state === 0 && buf.length >= 2) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) {
          socket.destroy();
          return reject(new Error(`SOCKS5 auth failed: ${buf[1]}`));
        }
        state = 1;
        const hbuf = Buffer.from(targetHost);
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hbuf.length]),
          hbuf,
          Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])
        ]);
        socket.write(req);
        buf = Buffer.alloc(0);
      } else if (state === 1 && buf.length >= 4) {
        const rep = buf[1];
        if (rep !== 0x00) {
          socket.destroy();
          return reject(new Error(`SOCKS5 connect failed: ${rep}`));
        }
        const atyp = buf[3];
        let respLen = 4;
        if (atyp === 0x01) respLen = 10;
        else if (atyp === 0x03) respLen = 4 + 1 + buf[4] + 2;
        else if (atyp === 0x04) respLen = 4 + 16 + 2;
        if (buf.length >= respLen) {
          socket.removeListener("data", onData);
          resolve(socket);
        }
      }
    };
    socket.on("data", onData);
    socket.on("error", reject);
    socket.setTimeout(30000, () => {
      socket.destroy();
      reject(new Error("SOCKS5 tunnel timeout"));
    });
  });
}

function createSocks5ServerSocket(options, callback) {
  const hostname = options.host || options.hostname || "localhost";
  const port = options.port || 80;
  socks5Connect(hostname, port)
    .then((socket) => { if (typeof callback === "function") callback(null, socket); })
    .catch((err) => { if (typeof callback === "function") callback(err); });
  return new net.Socket();
}

// ── 1. Patch net.connect / net.createConnection ──
const originalNetConnect = net.connect;
net.connect = function patchedNetConnect(...args) {
  let options = {};
  if (typeof args[0] === "object" && args[0] !== null) options = args[0];
  else if (typeof args[0] === "number") options = { port: args[0], host: args[1] || "localhost" };
  else if (typeof args[0] === "string") options = { path: args[0] };
  if (!options.host && !options.path) options = { host: args[0], port: args[1] };

  const hostname = (options.host || "").trim().toLowerCase();
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalNetConnect.call(this, ...args);
  }
  if (DEBUG) log(`net.connect: ${hostname} via SOCKS5`);

  // Return a proxy socket
  const socket = new net.Socket();
  const origOn = socket.on.bind(socket);
  let proxiedSocket = null;

  socks5Connect(options.host || "localhost", options.port || 80)
    .then((socks) => {
      proxiedSocket = socks;
      socket.emit("connect");
    })
    .catch((err) => {
      if (DEBUG) log(`SOCKS5 net.connect error: ${err.message}`);
      socket.destroy(err);
    });

  socket.on = function(evt, cb) {
    if (proxiedSocket) {
      if (evt === "data") proxiedSocket.on("data", cb);
      else if (evt === "error") proxiedSocket.on("error", cb);
      else if (evt === "close") proxiedSocket.on("close", cb);
      else if (evt === "end") proxiedSocket.on("end", cb);
      return origOn(evt, cb);
    }
    // Queue until SOCKS5 connects
    const self = this;
    const checkConn = setInterval(() => {
      if (proxiedSocket) {
        clearInterval(checkConn);
        if (evt === "data") proxiedSocket.on("data", cb);
        else if (evt === "error") proxiedSocket.on("error", cb);
        else if (evt === "close") proxiedSocket.on("close", cb);
        else if (evt === "end") proxiedSocket.on("end", cb);
      }
    }, 50);
    setTimeout(() => clearInterval(checkConn), 15000);
    return origOn(evt, cb);
  };
  socket.write = function(...wargs) {
    if (proxiedSocket) return proxiedSocket.write(...wargs);
    return false;
  };
  socket.end = function(...wargs) {
    if (proxiedSocket) return proxiedSocket.end(...wargs);
    return origOn("end", () => {});
  };
  socket.destroy = function(...wargs) {
    if (proxiedSocket) return proxiedSocket.destroy(...wargs);
    return origOn("close", () => {});
  };
  return socket;
};

// ── 2. Patch tls.connect ──
const originalTlsConnect = tls.connect;
tls.connect = function patchedTlsConnect(...args) {
  let options = {};
  if (typeof args[0] === "object" && args[0] !== null) options = args[0];
  else if (typeof args[0] === "number") options = { port: args[0], host: args[1] || "localhost" };

  const hostname = (options.host || options.servername || "").trim().toLowerCase();
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalTlsConnect.call(this, ...args);
  }
  if (DEBUG) log(`tls.connect: ${hostname} via SOCKS5`);

  const port = options.port || 443;
  const socket = new tls.TLSSocket(new net.Socket(), { ...options, _hc_proxied: true });

  socks5Connect(hostname, port)
    .then((socksSocket) => {
      const tlsSocket = tls.connect({
        socket: socksSocket,
        host: hostname,
        servername: options.servername || hostname,
        rejectUnauthorized: options.rejectUnauthorized !== false,
      });
      tlsSocket.on("data", (d) => socket.emit("data", d));
      tlsSocket.on("error", (e) => socket.emit("error", e));
      tlsSocket.on("close", () => socket.emit("close"));
      tlsSocket.on("end", () => socket.emit("end"));
      socket.write = tlsSocket.write.bind(tlsSocket);
      socket.end = tlsSocket.end.bind(tlsSocket);
      socket.destroy = tlsSocket.destroy.bind(tlsSocket);
      socket.emit("connect");
    })
    .catch((err) => {
      if (DEBUG) log(`SOCKS5 tls.connect error: ${err.message}`);
      return originalTlsConnect.call(this, ...args);
    });
  return socket;
};

// ── 3. Patch https.request ──
const originalHttpsRequest = https.request;
https.request = function patchedHttpsRequest(arg1, arg2, arg3) {
  let options = {}, callback;
  if (typeof arg1 === "string" || arg1 instanceof URL) {
    const url = typeof arg1 === "string" ? new URL(arg1) : arg1;
    options = { protocol: url.protocol, hostname: url.hostname, port: url.port, path: url.pathname + url.search };
    if (typeof arg2 === "object" && arg2 !== null) { Object.assign(options, arg2); callback = arg3; }
    else { callback = arg2; }
  } else { options = { ...arg1 }; callback = arg2; }

  const hostname = options.hostname || (options.host ? String(options.host).split(":")[0] : "");
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalHttpsRequest.call(this, arg1, arg2, arg3);
  }
  if (DEBUG) log(`https.request: ${hostname} via SOCKS5`);
  const newOpts = { ...options, _hc_proxied: true, createConnection: createSocks5ServerSocket };
  return originalHttpsRequest.call(this, newOpts, callback);
};

// ── 4. Patch http.request ──
const originalHttpRequest = http.request;
http.request = function patchedHttpRequest(arg1, arg2, arg3) {
  let options = {}, callback;
  if (typeof arg1 === "string" || arg1 instanceof URL) {
    const url = typeof arg1 === "string" ? new URL(arg1) : arg1;
    options = { protocol: url.protocol, hostname: url.hostname, port: url.port, path: url.pathname + url.search };
    if (typeof arg2 === "object" && arg2 !== null) { Object.assign(options, arg2); callback = arg3; }
    else { callback = arg2; }
  } else { options = { ...arg1 }; callback = arg2; }

  const hostname = options.hostname || (options.host ? String(options.host).split(":")[0] : "");
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalHttpRequest.call(this, arg1, arg2, arg3);
  }
  if (DEBUG) log(`http.request: ${hostname} via SOCKS5`);
  const newOpts = { ...options, _hc_proxied: true, createConnection: createSocks5ServerSocket };
  return originalHttpRequest.call(this, newOpts, callback);
};

// ── 5. Patch globalThis.fetch ──
const originalFetch = globalThis.fetch;
if (originalFetch) {
  globalThis.fetch = async function patchedFetch(input, init) {
    const req = input instanceof Request ? input : new Request(input, init);
    const url = new URL(req.url);
    const hostname = url.hostname;
    if (req.headers.get("x-hc-proxied") === "true" || !shouldProxyViaSOCKS5(hostname)) {
      return originalFetch.call(this, input, init);
    }
    if (DEBUG) log(`fetch: ${hostname} via SOCKS5`);

    return new Promise((resolve, reject) => {
      const chunks = [];
      const nodeReq = https.request(url, {
        method: req.method,
        headers: Object.fromEntries((req.headers || new Map()).entries ? req.headers.entries() : []),
        createConnection: createSocks5ServerSocket,
        timeout: 60000,
      }, (nodeRes) => {
        nodeRes.on("data", (c) => chunks.push(c));
        nodeRes.on("end", () => {
          resolve(new Response(Buffer.concat(chunks), {
            status: nodeRes.statusCode,
            statusText: nodeRes.statusMessage,
            headers: Object.fromEntries(Object.entries(nodeRes.headers || {})),
          }));
        });
      });
      nodeReq.on("error", reject);
      nodeReq.on("timeout", () => { nodeReq.destroy(); reject(new Error("SOCKS5 fetch timeout")); });

      if (req.body && req.body.getReader) {
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

log(`SOCKS5: ${SOCKS5_DOMAINS.join(", ")} → 127.0.0.1:${SOCKS5_PORT}`);

module.exports = {};
