/**
 * HuggingClaw Proxy — DNS Override + SOCKS5 Routing
 *
 * Two mechanisms to bypass HF Spaces network restrictions:
 *
 * 1. DNS OVERRIDE (for api.telegram.org):
 *    Patches Node.js dns module to resolve blocked domains to hardcoded IPs.
 *    HF Spaces blocks DNS for api.telegram.org but direct IP connections work.
 *    No proxy, no Tor — completely transparent and undetectable.
 *
 * 2. SOCKS5 ROUTING (for opencode.ai, WhatsApp):
 *    Routes traffic through a local self-rotating SOCKS5 proxy pool
 *    to provide IP rotation for rate-limit bypass.
 *
 * The local proxy pool runs on 127.0.0.1:9050 (proxy-pool.py).
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
// PART 1: DNS Override for Telegram
// ═══════════════════════════════════════════════════════════════

// Hardcoded Telegram Bot API IPs (api.telegram.org)
const TELEGRAM_API_IPS = [
  "149.154.167.220",   // Primary Telegram Bot API
  "149.154.166.110",   // Alternative
  "91.108.4.134",      // Alternative
  "149.154.167.221",   // Additional
  "149.154.175.50",    // Additional
];

// Hardcoded WhatsApp IPs (web.whatsapp.com, wss.web.whatsapp.com)
const WHATSAPP_IPS = [
  "157.240.3.52",      // web.whatsapp.com
  "157.240.7.52",      // Alternative
  "157.240.17.52",     // Alternative
];

// Domains we override DNS for
const DNS_OVERRIDE_DOMAINS = {
  "api.telegram.org": TELEGRAM_API_IPS,
  "web.whatsapp.com": WHATSAPP_IPS,
  "wss.web.whatsapp.com": WHATSAPP_IPS,
};

// Patch dns.lookup (used by Node.js for all DNS resolution)
const originalLookup = dns.lookup;
dns.lookup = function patchedLookup(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  
  const domain = (hostname || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE_DOMAINS[domain];
  
  if (ips && ips.length > 0) {
    const ip = ips[0]; // Use first IP
    const family = ip.includes(":") ? 6 : 4;
    if (typeof callback === "function") {
      callback(null, ip, family);
    }
    return { onerror: () => {} };
  }
  
  // Fall through to original
  if (typeof options === "function") {
    return originalLookup(hostname, options);
  }
  return originalLookup(hostname, options, callback);
};

// Patch dns.resolve4 (used by some libraries)
const originalResolve4 = dns.resolve4;
dns.resolve4 = function patchedResolve4(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  
  const domain = (hostname || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE_DOMAINS[domain];
  if (ips && ips.length > 0) {
    if (typeof callback === "function") callback(null, ips);
    return;
  }
  
  if (typeof options === "function") {
    return originalResolve4(hostname, options);
  }
  return originalResolve4(hostname, options, callback);
};

// Patch dns.resolve (covers resolve6, resolveAny etc.)
const originalResolve = dns.resolve;
dns.resolve = function patchedResolve(hostname, rrtype, callback) {
  if (typeof rrtype === "function") { callback = rrtype; rrtype = "A"; }
  
  const domain = (hostname || "").toString().toLowerCase();
  const ips = DNS_OVERRIDE_DOMAINS[domain];
  if (ips && ips.length > 0 && (rrtype === "A" || rrtype === "ANY")) {
    if (typeof callback === "function") callback(null, ips);
    return;
  }
  
  if (typeof rrtype === "function") {
    return originalResolve(hostname, rrtype);
  }
  return originalResolve(hostname, rrtype, callback);
};

log("DNS override active for:", Object.keys(DNS_OVERRIDE_DOMAINS).join(", "));

// ═══════════════════════════════════════════════════════════════
// PART 2: SOCKS5 Routing for opencode.ai + WhatsApp WebSocket
// ═══════════════════════════════════════════════════════════════

const SOCKS5_HOST = "127.0.0.1";
const SOCKS5_PORT = 9050;

// Domains routed through local SOCKS5 proxy pool
const SOCKS5_DOMAINS = [
  "opencode.ai",
  "web.whatsapp.com",
  "wss.web.whatsapp.com",
  "whatsapp.net",
];

const DEBUG = false;

// Helpers
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

// SOCKS5 Tunnel (pure Node.js)
function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: SOCKS5_HOST, port: SOCKS5_PORT }, () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00])); // SOCKS5: no auth
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
        let respLen = 4;
        const atyp = buf[3];
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
    .then((socket) => {
      if (typeof callback === "function") callback(null, socket);
    })
    .catch((err) => {
      if (typeof callback === "function") callback(err);
    });
  return new net.Socket();
}

// ── 1. Patch net.connect / net.createConnection (raw TCP/WebSocket) ──
const originalNetConnect = net.connect;
net.connect = function patchedNetConnect(...args) {
  let options = {};
  if (typeof args[0] === "object" && args[0] !== null) {
    options = args[0];
  } else if (typeof args[0] === "number") {
    options = { port: args[0], host: args[1] || "localhost" };
  } else if (typeof args[0] === "string") {
    options = { path: args[0] };
  }
  if (!options.host && !options.path) options = { host: args[0], port: args[1] };

  const hostname = (options.host || "").trim().toLowerCase();
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalNetConnect.call(this, ...args);
  }
  if (DEBUG) log(`net.connect: Routing ${hostname} via SOCKS5`);
  const socksOpts = { ...options, _hc_proxied: true };
  const socket = new net.Socket();
  socks5Connect(options.host || "localhost", options.port || 80)
    .then((socksSocket) => {
      socket.emit("connect"); // Signal the socket is ready
      // Replace socket methods to proxy through socksSocket
      const origOn = socket.on.bind(socket);
      socket.on = function(evt, cb) {
        if (evt === "data") socksSocket.on("data", cb);
        if (evt === "error") socksSocket.on("error", cb);
        if (evt === "close") socksSocket.on("close", cb);
        if (evt === "end") socksSocket.on("end", cb);
        return origOn(evt, cb);
      };
      socket.write = socksSocket.write.bind(socksSocket);
      socket.end = socksSocket.end.bind(socksSocket);
      socket.destroy = socksSocket.destroy.bind(socksSocket);
    })
    .catch((err) => {
      if (DEBUG) log(`SOCKS5 net.connect error: ${err.message}`);
      // Fallback to direct (in case proxy pool is down)
      return originalNetConnect.call(this, ...args);
    });
  return socket;
};

// ── 2. Patch tls.connect (for WSS WebSocket connections) ──
const originalTlsConnect = tls.connect;
tls.connect = function patchedTlsConnect(...args) {
  let options = {};
  if (typeof args[0] === "object" && args[0] !== null) {
    options = args[0];
  } else if (typeof args[0] === "number") {
    options = { port: args[0], host: args[1] || "localhost" };
  }

  const hostname = (options.host || options.servername || "").trim().toLowerCase();
  if (options._hc_proxied || !shouldProxyViaSOCKS5(hostname)) {
    return originalTlsConnect.call(this, ...args);
  }
  if (DEBUG) log(`tls.connect: Routing ${hostname} via SOCKS5`);

  const port = options.port || 443;
  const socket = new tls.TLSSocket(new net.Socket(), {
    ...options,
    _hc_proxied: true,
  });
  
  socks5Connect(hostname, port)
    .then((socksSocket) => {
      // Create TLS over the SOCKS5 connection
      const tlsSocket = tls.connect({
        socket: socksSocket,
        host: hostname,
        servername: options.servername || hostname,
        rejectUnauthorized: options.rejectUnauthorized !== false,
      });
      // Pipe TLSSocket events to our socket
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

// ── 3. Patch https.request (for outbound API calls) ──
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
  if (DEBUG) log(`https.request: Routing ${hostname} via SOCKS5`);
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
  if (DEBUG) log(`http.request: Routing ${hostname} via SOCKS5`);
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
    if (DEBUG) log(`fetch: Routing ${hostname} via SOCKS5`);
    const u = new URL(req.url);
    
    return new Promise((resolve, reject) => {
      const chunks = [];
      const nodeReq = https.request(u, {
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
            headers: Object.fromEntries(
              (nodeRes.headers || []).entries ? Object.entries(nodeRes.headers) : []
            ),
          }));
        });
      });
      nodeReq.on("error", reject);
      nodeReq.on("timeout", () => { nodeReq.destroy(); reject(new Error("SOCKS5 fetch timeout")); });
      
      if (req.body) {
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

// Startup banner
try {
  const fs = require("fs");
  fs.writeFileSync("/tmp/.hc-proxy-banner-shown", "1", { flag: "wx" });
  log(`DNS override: ${Object.keys(DNS_OVERRIDE_DOMAINS).join(", ")}`);
  log(`SOCKS5 routing: ${SOCKS5_DOMAINS.join(", ")} → 127.0.0.1:${SOCKS5_PORT}`);
} catch (_) {}

module.exports = {};
