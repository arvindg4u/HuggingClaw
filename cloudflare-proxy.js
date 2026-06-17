/**
 * Cloudflare + SOCKS5 Proxy: Transparent Fix for Blocked Domains
 *
 * Patches https.request/http.request/fetch and undici to redirect traffic
 * for blocked hosts through a Cloudflare Worker OR Tor SOCKS5 proxy.
 *
 * SOCKS5 mode is activated by setting SOCKS5_PROXY_URL (e.g. socks5h://127.0.0.1:9050)
 * and SOCKS5_PROXY_DOMAINS (comma-separated domains to route through Tor).
 */
"use strict";

const https = require("https");
const http = require("http");
const net = require("net");
const tls = require("tls");

const log = (...args) => console.error(...args);

// ── Cloudflare Worker Proxy Config ──
let PROXY_URL = process.env.CLOUDFLARE_PROXY_URL;
if (PROXY_URL && !PROXY_URL.startsWith("http://") && !PROXY_URL.startsWith("https://")) {
  PROXY_URL = `https://${PROXY_URL}`;
}

// ── SOCKS5 / Tor Proxy Config ──
const SOCKS5_PROXY = (process.env.SOCKS5_PROXY_URL || "").trim();
let SOCKS5_HOST = "";
let SOCKS5_PORT = 9050;
if (SOCKS5_PROXY) {
  try {
    const u = new URL(SOCKS5_PROXY);
    SOCKS5_HOST = u.hostname;
    SOCKS5_PORT = parseInt(u.port) || 9050;
  } catch (e) {
    log(`[proxy] Invalid SOCKS5_PROXY_URL: ${SOCKS5_PROXY}`);
  }
}
const SOCKS5_DOMAINS_RAW = (process.env.SOCKS5_PROXY_DOMAINS || "").trim();
const SOCKS5_DOMAIN_LIST = SOCKS5_DOMAINS_RAW ? SOCKS5_DOMAINS_RAW.split(",").map(d => d.trim().toLowerCase()).filter(Boolean) : [];

const DEBUG = true;
const PROXY_SHARED_SECRET = (process.env.CLOUDFLARE_PROXY_SECRET || "").trim();

// ── Blocked Domains for Cloudflare Worker ──
const DEFAULT_PROXY_DOMAINS = [
  "api.telegram.org", "discord.com", "discordapp.com",
  "gateway.discord.gg", "status.discord.com", "web.whatsapp.com",
  "graph.facebook.com", "graph.instagram.com",
  "api.twitter.com", "api.x.com", "upload.twitter.com",
  "api.linkedin.com", "www.linkedin.com",
  "open.tiktokapis.com", "oauth.reddit.com",
  "youtube.com", "www.youtube.com",
  "api.resend.com", "api.sendgrid.com", "api.mailgun.net",
  "googleapis.com", "google.com", "googleusercontent.com", "gstatic.com",
];

const PROXY_DOMAINS_RAW = (process.env.CLOUDFLARE_PROXY_DOMAINS || "").trim();
const PROXY_ALL = PROXY_DOMAINS_RAW === "*";

let BLOCKED_DOMAINS;
if (PROXY_ALL) {
  BLOCKED_DOMAINS = [];
} else {
  const extra = PROXY_DOMAINS_RAW.split(",").map(d => d.trim()).filter(Boolean);
  BLOCKED_DOMAINS = [...DEFAULT_PROXY_DOMAINS];
  for (const d of extra) {
    if (!BLOCKED_DOMAINS.includes(d)) BLOCKED_DOMAINS.push(d);
  }
}

// ── Helpers ──
const isInternalHost = (hostname) => {
  const n = String(hostname || "").trim().toLowerCase();
  if (!n) return true;
  return n === "localhost" || n === "127.0.0.1" || n === "::1" || n === "0.0.0.0" ||
    n.endsWith(".hf.space") || n.endsWith(".huggingface.co") || n === "huggingface.co" ||
    (PROXY_URL && (n === new URL(PROXY_URL).hostname));
};

const matchesDomain = (hostname, domainList) => {
  const n = String(hostname || "").trim().toLowerCase();
  return domainList.some(d => n === d || n.endsWith(`.${d}`));
};

const shouldProxyViaCF = (hostname) => PROXY_URL && !isInternalHost(hostname) && matchesDomain(hostname, BLOCKED_DOMAINS);
const shouldProxyViaSOCKS5 = (hostname) => SOCKS5_HOST && !isInternalHost(hostname) && matchesDomain(hostname, SOCKS5_DOMAIN_LIST);

// ── SOCKS5 Tunnel (pure Node.js, no deps) ──
function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: SOCKS5_HOST, port: SOCKS5_PORT }, () => {
      // SOCKS5 handshake: no auth
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0; // 0 = auth, 1 = connect
    let buf = Buffer.alloc(0);
    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      if (state === 0 && buf.length >= 2) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) {
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
          return reject(new Error(`SOCKS5 connect failed: ${rep}`));
        }
        // Determine response length (variable for domain names)
        let respLen = 4;
        const atyp = buf[3];
        if (atyp === 0x01) respLen = 10;       // IPv4
        else if (atyp === 0x03) respLen = 7 + buf[4]; // Domain
        else if (atyp === 0x04) respLen = 22;  // IPv6
        if (buf.length >= respLen) {
          socket.removeListener("data", onData);
          resolve(socket);
        }
      }
    };
    socket.on("data", onData);
    socket.on("error", reject);
    socket.setTimeout(30000, () => { socket.destroy(); reject(new Error("SOCKS5 timeout")); });
  });
}

// ── Create raw TCP socket via SOCKS5 (https.request handles TLS upgrade) ──
function createSocks5ServerSocket(options, callback) {
  socks5Connect(options.hostname || options.host || "localhost", options.port || 443)
    .then((rawSocket) => callback(null, rawSocket))
    .catch(callback);
}

// ── Patch https.request ──
if (PROXY_URL || SOCKS5_HOST) {
  const originalHttpsRequest = https.request;
  const originalHttpRequest = http.request;
  const originalFetch = typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : null;

  https.request = function patchedHttpsRequest(arg1, arg2, arg3) {
    let options = {}, callback;
    if (typeof arg1 === "string" || arg1 instanceof URL) {
      const url = typeof arg1 === "string" ? new URL(arg1) : arg1;
      options = { protocol: url.protocol, hostname: url.hostname, port: url.port, path: url.pathname + url.search };
      if (typeof arg2 === "object" && arg2 !== null) { Object.assign(options, arg2); callback = arg3; }
      else { callback = arg2; }
    } else { options = { ...arg1 }; callback = arg2; }

    const hostname = options.hostname || (options.host ? String(options.host).split(":")[0] : "");
    const path = options.path || "/";
    const headers = options.headers || {};
    const alreadyProxied = options._proxied;
    const hasTargetHeader = headers["x-target-host"] || headers["X-Target-Host"];

    // Try SOCKS5 first
    if (shouldProxyViaSOCKS5(hostname) && !alreadyProxied) {
      if (DEBUG) log(`[proxy] Routing ${hostname}${path} via SOCKS5 (${SOCKS5_HOST}:${SOCKS5_PORT})`);
      // Use createConnection to route through SOCKS5 tunnel
      const newOpts = { ...options, _proxied: true, createConnection: createSocks5ServerSocket };
      return originalHttpsRequest.call(this, newOpts, callback);
    }

    // Then try Cloudflare Worker
    if (shouldProxyViaCF(hostname) && !alreadyProxied && !hasTargetHeader) {
      if (DEBUG) log(`[proxy] Redirecting ${hostname}${path} -> ${new URL(PROXY_URL).hostname}`);
      const newOpts = { ...options, _proxied: true, protocol: "https:", hostname: new URL(PROXY_URL).hostname, port: new URL(PROXY_URL).port || 443, servername: new URL(PROXY_URL).hostname };
      delete newOpts.host;
      if (!newOpts.headers) newOpts.headers = {};
      newOpts.headers["x-target-host"] = hostname;
      if (PROXY_SHARED_SECRET) newOpts.headers["x-proxy-key"] = PROXY_SHARED_SECRET;
      return originalHttpsRequest.call(this, newOpts, callback);
    }

    return originalHttpsRequest.call(this, options, callback);
  };

  // ── Patch http.request ──
  http.request = function patchedHttpRequest(arg1, arg2, arg3) {
    let options = {}, callback;
    if (typeof arg1 === "string" || arg1 instanceof URL) {
      const url = typeof arg1 === "string" ? new URL(arg1) : arg1;
      options = { protocol: url.protocol, hostname: url.hostname, port: url.port, path: url.pathname + url.search };
      if (typeof arg2 === "object" && arg2 !== null) { Object.assign(options, arg2); callback = arg3; }
      else { callback = arg2; }
    } else { options = { ...arg1 }; callback = arg2; }

    const hostname = options.hostname || (options.host ? String(options.host).split(":")[0] : "");
    const alreadyProxied = options._proxied;

    if (shouldProxyViaSOCKS5(hostname) && !alreadyProxied) {
      if (DEBUG) log(`[proxy] Routing ${hostname} via SOCKS5 (HTTP)`);
      const newOpts = { ...options, _proxied: true, createConnection: socks5Connect };
      return originalHttpRequest.call(this, newOpts, callback);
    }

    if (shouldProxyViaCF(hostname) && !alreadyProxied) {
      if (DEBUG) log(`[proxy] Redirecting ${hostname} -> Cloudflare Worker`);
      const newOpts = { ...options, _proxied: true, protocol: "https:", hostname: new URL(PROXY_URL).hostname, port: new URL(PROXY_URL).port || 443, servername: new URL(PROXY_URL).hostname };
      delete newOpts.host;
      if (!newOpts.headers) newOpts.headers = {};
      newOpts.headers["x-target-host"] = hostname;
      if (PROXY_SHARED_SECRET) newOpts.headers["x-proxy-key"] = PROXY_SHARED_SECRET;
      return originalHttpRequest.call(this, newOpts, callback);
    }

    return originalHttpRequest.call(this, options, callback);
  };

  // ── Patch globalThis.fetch ──
  if (originalFetch) {
    globalThis.fetch = async function patchedFetch(input, init) {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const hostname = url.hostname;
      const alreadyProxied = req.headers.get("x-proxied") === "true";
      const hasTargetHeader = req.headers.has("x-target-host");

      if (shouldProxyViaSOCKS5(hostname) && !alreadyProxied) {
        if (DEBUG) log(`[proxy] fetch: Routing ${hostname} via SOCKS5`);
        return new Promise((resolve, reject) => {
          socks5Connect(hostname, 443)
            .then((rawSocket) => {
              const tlsSocket = tls.connect({ socket: rawSocket, host: hostname, servername: hostname }, () => {
                // Send the HTTP request over TLS
                const method = req.method;
                const path = url.pathname + url.search;
                const headers = [];
                req.headers.forEach((v, k) => headers.push(`${k}: ${v}`));
                const body = req.body ? req.body : "";
                const reqStr = `${method} ${path} HTTP/1.1\r\nhost: ${hostname}\r\n${headers.join("\r\n")}\r\nx-proxied: true\r\nconnection: close\r\n\r\n`;
                tlsSocket.write(reqStr);
                let respData = Buffer.alloc(0);
                tlsSocket.on("data", (d) => { respData = Buffer.concat([respData, d]); });
                tlsSocket.on("end", () => {
                  const respStr = respData.toString();
                  const [statusLine, ...headerLines] = respStr.split("\r\n");
                  const statusMatch = statusLine.match(/HTTP\/\d+\.\d+ (\d+)/);
                  const status = statusMatch ? parseInt(statusMatch[1]) : 502;
                  const bodyStart = respStr.indexOf("\r\n\r\n") + 4;
                  const bodyText = respStr.slice(bodyStart);
                  resolve(new Response(bodyText, { status, headers: { "content-type": "application/json" } }));
                });
                tlsSocket.on("error", reject);
              });
              tlsSocket.on("error", reject);
            })
            .catch(reject);
        });
      }

      if (shouldProxyViaCF(hostname) && !alreadyProxied && !hasTargetHeader) {
        if (DEBUG) log(`[proxy] fetch: Redirecting ${hostname} -> Cloudflare Worker`);
        const proxyUrl = new URL(PROXY_URL);
        const newUrl = `https://${proxyUrl.hostname}${url.pathname}${url.search}`;
        const newHeaders = new Headers(req.headers);
        newHeaders.set("x-target-host", hostname);
        if (PROXY_SHARED_SECRET) newHeaders.set("x-proxy-key", PROXY_SHARED_SECRET);
        newHeaders.set("x-proxied", "true");
        return originalFetch(newUrl, { ...init, headers: newHeaders });
      }

      return originalFetch(input, init);
    };
  }

  // ── Patch undici dispatch ──
  try {
    const patchDispatch = (proto, name) => {
      if (!proto || !proto.dispatch || proto.dispatch._patched) return;
      const origDispatch = proto.dispatch;
      proto.dispatch = function patchedDispatch(options, handler) {
        let origin = options.origin || "";
        if (typeof origin !== "string") { try { origin = origin.origin || origin.toString(); } catch (e) { origin = ""; } }
        let hostname = "";
        try { hostname = new URL(String(origin)).hostname; } catch (e) { hostname = String(origin || "").split(":")[0]; }

        // SOCKS5
        if (hostname && shouldProxyViaSOCKS5(hostname)) {
          if (DEBUG) log(`[proxy] undici ${name}: Routing ${hostname} via SOCKS5`);
          // Fall back to fetch which handles SOCKS5
          return origDispatch.call(this, options, handler);
        }

        // Cloudflare Worker
        if (hostname && shouldProxyViaCF(hostname)) {
          if (DEBUG) log(`[proxy] undici ${name}: ${hostname} -> ${new URL(PROXY_URL).hostname}`);
          const targetHeader = "x-target-host";
          if (Array.isArray(options.headers)) {
            let found = false;
            for (let i = 0; i < options.headers.length; i += 2) {
              if (String(options.headers[i]).toLowerCase() === targetHeader) { found = true; break; }
            }
            if (!found) { options.headers.push(targetHeader, hostname); }
          } else {
            options.headers = options.headers || {};
            options.headers[targetHeader] = hostname;
          }
          options.origin = PROXY_URL;
        }
        return origDispatch.call(this, options, handler);
      };
      proto.dispatch._patched = true;
    };

    const patchUndici = (exports) => {
      for (const key in exports) {
        if (exports[key] && exports[key].prototype && typeof exports[key].prototype.dispatch === "function") {
          patchDispatch(exports[key].prototype, key);
        }
      }
      if (exports.getGlobalDispatcher) {
        try { const gd = exports.getGlobalDispatcher(); if (gd && gd.dispatch && !gd.dispatch._patched) patchDispatch(gd, "Global"); } catch (e) {}
      }
      if (exports.Agent && exports.Agent.prototype) patchDispatch(exports.Agent.prototype, "Agent");
      if (exports.Pool && exports.Pool.prototype) patchDispatch(exports.Pool.prototype, "Pool");
      if (exports.Client && exports.Client.prototype) patchDispatch(exports.Client.prototype, "Client");
    };

    try { const undici = require("undici"); patchUndici(undici); } catch (e) {}
    const Module = require("module");
    const originalRequire = Module.prototype.require;
    Module.prototype.require = function (id) {
      const exports = originalRequire.apply(this, arguments);
      if (id === "undici" || /node_modules\/undici(?:\/|$)/.test(id)) { try { patchUndici(exports); } catch (e) {} }
      return exports;
    };
  } catch (e) {
    if (DEBUG) log(`[proxy] undici patch skipped: ${e.message}`);
  }

  // Startup banner
  try {
    require("fs").writeFileSync("/tmp/.cf-proxy-banner-shown", "1", { flag: "wx" });
    if (SOCKS5_HOST) log(`[proxy] SOCKS5 active (${SOCKS5_HOST}:${SOCKS5_PORT}) for: ${SOCKS5_DOMAINS_RAW || "(none)"}`);
    if (PROXY_URL) log(`[proxy] Cloudflare active -> ${new URL(PROXY_URL).hostname}${PROXY_ALL ? " (wildcard)" : ""}`);
  } catch (_) {}
}
