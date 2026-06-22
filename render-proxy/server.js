/**
 * HuggingClaw Render Proxy — Telegram + WhatsApp relay
 *
 * Deploy on Render free tier.  HF Spaces routes Telegram API and WhatsApp
 * traffic through this proxy to bypass outbound connection blocks.
 *
 * Endpoints:
 *   /telegram/*         →  proxies to https://api.telegram.org/*
 *   /whatsapp/*         →  proxies WhatsApp Web HTTP endpoints
 *   /whatsapp-ws/       →  WebSocket proxy for WhatsApp Web
 *   /health             →  health check (for cron ping)
 *   /                   →  status page
 */
"use strict";

const http = require("http");
const https = require("https");
const url = require("url");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const TELEGRAM_API = "api.telegram.org";
const WHATSAPP_DOMAINS = {
  "web.whatsapp.com": "web.whatsapp.com",
  "wss.web.whatsapp.com": "wss.web.whatsapp.com",
  "g.whatsapp.net": "g.whatsapp.net",
  "mmg.whatsapp.net": "mmg.whatsapp.net",
};

// ── Request logging ──────────────────────────────────────────────────────
function log(prefix, msg) {
  const ts = new Date().toISOString().replace("T", " ").substring(0, 19);
  console.log(`[${ts}] [${prefix}] ${msg}`);
}

// ── HTTP proxy for Telegram API ──────────────────────────────────────────
// HF Spaces sends: GET/POST https://render-proxy-url/telegram/botXXX/method
// We proxy to:     GET/POST https://api.telegram.org/botXXX/method
function handleTelegram(req, res, path) {
  const tgPath = path.replace(/^\/telegram/, "") || "/";
  const tgUrl = `https://${TELEGRAM_API}${tgPath}${url.parse(req.url).search || ""}`;
  const tgParsed = new URL(tgUrl);

  log("telegram", `${req.method} ${tgPath}`);

  const options = {
    hostname: tgParsed.hostname,
    port: 443,
    path: tgParsed.pathname + tgParsed.search,
    method: req.method,
    headers: {
      ...req.headers,
      host: TELEGRAM_API,
      "x-forwarded-proto": "https",
      "x-forwarded-for": req.socket.remoteAddress,
    },
    timeout: 30000,
  };

  // Remove proxy-specific headers
  delete options.headers["x-hc"];
  delete options.headers["x-target-host"];

  const proxyReq = https.request(options, (proxyRes) => {
    // Stream response back to HF Spaces
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (e) => {
    log("telegram", `ERROR: ${e.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
  });

  proxyReq.on("timeout", () => {
    proxyReq.destroy();
    if (!res.headersSent) {
      res.writeHead(504, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "proxy timeout" }));
    }
  });

  req.pipe(proxyReq);
}

// ── HTTP proxy for WhatsApp Web endpoints ────────────────────────────────
function handleWhatsAppHttp(req, res, path) {
  const waPath = path.replace(/^\/whatsapp/, "") || "/";
  // Default to web.whatsapp.com for primary WhatsApp Web traffic
  const targetHost = "web.whatsapp.com";
  const waUrl = `https://${targetHost}${waPath}${url.parse(req.url).search || ""}`;
  const waParsed = new URL(waUrl);

  log("whatsapp-http", `${req.method} ${waPath}`);

  const options = {
    hostname: waParsed.hostname,
    port: 443,
    path: waParsed.pathname + waParsed.search,
    method: req.method,
    headers: { ...req.headers, host: targetHost },
    timeout: 120000,
  };
  delete options.headers["x-hc"];
  delete options.headers["x-target-host"];

  const proxyReq = https.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on("error", (e) => {
    log("whatsapp-http", `ERROR: ${e.message}`);
    if (!res.headersSent) res.writeHead(502).end(e.message);
  });
  proxyReq.on("timeout", () => { proxyReq.destroy(); if (!res.headersSent) res.writeHead(504).end("timeout"); });
  req.pipe(proxyReq);
}

// ── Health endpoint ─────────────────────────────────────────────────────
function handleHealth(res) {
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(JSON.stringify({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    telegram: "https://api.telegram.org",
    whatsapp: "web.whatsapp.com",
  }));
}

// ── Status / landing page ───────────────────────────────────────────────
function handleStatus(res) {
  res.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-cache" });
  res.end(`HuggingClaw Render Proxy\nUptime: ${Math.floor(process.uptime())}s\n\nEndpoints:\n  /telegram/*     → Telegram Bot API proxy\n  /whatsapp/*     → WhatsApp Web HTTP proxy\n  /whatsapp-ws/   → WhatsApp WebSocket relay\n  /health         → Health check\n`);
}

// ── HTTP Server ──────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const path = url.parse(req.url).pathname;

  if (path === "/health") return handleHealth(res);
  if (path === "/" || path === "") return handleStatus(res);
  if (path.startsWith("/telegram")) return handleTelegram(req, res, path);
  if (path.startsWith("/whatsapp-ws")) {
    // WebSocket upgrade handled by the WSS server
    res.writeHead(426, { "Content-Type": "text/plain" });
    return res.end("Upgrade Required — use WebSocket");
  }
  if (path.startsWith("/whatsapp")) return handleWhatsAppHttp(req, res, path);

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

// ── WebSocket relay for WhatsApp Web ────────────────────────────────────
const wss = new WebSocketServer({ server, path: "/whatsapp-ws" });

wss.on("connection", (clientWs, req) => {
  const targetHost = req.headers["x-target-host"] || "wss.web.whatsapp.com";
  log("whatsapp-ws", `New connection → ${targetHost}`);

  // Extract target path from query or default to /
  const targetPath = url.parse(req.url).query || "/";
  const targetUrl = `wss://${targetHost}/${targetPath}`;

  let targetWs;
  try {
    targetWs = new (require("ws"))(targetUrl, {
      headers: { host: targetHost },
      handshakeTimeout: 15000,
    });
  } catch (e) {
    log("whatsapp-ws", `Connection error: ${e.message}`);
    clientWs.close();
    return;
  }

  // Bidirectional relay
  targetWs.on("open", () => {
    log("whatsapp-ws", `Connected to ${targetHost}`);
  });

  targetWs.on("message", (data) => {
    if (clientWs.readyState === clientWs.OPEN) clientWs.send(data);
  });

  targetWs.on("error", (e) => {
    log("whatsapp-ws", `Target error: ${e.message}`);
    clientWs.close();
  });

  targetWs.on("close", () => {
    clientWs.close();
  });

  clientWs.on("message", (data) => {
    if (targetWs.readyState === targetWs.OPEN) targetWs.send(data);
  });

  clientWs.on("error", (e) => {
    log("whatsapp-ws", `Client error: ${e.message}`);
    targetWs.close();
  });

  clientWs.on("close", () => {
    targetWs.close();
  });
});

// ── Start server ────────────────────────────────────────────────────────
server.listen(PORT, "0.0.0.0", () => {
  console.log(`[hc-render-proxy] Listening on port ${PORT}`);
  console.log(`[hc-render-proxy] Telegram → https://api.telegram.org`);
  console.log(`[hc-render-proxy] WhatsApp → web.whatsapp.com`);
});
