/**
 * HuggingClaw Render Proxy — Telegram + WhatsApp + Discord relay
 *
 * Deploy on Render free tier.  HF Spaces routes Telegram API, WhatsApp, and Discord
 * traffic through this proxy to bypass outbound connection blocks.
 *
 * Endpoints:
 *   /telegram/*         →  proxies to https://api.telegram.org/*
 *   /whatsapp/*         →  proxies WhatsApp Web HTTP endpoints
 *   /whatsapp-ws/       →  WebSocket proxy for WhatsApp Web
 *   /discord/*          →  proxies to https://discord.com/*
 *   /health             →  health check (for cron ping)
 *   /                   →  status page
 */
"use strict";

const http = require("http");
const https = require("https");
const net = require("net");
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
  // For getUpdates (long-poll), cap timeout at 25s so Render's
  // infrastructure doesn't kill the long connection.
  let queryStr = url.parse(req.url).search || "";
  if (tgPath.includes("getUpdates")) {
    // Remove any existing timeout parameter
    queryStr = queryStr.replace(/(^|&)timeout=[^&]*/g, "");
    // Add our capped timeout
    queryStr = queryStr ? queryStr + "&timeout=25" : "?timeout=25";
  }
  const tgUrl = `https://${TELEGRAM_API}${tgPath}${queryStr}`;
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
// Supports all WhatsApp domains via x-target-host header:
//   web.whatsapp.com, g.whatsapp.net, mmg.whatsapp.net,
//   pps.whatsapp.net, static.whatsapp.net
function handleWhatsAppHttp(req, res, path) {
  const waPath = path.replace(/^\/whatsapp/, "") || "/";
  // Use x-target-host header to determine the actual WhatsApp domain
  const targetHost = req.headers["x-target-host"] || "web.whatsapp.com";
  const waUrl = `https://${targetHost}${waPath}${url.parse(req.url).search || ""}`;
  const waParsed = new URL(waUrl);

  log("whatsapp-http", `${req.method} ${waPath} → ${targetHost}`);

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

// ── HTTP proxy for Discord API ───────────────────────────────────────────
function handleDiscord(req, res, path) {
  const discordPath = path.replace(/^\/discord/, "") || "/";
  const options = {
    hostname: "discord.com",
    port: 443,
    path: discordPath,
    method: req.method,
    headers: { ...req.headers },
    timeout: 30000,
  };
  delete options.headers["host"];
  delete options.headers["x-target-host"];

  log("discord", `${req.method} ${discordPath}`);
  const proxyReq = https.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on("error", (e) => {
    log("discord", `ERROR: ${e.message}`);
    if (!res.headersSent) res.writeHead(502).end(JSON.stringify({ error: e.message }));
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
    discord: "https://discord.com",
  }));
}

// ── Status / landing page ───────────────────────────────────────────────
function handleStatus(res) {
  res.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-cache" });
  res.end(`HuggingClaw Render Proxy\nUptime: ${Math.floor(process.uptime())}s\n\nEndpoints:\n  /telegram/*     → Telegram Bot API proxy\n  /whatsapp/*     → WhatsApp Multi-domain HTTP proxy (x-target-host)\n  /whatsapp-ws    → WhatsApp WebSocket relay (query: ?host=&path=)\n  /discord/*      → Discord API proxy\n  /health         → Health check\n`);
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
  if (path.startsWith("/discord")) return handleDiscord(req, res, path);

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

// ── WebSocket relay for WhatsApp Web (any domain, any path) ─────────────
// Baileys connects to wss.web.whatsapp.com with dynamic paths.
// The client sends the target as a query param: /whatsapp-ws?path=/ws&host=g.whatsapp.net
// Or uses x-target-host + x-target-path headers for non-primary domains.
const wss = new WebSocketServer({ server, path: "/whatsapp-ws" });

function parseWsTarget(req) {
  const query = url.parse(req.url, true).query;
  const host = req.headers["x-target-host"] || query.host || "wss.web.whatsapp.com";
  const path = query.path || req.headers["x-target-path"] || "/";
  return { host: host.replace(/^wss:\/\//, "").replace(/\/.*$/, ""), path };
}

wss.on("connection", (clientWs, req) => {
  const target = parseWsTarget(req);
  const targetUrl = `wss://${target.host}${target.path}`;
  log("whatsapp-ws", `New → ${target.host}${target.path}`);

  let targetWs;
  try {
    targetWs = new (require("ws"))(targetUrl, {
      headers: { host: target.host, origin: "https://web.whatsapp.com" },
      handshakeTimeout: 20000,
      rejectUnauthorized: false,
    });
  } catch (e) {
    log("whatsapp-ws", `Connection failed: ${e.message}`);
    clientWs.close(1011, e.message);
    return;
  }

  let errLogged = false;

  targetWs.on("open", () => {
    log("whatsapp-ws", `Connected to ${target.host}`);
  });

  targetWs.on("message", (data, isBinary) => {
    if (clientWs.readyState === clientWs.OPEN) {
      clientWs.send(data, { binary: isBinary });
    }
  });

  targetWs.on("error", (e) => {
    if (!errLogged) { errLogged = true; log("whatsapp-ws", `Target err: ${e.message}`); }
    try { clientWs.close(); } catch (_) {}
  });

  targetWs.on("close", (code, reason) => {
    try { clientWs.close(code, reason); } catch (_) {}
  });

  clientWs.on("message", (data, isBinary) => {
    if (targetWs.readyState === targetWs.OPEN) {
      targetWs.send(data, { binary: isBinary });
    }
  });

  clientWs.on("error", (e) => {
    if (!errLogged) { errLogged = true; log("whatsapp-ws", `Client err: ${e.message}`); }
    try { targetWs.close(); } catch (_) {}
  });

  clientWs.on("close", (code, reason) => {
    try { targetWs.close(code, reason); } catch (_) {}
  });
});


// ── WebSocket TCP tunnel for Discord Gateway ──────────────────────────
// cloudflare-proxy.js connects here and sends {host, port} JSON to tunnel
// TCP traffic through Render\'s unrestricted outbound (bypasses WireGuard).
// Protocol matches the "legacy format" used by wg-proxy/relay.js:
//   1. Client sends:  {"host":"gateway.discord.gg","port":443}
//   2. Server replies: {"status":"connected"}
//   3. Binary frames flow bidirectionally
const discordWss = new WebSocketServer({ server, path: "/discord-ws" });

discordWss.on("connection", (ws, req) => {
  log("discord-ws", "New tunnel connection");
  let targetSocket = null;

  const cleanup = () => {
    if (targetSocket) { try { targetSocket.end(); } catch(_) {} targetSocket = null; }
  };

  ws.on("message", (data, isBinary) => {
    if (!isBinary) {
      // Text frame \u2014 JSON control message
      const str = typeof data === "string" ? data : data.toString();
      try {
        const msg = JSON.parse(str);
        if (msg.host && msg.port && !targetSocket) {
          const host = msg.host;
          const port = parseInt(msg.port) || 443;
          log("discord-ws", `Connecting to ${host}:${port}`);

          targetSocket = net.connect(port, host, () => {
            log("discord-ws", `Connected to ${host}:${port}`);
            if (ws.readyState === ws.OPEN) {
              ws.send(JSON.stringify({ status: "connected" }), { binary: false });
            }
          });

          targetSocket.on("data", (td) => {
            if (ws.readyState === ws.OPEN) {
              ws.send(td, { binary: true });
            }
          });

          targetSocket.on("error", (err) => {
            log("discord-ws", `Socket error: ${err.message}`);
            try { ws.send(JSON.stringify({ error: err.message })); } catch(_) {}
            cleanup();
          });

          targetSocket.on("close", () => {
            log("discord-ws", `Socket closed for ${host}:${port}`);
            cleanup();
            try { ws.close(); } catch(_) {}
          });

          return;
        }
        if (msg.error && ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ error: msg.error }));
        }
      } catch(e) {
        log("discord-ws", `Invalid JSON: ${e.message}`);
      }
      return;
    }

    // Binary frame \u2014 forward to target socket
    if (targetSocket) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      try { targetSocket.write(buf); } catch(_) {}
    }
  });

  ws.on("close", () => {
    log("discord-ws", "WebSocket closed");
    cleanup();
  });

  ws.on("error", (e) => {
    log("discord-ws", `WebSocket error: ${e.message}`);
    cleanup();
  });
});

// ── WebSocket TCP tunnel for WhatsApp ────────────────────────────
// Same protocol as discord-ws: client sends JSON {host, port},
// server connects via net.connect(), binary frames flow bidirectionally.
const whatsappWss = new WebSocketServer({ server, path: "/whatsapp-tcp" });

whatsappWss.on("connection", (ws, req) => {
  log("whatsapp-tcp", "New tunnel connection");
  let targetSocket = null;

  const cleanup = () => {
    if (targetSocket) { try { targetSocket.end(); } catch(_) {} targetSocket = null; }
  };

  ws.on("message", (data, isBinary) => {
    if (!isBinary) {
      const str = typeof data === "string" ? data : data.toString();
      try {
        const msg = JSON.parse(str);
        if (msg.host && msg.port && !targetSocket) {
          const host = msg.host;
          const port = parseInt(msg.port) || 443;
          log("whatsapp-tcp", `Connecting to ${host}:${port}`);

          targetSocket = net.connect(port, host, () => {
            log("whatsapp-tcp", `Connected to ${host}:${port}`);
            if (ws.readyState === ws.OPEN) {
              ws.send(JSON.stringify({ status: "connected" }), { binary: false });
            }
          });

          targetSocket.on("data", (td) => {
            if (ws.readyState === ws.OPEN) {
              ws.send(td, { binary: true });
            }
          });

          targetSocket.on("error", (err) => {
            log("whatsapp-tcp", `Socket error: ${err.message}`);
            try { ws.send(JSON.stringify({ error: err.message })); } catch(_) {}
            cleanup();
          });

          targetSocket.on("close", () => {
            log("whatsapp-tcp", `Socket closed for ${host}:${port}`);
            cleanup();
            try { ws.close(); } catch(_) {}
          });

          return;
        }
        if (msg.error && ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ error: msg.error }));
        }
      } catch(e) {
        log("whatsapp-tcp", `Invalid JSON: ${e.message}`);
      }
      return;
    }

    if (targetSocket) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      try { targetSocket.write(buf); } catch(_) {}
    }
  });

  ws.on("close", () => {
    log("whatsapp-tcp", "WebSocket closed");
    cleanup();
  });

  ws.on("error", (e) => {
    log("whatsapp-tcp", `WebSocket error: ${e.message}`);
    cleanup();
  });
});

// ── Self-ping every 10min to prevent Render free tier sleep ─────────────
setInterval(() => {
  http.get(`http://127.0.0.1:${PORT}/health`, (r) => r.resume());
}, 10 * 60 * 1000);

// ── Start server ────────────────────────────────────────────────────────
server.listen(PORT, "0.0.0.0", () => {
  console.log(`[hc-render-proxy] Listening on port ${PORT}`);
  console.log(`[hc-render-proxy] Telegram → https://api.telegram.org`);
  console.log(`[hc-render-proxy] WhatsApp → web.whatsapp.com / g.whatsapp.net / mmg.whatsapp.net / pps.whatsapp.net / static.whatsapp.net`);
  console.log(`[hc-render-proxy] Discord WS tunnel → /discord-ws (TCP relay for gateway.discord.gg)`);
  console.log(`[hc-render-proxy] WhatsApp TCP tunnel → /whatsapp-tcp (TCP relay for WhatsApp domains)`);
  console.log(`[hc-render-proxy] Cron ping → /health every 10min to keep awake`);
});
