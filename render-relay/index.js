const http = require("http");
const https = require("https");
const net = require("net");
const tls = require("tls");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const SOCKS_PORT = 9050;

/**
 * HuggingClaw WebSocket-to-TCP Relay
 *
 * HF Spaces blocks outbound WhatsApp connections. This relay:
 * 1. Accepts WebSocket connections from HF Space
 * 2. Upgrades to TCP/TLS to target (web.whatsapp.com)
 * 3. Bidirectional relay — WebSocket ↔ TCP
 *
 * Also provides SOCKS5 proxy on :9050 for HTTP CONNECT.
 */

// ── SOCKS5 Proxy ──
const socksServer = net.createServer((clientSocket) => {
  let state = 0; // 0=auth, 1=request
  let buf = Buffer.alloc(0);

  clientSocket.on("data", (data) => {
    buf = Buffer.concat([buf, data]);

    if (state === 0 && buf.length >= 2) {
      if (buf[0] !== 0x05) { clientSocket.destroy(); return; }
      clientSocket.write(Buffer.from([0x05, 0x00]));
      state = 1;
      buf = Buffer.alloc(0);
      return;
    }

    if (state === 1 && buf.length >= 4) {
      const ver = buf[0];
      const cmd = buf[1];
      const atyp = buf[3];
      let host, port, headerLen;

      if (atyp === 0x01) { // IPv4
        if (buf.length < 10) return;
        host = buf.slice(4, 8).join(".");
        port = buf.readUInt16BE(8);
        headerLen = 10;
      } else if (atyp === 0x03) { // Domain
        const len = buf[4];
        if (buf.length < 7 + len) return;
        host = buf.slice(5, 5 + len).toString();
        port = buf.readUInt16BE(5 + len);
        headerLen = 7 + len;
      } else { clientSocket.destroy(); return; }

      // Connect to target
      const target = net.createConnection({ host, port }, () => {
        clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        target.pipe(clientSocket);
        clientSocket.pipe(target);
      });
      target.on("error", () => clientSocket.destroy());
      clientSocket.on("error", () => target.destroy());
      buf = Buffer.alloc(0);
      state = 2;
    }
  });
});

socksServer.listen(SOCKS_PORT, "0.0.0.0", () => {
  console.log(`SOCKS5 proxy ready on :${SOCKS_PORT}`);
});

// ── WebSocket-to-TCP Relay ──
const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const targetHost = url.searchParams.get("host") || "web.whatsapp.com";
  const targetPort = parseInt(url.searchParams.get("port")) || 443;
  const useTls = url.searchParams.get("tls") !== "false";

  console.log(`WS relay: ${targetHost}:${targetPort}`);

  let targetSocket;
  const targetCleanup = () => { try { targetSocket?.end(); } catch {} };

  if (useTls) {
    targetSocket = tls.connect(targetPort, targetHost, { rejectUnauthorized: false }, () => {
      ws.send(JSON.stringify({ type: "connected" }));
    });
  } else {
    targetSocket = net.createConnection(targetPort, targetHost, () => {
      ws.send(JSON.stringify({ type: "connected" }));
    });
  }

  targetSocket.on("data", (data) => {
    if (ws.readyState === ws.OPEN) ws.send(data);
  });
  targetSocket.on("error", (e) => {
    console.log(`TCP error: ${e.message}`);
    try { ws.close(); } catch {}
  });
  targetSocket.on("close", () => { try { ws.close(); } catch {} });

  ws.on("message", (data) => {
    try {
      // Check if it's a control message
      const msg = JSON.parse(data.toString());
      if (msg.type === "target") {
        // Reconnect to new target
        targetCleanup();
        // (simplified: reconnect logic)
        return;
      }
    } catch {}
    // Binary data — forward to target
    try { targetSocket.write(Buffer.from(data)); } catch {}
  });
  ws.on("close", targetCleanup);
  ws.on("error", targetCleanup);
});

// ── HTTP Server (for health checks + WebSocket upgrade) ──
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  // Health check
  if (url.pathname === "/health" || url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", socks: `:${SOCKS_PORT}`, wsRelay: true }));
    return;
  }

  // WhatsApp WebSocket relay path
  if (url.pathname === "/whatsapp" || url.pathname.startsWith("/whatsapp/")) {
    res.writeHead(426, { "Content-Type": "text/plain" });
    res.end("WebSocket connection required");
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

// WebSocket upgrade handling
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/whatsapp") || url.pathname.startsWith("/ws")) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Relay server ready on :${PORT}`);
  console.log(`  WS endpoint: /whatsapp?host=web.whatsapp.com&port=443`);
  console.log(`  SOCKS5: :${SOCKS_PORT}`);
});
