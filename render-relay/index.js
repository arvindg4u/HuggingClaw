const http = require("http");
const https = require("https");
const net = require("net");
const tls = require("tls");
const { WebSocketServer } = require("ws");
const { URL } = require("url");

const PORT = process.env.PORT || 10000;

/**
 * HuggingClaw WebSocket-to-TCP Relay — single-port mode
 *
 * Same port (PORT) handles:
 *   - HTTP health checks   GET /health
 *   - WebSocket relay      WS /whatsapp?host=X&port=Y
 *   - SOCKS5 proxy         Raw TCP, first byte 0x05
 *   - HTTP CONNECT proxy   CONNECT host:port HTTP/1.1
 */

function socks5Connect(clientSocket, data) {
  let buf = Buffer.from(data);
  let state = 0;
  let targetHost, targetPort;

  const onData = (d) => {
    buf = Buffer.concat([buf, d]);

    if (state === 0 && buf.length >= 2) {
      if (buf[0] !== 0x05) { clientSocket.destroy(); return; }
      clientSocket.write(Buffer.from([0x05, 0x00]));
      state = 1;
      buf = Buffer.alloc(0);
      return;
    }

    if (state === 1 && buf.length >= 4) {
      const atyp = buf[3];
      if (atyp === 0x01) {
        if (buf.length < 10) return;
        targetHost = buf.slice(4, 8).join(".");
        targetPort = buf.readUInt16BE(8);
      } else if (atyp === 0x03) {
        const len = buf[4];
        if (buf.length < 7 + len) return;
        targetHost = buf.slice(5, 5 + len).toString();
        targetPort = buf.readUInt16BE(5 + len);
      } else { clientSocket.destroy(); return; }

      const target = net.createConnection({ host: targetHost, port: targetPort }, () => {
        clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        target.pipe(clientSocket);
        clientSocket.pipe(target);
      });
      target.on("error", () => clientSocket.destroy());
      clientSocket.on("error", () => target.destroy());
      state = 2;
    }
  };

  clientSocket.on("data", onData);
}

function httpConnectProxy(clientSocket, data) {
  const req = data.toString();
  const match = req.match(/^CONNECT\s+([^:]+):(\d+)\s+HTTP/i);
  if (!match) { clientSocket.destroy(); return; }

  const targetHost = match[1];
  const targetPort = parseInt(match[2]);

  const target = net.createConnection({ host: targetHost, port: targetPort }, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    target.pipe(clientSocket);
    clientSocket.pipe(target);
  });
  target.on("error", () => clientSocket.destroy());
  clientSocket.on("error", () => target.destroy());
}

// ── Host-level WebSocket → TCP relay ──
const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const targetHost = url.searchParams.get("host") || "web.whatsapp.com";
  const targetPort = parseInt(url.searchParams.get("port")) || 443;
  const useTls = url.searchParams.get("tls") !== "false";

  console.log(`WS relay: ${targetHost}:${targetPort}`);

  let targetSocket;
  const cleanup = () => { try { targetSocket?.end(); } catch {} };

  const connectTarget = () => {
    if (useTls) {
      targetSocket = tls.connect(targetPort, targetHost, { rejectUnauthorized: false }, () => {
        try { ws.send(JSON.stringify({ type: "connected" })); } catch {}
      });
    } else {
      targetSocket = net.createConnection(targetPort, targetHost, () => {
        try { ws.send(JSON.stringify({ type: "connected" })); } catch {}
      });
    }

    targetSocket.on("data", (d) => { try { if (ws.readyState === ws.OPEN) ws.send(d); } catch {} });
    targetSocket.on("error", (e) => { console.log(`TCP err: ${e.message}`); cleanup(); try { ws.close(); } catch {} });
    targetSocket.on("close", () => { try { ws.close(); } catch {} });
  };

  connectTarget();

  ws.on("message", (d) => {
    try { targetSocket?.write(Buffer.from(d)); } catch {}
  });
  ws.on("close", cleanup);
  ws.on("error", cleanup);
});

// ── Single-port connection handler ──
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/health" || url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", socks5: `:${PORT}`, wsRelay: true }));
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

// WebSocket upgrade
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/whatsapp") || url.pathname.startsWith("/ws")) {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  } else {
    socket.destroy();
  }
});

// Detect SOCKS5 / HTTP CONNECT on the same port
server.on("connection", (socket) => {
  socket.once("data", (data) => {
    if (data.length === 0) return;

    const firstByte = data[0];

    if (firstByte === 0x05) {
      // SOCKS5
      socks5Connect(socket, data);
    } else if (firstByte === 0x43) {
      // 'C' — HTTP CONNECT
      httpConnectProxy(socket, data);
    } else {
      // Regular HTTP — re-emit to HTTP server
      socket.unshift(data);
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Relay ready on :${PORT}`);
  console.log(`  SOCKS5 / HTTP CONNECT / WS / HTTP — all on same port`);
});
