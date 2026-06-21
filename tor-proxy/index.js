#!/usr/bin/env node
/**
 * HuggingClaw Tor Proxy — WebSocket relay through Tor SOCKS5
 *
 * Uses http.createServer + ws.WebSocketServer for Render compatibility.
 * Render's reverse proxy requires the HTTP protocol to be handled by
 * Node's built-in http.Server (the C++ HTTP parser) — raw TCP byte
 * sniffing with net.createServer breaks their proxy's WS forwarding.
 *
 * Single port handles:
 *   - WebSocket      WS relay → Tor SOCKS5 → target (IP rotation)
 *   - Health check   GET /    → { status:"ok", tor:true }
 */

const http = require("http");
const net = require("net");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const TOR_HOST = "127.0.0.1";
const TOR_PORT = 9150;

// ── SOCKS5 through Tor ──
function socks5ViaTor(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0, buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("timeout")); }, timeout);
    const cleanup = () => { clearTimeout(timer); socket.removeListener("data", onData); };
    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      try {
        if (state === 0 && buf.length >= 2) {
          if (buf[0] !== 0x05 || buf[1] !== 0x00) { cleanup(); socket.destroy(); return reject(new Error("auth fail")); }
          state = 1;
          const hb = Buffer.from(targetHost);
          socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]));
          buf = Buffer.alloc(0);
        } else if (state === 1 && buf.length >= 4) {
          if (buf[1] !== 0x00) { cleanup(); socket.destroy(); return reject(new Error("reject: " + buf[1])); }
          const at = buf[3];
          let need = 4;
          if (at === 0x01) need = 10;
          else if (at === 0x03) need = 4 + 1 + buf[4] + 2;
          else if (at === 0x04) need = 4 + 16 + 2;
          if (buf.length >= need) { cleanup(); resolve(socket); }
        }
      } catch (e) { cleanup(); reject(e); }
    };
    socket.on("data", onData);
    socket.on("error", (e) => { cleanup(); reject(e); });
    socket.setTimeout(timeout, () => { socket.destroy(); cleanup(); reject(new Error("timeout")); });
  });
}

// ── HTTP server ──
const server = http.createServer((req, res) => {
  const body = JSON.stringify({ status: "ok", tor: true, torPort: TOR_PORT, port: PORT });
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(body);
});

// ── WebSocket server ──
const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  // Client connected via WS — now send JSON config
  let expectingConfig = true;
  let torSocket = null;
  let configBuffer = Buffer.alloc(0);

  ws.on("message", (data) => {
    if (expectingConfig) {
      try {
        const cfg = JSON.parse(data.toString());
        const th = cfg.host || "opencode.ai";
        const tp = cfg.port || 443;

        socks5ViaTor(th, tp)
          .then((ts) => {
            torSocket = ts;
            expectingConfig = false;
            ws.send(JSON.stringify({ status: "connected" }));

            // Bidirectional relay
            ts.on("data", (td) => {
              try { if (ws.readyState === ws.OPEN) ws.send(td); } catch (e) {}
            });
            ts.on("error", () => cleanup());
            ts.on("close", () => cleanup());
          })
          .catch((err) => {
            try { ws.send(JSON.stringify({ error: err.message })); } catch (e) {}
            cleanup();
          });
      } catch (e) {
        cleanup();
      }
    } else if (torSocket) {
      // Relay data to Tor
      try {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        torSocket.write(buf);
      } catch (e) {
        console.log("[ws] relay write error: " + e.message);
        cleanup();
      }
    }
  });

  ws.on("close", (code, reason) => {
    console.log("[ws] client closed: code=" + code + " reason=" + (reason ? reason.toString() : "none"));
    cleanup();
  });
  ws.on("error", (e) => { console.log("[ws] client error: " + e.message); cleanup(); });

  function cleanup() {
    try { ws.close(); } catch (e) {}
    try { torSocket?.end(); } catch (e) {}
  }
});

// Handle WS upgrade requests
server.on("upgrade", (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

// ── Startup ──
async function main() {
  console.log(`[tor-proxy] Starting on 0.0.0.0:${PORT}`);

  const tor = spawn("tor", ["-f", "/app/torrc"], { stdio: ["ignore", "pipe", "pipe"] });
  tor.stdout.on("data", (d) => process.stdout.write(`[tor] ${d}`));
  tor.stderr.on("data", (d) => process.stderr.write(`[tor] ${d}`));
  tor.on("exit", (code) => { console.log(`[tor-proxy] Tor exited (code=${code})`); process.exit(1); });

  // Wait for real circuit-ready
  console.log("[tor-proxy] Waiting for Tor circuits...");
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => { s.write(Buffer.from([0x05, 0x01, 0x00])); });
        let state = 0, buf = Buffer.alloc(0);
        const timer = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
        s.on("data", (d) => {
          buf = Buffer.concat([buf, d]);
          if (state === 0 && buf.length >= 2) {
            if (buf[0] !== 0x05 || buf[1] !== 0x00) { clearTimeout(timer); s.destroy(); reject(new Error("auth")); return; }
            state = 1;
            const hb = Buffer.from("httpbin.org");
            s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([0x01, 0xBB])]));
            buf = Buffer.alloc(0);
          } else if (state === 1 && buf.length >= 4) {
            clearTimeout(timer);
            if (buf[1] === 0x00) { s.end(); resolve(); } else { s.destroy(); reject(new Error("reject:" + buf[1])); }
          }
        });
        s.on("error", (e) => { clearTimeout(timer); reject(e); });
      });
      ready = true;
      console.log(`[tor-proxy] Tor circuit-ready after ${attempt + 1}s`);
      break;
    } catch (e) {
      if (attempt < 59) await new Promise((r) => setTimeout(r, 1000));
    }
  }
  if (!ready) console.log("[tor-proxy] WARNING: Tor not ready");

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[tor-proxy] Proxy ready on :${PORT}`);
    console.log(`[tor-proxy]   WebSocket relay → Tor SOCKS5 :${TOR_PORT}`);
  });
}

main().catch((err) => { console.error("[tor-proxy] Fatal:", err); process.exit(1); });
