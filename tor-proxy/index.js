#!/usr/bin/env node
/**
 * HuggingClaw Tor Proxy — WebSocket relay through Tor SOCKS5
 *
 * Uses net.createServer: Node's http.Server has a C++ parser that reads
 * from the internal socket buffer directly — after a 101 upgrade response
 * it still consumes WS frame bytes, corrupting the stream.  With
 * net.createServer we control all bytes from the first read.
 *
 * Single port handles:
 *   - WebSocket      Upgrade request → 101 + JSON config relay via Tor
 *   - Health check   GET /health     → { status:"ok", tor:true }
 */

const net = require("net");
const crypto = require("crypto");
const { spawn } = require("child_process");

const PORT = process.env.PORT || 10000;
const TOR_HOST = "127.0.0.1";
const TOR_PORT = 9150;
const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6";

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

// ── WS frame relay → Tor ──
function startWsRelay(socket, initialBuf) {
  let frameBuf = Buffer.isBuffer(initialBuf) ? initialBuf : Buffer.alloc(0);
  let expectingConfig = true;
  let torSocket = null;

  function processFrames() {
    while (frameBuf.length >= 2) {
      const opcode = frameBuf[0] & 0x0F;
      const masked = (frameBuf[1] & 0x80) !== 0;
      let len = frameBuf[1] & 0x7F;
      let offset = 2;

      if (len === 126) { if (frameBuf.length < 4) return; len = frameBuf.readUInt16BE(2); offset = 4; }
      else if (len === 127) { if (frameBuf.length < 10) return; len = Number(frameBuf.readBigUInt64BE(2)); offset = 10; }

      if (masked) offset += 4;
      if (frameBuf.length < offset + len) return;

      const rawPayload = frameBuf.slice(offset, offset + len);
      const maskBytes = masked ? frameBuf.slice(offset - 4, offset) : null;
      let payload = rawPayload;
      if (maskBytes) {
        payload = Buffer.alloc(rawPayload.length);
        for (let i = 0; i < rawPayload.length; i++) payload[i] = rawPayload[i] ^ maskBytes[i % 4];
      }
      frameBuf = frameBuf.slice(offset + len);

      if (opcode === 0x8) { cleanup(); return; }
      if (opcode === 0x9) continue;

      if (expectingConfig) {
        try {
          const cfg = JSON.parse(payload.toString());
          const th = cfg.host || "opencode.ai";
          const tp = cfg.port || 443;
          socks5ViaTor(th, tp)
            .then((ts) => {
              torSocket = ts;
              expectingConfig = false;
              sendWsFrame(JSON.stringify({ status: "connected" }));
              ts.on("data", (td) => sendWsFrame(td));
              ts.on("error", cleanup);
              ts.on("close", cleanup);
            })
            .catch((err) => {
              try { sendWsFrame(JSON.stringify({ error: err.message })); } catch (e) {}
              cleanup();
            });
        } catch (e) { cleanup(); }
      } else if (torSocket) {
        try { torSocket.write(payload); } catch (e) {}
      }
    }
  }

  function sendWsFrame(data) {
    if (socket.destroyed) return;
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const len = buf.length;
    const hdr = len < 126 ? Buffer.from([0x82, len]) : (() => { const h = Buffer.alloc(4); h[0] = 0x82; h[1] = 126; h.writeUInt16BE(len, 2); return h; })();
    try { socket.write(Buffer.concat([hdr, buf])); } catch (e) {}
  }

  function cleanup() {
    socket.removeListener("data", onData);
    try { socket.destroy(); } catch (e) {}
    try { torSocket?.end(); } catch (e) {}
  }

  function onData(d) {
    frameBuf = Buffer.concat([frameBuf, d]);
    processFrames();
  }

  socket.on("data", onData);
  socket.on("error", cleanup);
  socket.on("close", cleanup);
  processFrames();
}

// ── Connection handler ──
const server = net.createServer((socket) => {
  socket.once("data", (data) => {
    if (data.length === 0) return;

    // All incoming data is HTTP (Render forwards HTTP after TLS termination).
    // Check for WS upgrade vs health check.
    const raw = data.toString();

    if (raw.includes("Upgrade: websocket") || raw.includes("upgrade: websocket")) {
      // WebSocket upgrade
      const key = raw.match(/Sec-WebSocket-Key:\s*(\S+)/i);
      if (!key) { socket.destroy(); return; }

      const accept = crypto.createHash("sha1").update(key[1] + WS_GUID).digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
      );

      // Determine what data came after the HTTP headers (the head)
      const idx = data.indexOf("\r\n\r\n");
      const headStart = idx >= 0 ? idx + 4 : data.length;
      const head = data.slice(headStart);

      startWsRelay(socket, head);
    } else {
      // Health check
      const body = JSON.stringify({ status: "ok", tor: true, torPort: TOR_PORT, port: PORT });
      socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(body) + "\r\nConnection: close\r\n\r\n" + body);
      socket.end();
    }
  });
});

// ── Startup ──
async function main() {
  console.log(`[tor-proxy] Starting on 0.0.0.0:${PORT}`);

  // 1. Start Tor
  const tor = spawn("tor", ["-f", "/app/torrc"], { stdio: ["ignore", "pipe", "pipe"] });
  tor.stdout.on("data", (d) => process.stdout.write(`[tor] ${d}`));
  tor.stderr.on("data", (d) => process.stderr.write(`[tor] ${d}`));
  tor.on("exit", (code) => { console.log(`[tor-proxy] Tor exited (code=${code})`); process.exit(1); });

  // 2. Wait for Tor circuit-ready (real connect test)
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

  // 3. Start server
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[tor-proxy] Proxy ready on :${PORT}`);
    console.log(`[tor-proxy]   WebSocket relay → Tor SOCKS5 :${TOR_PORT}`);
  });
}

main().catch((err) => { console.error("[tor-proxy] Fatal:", err); process.exit(1); });
