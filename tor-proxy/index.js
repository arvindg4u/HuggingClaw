#!/usr/bin/env node
/**
 * HuggingClaw Tor Proxy — WebSocket relay through Tor SOCKS5
 *
 * For Render deployment: Render terminates TLS at their edge and forwards
 * HTTP/WS to our server.  We use http.createServer (which integrates with
 * Node's C++ HTTP parser) so WS upgrades work through Render's proxy.
 *
 * Single port handles:
 *   - WebSocket      Upgrade header   → read JSON, chain to Tor SOCKS5
 *   - Health check   GET /health      → { status:"ok", tor:true, ... }
 */

const http = require("http");
const net = require("net");
const crypto = require("crypto");
const { spawn } = require("child_process");

const PORT = process.env.PORT || 10000;
const TOR_HOST = "127.0.0.1";
const TOR_PORT = 9150;

// ── Shared SOCKS5 chain helper ──
function socks5ViaTor(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0;
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("SOCKS5 timeout")); }, timeout);
    const cleanup = () => { clearTimeout(timer); socket.removeListener("data", onData); };

    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      try {
        if (state === 0 && buf.length >= 2) {
          if (buf[0] !== 0x05 || buf[1] !== 0x00) {
            cleanup(); socket.destroy();
            return reject(new Error(`Tor auth fail: ${buf[1]}`));
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
            cleanup(); socket.destroy();
            return reject(new Error(`Tor reject: ${buf[1]}`));
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
        cleanup(); reject(e);
      }
    };
    socket.on("data", onData);
    socket.on("error", (e) => { cleanup(); reject(e); });
    socket.setTimeout(timeout, () => { socket.destroy(); cleanup(); reject(new Error("connect timeout")); });
  });
}

// ── WebSocket frame relay → Tor SOCKS5 ──
// On Render, WS upgrades go through Node's http.Server 'upgrade' event.
// We extract the config JSON from the first WS frame, connect through Tor,
// then relay bidirectionally (WS frames ↔ Tor TCP).
const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6";

function startWsRelay(socket, head) {
  let frameBuf = Buffer.isBuffer(head) && head.length > 0 ? head : Buffer.alloc(0);
  let expectingConfig = true;
  let torSocket = null;

  function processBuffer() {
    if (expectingConfig) {
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

        if (opcode === 0x1 || opcode === 0x2) {
          try {
            const cfg = JSON.parse(payload.toString());
            const th = cfg.host || "opencode.ai";
            const tp = cfg.port || 443;

            socks5ViaTor(th, tp)
              .then((ts) => {
                torSocket = ts;
                expectingConfig = false;
                sendFrame(JSON.stringify({ status: "connected" }));
                ts.on("data", (td) => sendFrame(td));
                ts.on("error", cleanup);
                ts.on("close", cleanup);
              })
              .catch((err) => {
                console.log("[ws] Tor error: " + (err.message || err));
                try { sendFrame(JSON.stringify({ error: err.message || "Tor failed" })); } catch (e) {}
                cleanup();
              });
          } catch (e) {
            cleanup();
          }
        }
      }
    } else if (torSocket) {
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
        try { torSocket.write(payload); } catch (e) {}
      }
    }
  }

  function sendFrame(data) {
    if (socket.destroyed) return;
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const len = buf.length;
    let hdr;
    if (len < 126) { hdr = Buffer.from([0x82, len]); }
    else { hdr = Buffer.alloc(4); hdr[0] = 0x82; hdr[1] = 126; hdr.writeUInt16BE(len, 2); }
    try { socket.write(Buffer.concat([hdr, buf])); } catch (e) {}
  }

  function cleanup() {
    socket.removeListener("data", onFrameData);
    try { socket.destroy(); } catch (e) {}
    try { torSocket?.end(); } catch (e) {}
  }

  const onFrameData = (d) => {
    frameBuf = Buffer.concat([frameBuf, d]);
    processBuffer();
  };

  socket.on("data", onFrameData);
  socket.on("error", cleanup);
  socket.on("close", cleanup);

  // Process any initial data (e.g., WS frame in same TCP segment)
  processBuffer();
}

// ── HTTP server ──
// Node's http.Server parses HTTP and emits 'upgrade' for WS connections.
// This is compatible with Render's TLS-terminated proxy.
const server = http.createServer((req, res) => {
  // Health check
  const body = JSON.stringify({
    status: "ok",
    tor: true,
    torPort: TOR_PORT,
    port: PORT,
  });
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
});

// WebSocket upgrade handling
server.on("upgrade", (req, socket, head) => {
  const key = req.headers["sec-websocket-key"];
  if (!key) { socket.destroy(); return; }

  const accept = crypto
    .createHash("sha1")
    .update(key + WS_GUID)
    .digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + accept + "\r\n" +
    "\r\n"
  );

  startWsRelay(socket, head);
});

// ── Start Tor and launch server ──
async function main() {
  console.log(`[tor-proxy] Starting on 0.0.0.0:${PORT}`);

  const tor = spawn("tor", ["-f", "/app/torrc"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  tor.stdout.on("data", (d) => process.stdout.write(`[tor] ${d}`));
  tor.stderr.on("data", (d) => process.stderr.write(`[tor] ${d}`));
  tor.on("exit", (code) => {
    console.log(`[tor-proxy] Tor exited (code=${code})`);
    process.exit(1);
  });

  // Wait for Tor to be circuit-ready (real connect test)
  console.log("[tor-proxy] Waiting for Tor circuits...");
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => {
          s.write(Buffer.from([0x05, 0x01, 0x00]));
        });
        let state = 0, buf = Buffer.alloc(0);
        const timer = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
        s.on("data", (d) => {
          buf = Buffer.concat([buf, d]);
          if (state === 0 && buf.length >= 2) {
            if (buf[0] !== 0x05 || buf[1] !== 0x00) { clearTimeout(timer); s.destroy(); reject(new Error("auth fail")); return; }
            state = 1;
            const hb = Buffer.from("httpbin.org");
            s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([0x01, 0xBB])]));
            buf = Buffer.alloc(0);
          } else if (state === 1 && buf.length >= 4) {
            clearTimeout(timer);
            if (buf[1] === 0x00) { s.end(); resolve(); }
            else { s.destroy(); reject(new Error("Tor reject: " + buf[1])); }
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

main().catch((err) => {
  console.error("[tor-proxy] Fatal:", err);
  process.exit(1);
});
