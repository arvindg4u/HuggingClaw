#!/usr/bin/env node
/**
 * HuggingClaw Tor Proxy — SOCKS5 / HTTP CONNECT / WebSocket relay through Tor
 *
 * Routes all upstream traffic through the local Tor SOCKS5 proxy
 * (127.0.0.1:9150) so every connection uses a different Tor exit node IP.
 *
 * Single port (10000) handles:
 *   - SOCKS5         first byte 0x05  → chain to Tor SOCKS5
 *   - HTTP CONNECT   first byte 'C'   → chain to Tor SOCKS5
 *   - WebSocket      Upgrade header   → read JSON, chain to Tor SOCKS5
 *   - Health check   GET /health      → { status:"ok", tor:true, ... }
 */

const net = require("net");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { Duplex } = require("stream");

const PORT = process.env.PORT || 10000;
const TOR_HOST = "127.0.0.1";
const TOR_PORT = 9150;

// ── Shared SOCKS5 chain helper ──
// Opens a TCP connection to Tor SOCKS5, does the handshake,
// and requests a connection to targetHost:targetPort.
// Returns { socket } on success, throws on failure.
function socks5ViaTor(targetHost, targetPort, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => {
      // Greeting: SOCKS5, 1 method, no auth
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0; // 0=greeting, 1=connect, 2=done
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("SOCKS5 timeout")); }, timeout);
    const cleanup = () => { clearTimeout(timer); socket.removeListener("data", onData); };

    const onData = (data) => {
      buf = Buffer.concat([buf, data]);
      try {
        if (state === 0 && buf.length >= 2) {
          if (buf[0] !== 0x05 || buf[1] !== 0x00) {
            cleanup(); socket.destroy();
            return reject(new Error(`Tor SOCKS5 auth fail: ${buf[1]}`));
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
            return reject(new Error(`Tor SOCKS5 reject: ${buf[1]}`));
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

// ── SOCKS5 proxy handler (client -> Tor SOCKS5 -> target) ──
function handleSocks5(clientSocket, firstData) {
  let buf = Buffer.from(firstData);
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

      state = 2; // connecting
      socks5ViaTor(targetHost, targetPort)
        .then((torSocket) => {
          // SOCKS5 success response (BND.ADDR = 0.0.0.0:0 meaning Tor's bind)
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          torSocket.pipe(clientSocket);
          clientSocket.pipe(torSocket);
        })
        .catch(() => {
          clientSocket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.destroy();
        });
    }
  };

  clientSocket.on("data", onData);
  clientSocket.on("error", () => {});
}

// ── HTTP CONNECT handler ──
function handleHttpConnect(clientSocket, firstData) {
  const req = firstData.toString();
  const match = req.match(/^CONNECT\s+([^:]+):(\d+)\s+HTTP/i);
  if (!match) {
    clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    clientSocket.destroy();
    return;
  }
  const targetHost = match[1];
  const targetPort = parseInt(match[2]);

  socks5ViaTor(targetHost, targetPort)
    .then((torSocket) => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      torSocket.pipe(clientSocket);
      clientSocket.pipe(torSocket);
    })
    .catch(() => {
      clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      clientSocket.destroy();
    });
}

const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6";

// ── WebSocket upgrade handler (from HTTP server 'upgrade' event) ──
// Node's http parser has already parsed the request headers.
function handleWsUpgrade(req, socket, head) {
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

  // Start frame relay — head may contain first frame data
  startWsRelay(socket, head);
}

// ── WebSocket handler (from raw connection sniff) ──
// We have raw HTTP text — extract key, send 101, start relay.
function handleWsFromRaw(socket, rawData) {
  const raw = rawData.toString();
  const m = raw.match(/Sec-WebSocket-Key:\s*(\S+)/i);
  if (!m) { socket.destroy(); return; }

  const accept = crypto
    .createHash("sha1")
    .update(m[1] + WS_GUID)
    .digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + accept + "\r\n" +
    "\r\n"
  );

  // The rawData still has the HTTP headers read already — parse past them
  const idx = rawData.indexOf("\r\n\r\n");
  const bodyStart = idx >= 0 ? idx + 4 : rawData.length;
  const initialData = rawData.slice(bodyStart);
  startWsRelay(socket, initialData);
}

// ── WebSocket frame relay → Tor SOCKS5 ──
// Reads masked WS frames, extracts config JSON, connects to Tor,
// then relays bidirectionally (WS frames ↔ Tor TCP).
function startWsRelay(clientSocket, initialData) {
  let frameBuf = Buffer.isBuffer(initialData) ? initialData : Buffer.alloc(0);
  let expectingConfig = true;
  let torSocket = null;

  const onFrameData = (d) => {
    frameBuf = Buffer.concat([frameBuf, d]);

    if (expectingConfig) {
      // Try to parse WS frame
      while (frameBuf.length >= 2) {
        const opcode = frameBuf[0] & 0x0F;
        const masked = (frameBuf[1] & 0x80) !== 0;
        let len = frameBuf[1] & 0x7F;
        let offset = 2;

        if (len === 126) {
          if (frameBuf.length < 4) return;
          len = frameBuf.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (frameBuf.length < 10) return;
          len = Number(frameBuf.readBigUInt64BE(2));
          offset = 10;
        }

        if (masked) offset += 4;
        if (frameBuf.length < offset + len) return;

        const rawPayload = frameBuf.slice(offset, offset + len);
        const maskBytes = masked ? frameBuf.slice(offset - 4, offset) : null;

        let payload = rawPayload;
        if (maskBytes) {
          payload = Buffer.alloc(rawPayload.length);
          for (let i = 0; i < rawPayload.length; i++) {
            payload[i] = rawPayload[i] ^ maskBytes[i % 4];
          }
        }

        frameBuf = frameBuf.slice(offset + len);

        if (opcode === 0x8) { // close
          cleanup();
          return;
        }
        if (opcode === 0x9) continue; // ping

        if (opcode === 0x1 || opcode === 0x2) { // text/binary
          try {
            const cfg = JSON.parse(payload.toString());
            const th = cfg.host || "opencode.ai";
            const tp = cfg.port || 443;

            console.log("[ws] connecting via Tor to " + th + ":" + tp);
            socks5ViaTor(th, tp)
              .then((ts) => {
                console.log("[ws] Tor connected to " + th);
                torSocket = ts;
                expectingConfig = false;

                // Send "connected" response over WS
                const msg = Buffer.from(JSON.stringify({ status: "connected" }));
                sendWsFrame(msg);

                // Bidirectional relay
                ts.on("data", (td) => sendWsFrame(td));
                ts.on("error", cleanup);
                ts.on("close", cleanup);
              })
              .catch((err) => {
                console.log("[ws] Tor connect failed: " + (err.message || err));
                const errMsg = Buffer.from(JSON.stringify({ error: "Tor connection failed" }));
                sendWsFrame(errMsg);
                cleanup();
              });
          } catch (e) {
            cleanup();
          }
        }
      }
    } else if (torSocket) {
      // Data frames during relay — forward to Tor
      while (frameBuf.length >= 2) {
        const opcode = frameBuf[0] & 0x0F;
        const masked = (frameBuf[1] & 0x80) !== 0;
        let len = frameBuf[1] & 0x7F;
        let offset = 2;

        if (len === 126) {
          if (frameBuf.length < 4) return;
          len = frameBuf.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (frameBuf.length < 10) return;
          len = Number(frameBuf.readBigUInt64BE(2));
          offset = 10;
        }

        if (masked) offset += 4;
        if (frameBuf.length < offset + len) return;

        const rawPayload = frameBuf.slice(offset, offset + len);
        const maskBytes = masked ? frameBuf.slice(offset - 4, offset) : null;

        let payload = rawPayload;
        if (maskBytes) {
          payload = Buffer.alloc(rawPayload.length);
          for (let i = 0; i < rawPayload.length; i++) {
            payload[i] = rawPayload[i] ^ maskBytes[i % 4];
          }
        }

        frameBuf = frameBuf.slice(offset + len);

        if (opcode === 0x8) { cleanup(); return; }
        if (opcode === 0x9) continue;
        try { torSocket.write(payload); } catch (e) {}
      }
    }
  };

  function sendWsFrame(data) {
    if (clientSocket.destroyed) return;
    const len = data.length;
    let hdr;
    if (len < 126) {
      hdr = Buffer.from([0x82, len]);
    } else {
      hdr = Buffer.alloc(4);
      hdr[0] = 0x82;
      hdr[1] = 126;
      hdr.writeUInt16BE(len, 2);
    }
    try { clientSocket.write(Buffer.concat([hdr, data])); } catch (e) {}
  }

  function cleanup() {
    clientSocket.removeListener("data", onFrameData);
    try { clientSocket.destroy(); } catch (e) {}
    try { torSocket?.end(); } catch (e) {}
  }

  clientSocket.on("data", onFrameData);
  clientSocket.on("error", cleanup);
  clientSocket.on("close", cleanup);
}

// ── Raw TCP server (no http.createServer — must intercept all protocols) ──
// Using net.createServer gives full control over every byte before any internal
// parser (C++ HTTP parser in http.Server) can consume it.  With net.Server,
// the socket is already flowing — no pause/resume needed.
function handleHttpRequest(socket, data) {
  const raw = data.toString();
  const reqLine = raw.split("\r\n")[0];

  // WebSocket upgrade (must check before GET/HEAD — both are GET /)
  if (raw.includes("Upgrade: websocket") || raw.includes("upgrade: websocket")) {
    handleWsFromRaw(socket, data);
    return;
  }

  // Health check
  if (reqLine.startsWith("GET ") || reqLine.startsWith("HEAD ")) {
    const body = JSON.stringify({
      status: "ok",
      tor: true,
      torPort: TOR_PORT,
      port: PORT,
    });
    socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n" + body);
    socket.end();
    return;
  }

  // Unknown — close
  socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad Request");
  socket.end();
}

const server = net.createServer((socket) => {
  socket.once("data", (data) => {
    if (data.length === 0) return;
    const firstByte = data[0];
    const str = data.toString();

    if (firstByte === 0x05) {
      // SOCKS5
      handleSocks5(socket, data);
    } else if (firstByte === 0x43) {
      // 'C' — HTTP CONNECT
      handleHttpConnect(socket, data);
    } else {
      // HTTP request or WebSocket upgrade
      handleHttpRequest(socket, data);
    }
  });
});

// ── Start Tor and launch server ──
async function main() {
  console.log(`[tor-proxy] Starting Tor proxy on 0.0.0.0:${PORT}`);

  // 1. Start Tor daemon
  const tor = spawn("tor", ["-f", "/app/torrc"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  tor.stdout.on("data", (d) => process.stdout.write(`[tor] ${d}`));
  tor.stderr.on("data", (d) => process.stderr.write(`[tor] ${d}`));
  tor.on("exit", (code) => {
    console.log(`[tor-proxy] Tor exited (code=${code}) — shutting down`);
    process.exit(1);
  });

  // 2. Wait for Tor SOCKS5 to be ready (up to 30s)
  console.log("[tor-proxy] Waiting for Tor SOCKS5 to bootstrap...");
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: TOR_HOST, port: TOR_PORT }, () => {
          s.write(Buffer.from([0x05, 0x01, 0x00]));
          s.once("data", (resp) => {
            if (resp.length >= 2 && resp[0] === 0x05 && resp[1] === 0x00) {
              s.end();
              resolve();
            } else {
              s.end();
              reject(new Error("bad resp"));
            }
          });
        });
        s.on("error", reject);
        s.setTimeout(3000, () => { s.destroy(); reject(new Error("timeout")); });
      });
      ready = true;
      console.log(`[tor-proxy] Tor ready after ${attempt + 1}s`);
      break;
    } catch (e) {
      if (attempt < 29) await new Promise((r) => setTimeout(r, 1000));
    }
  }

  if (!ready) {
    console.log("[tor-proxy] WARNING: Tor not ready after 30s — starting anyway");
  }

  // 3. Start proxy server
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[tor-proxy] Proxy ready on :${PORT}`);
    console.log(`[tor-proxy]   SOCKS5 / HTTP CONNECT / WS — all on same port`);
    console.log(`[tor-proxy]   Upstream: Tor SOCKS5 at ${TOR_HOST}:${TOR_PORT}`);
    if (!ready) {
      console.log("[tor-proxy]   ⚠ Tor still bootstrapping — connections will queue");
    }
  });
}

main().catch((err) => {
  console.error("[tor-proxy] Fatal:", err);
  process.exit(1);
});
