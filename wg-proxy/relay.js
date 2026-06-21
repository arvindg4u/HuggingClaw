#!/usr/bin/env node
const http = require("http");
const net = require("net");
const dns = require("dns");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const SOCKS_HOST = "127.0.0.1";
const SOCKS_PORT = 1080;

// ── WireGuard rotation config ──
const WG_PRIVATE_KEY = process.env.WG_PRIVATE_KEY || "wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=";
const WG_PEER_PUBLIC_KEY = process.env.WG_PEER_PUBLIC_KEY || "Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=";
const ROTATION_INTERVAL_MS = parseInt(process.env.WG_ROTATION_INTERVAL || "1800000"); // default 30 min

// Parse endpoints: WG_ENDPOINTS takes precedence over WG_ENDPOINT
// Format: comma-separated "ip:port" or semicolon-separated (for IPv6)
let WG_ENDPOINTS = [];
const endpointsRaw = process.env.WG_ENDPOINTS || process.env.WG_ENDPOINT || "146.70.202.34:51820";
// Support both comma and semicolon separation for IPv6 compatibility
WG_ENDPOINTS = endpointsRaw.split(/[,;]/).map(s => s.trim()).filter(Boolean);

let currentWireProxy = null;
let currentEndpointIdx = 0;
let rotationTimer = null;

function pickEndpoint() {
  if (WG_ENDPOINTS.length <= 1) return WG_ENDPOINTS[0] || "146.70.202.34:51820";
  // Pick next endpoint in rotation
  currentEndpointIdx = (currentEndpointIdx + 1) % WG_ENDPOINTS.length;
  return WG_ENDPOINTS[currentEndpointIdx];
}

function startWireProxy(endpoint) {
  const fs = require("fs");
  const config = `[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ${WG_PEER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}
PersistentKeepalive = 25

[Socks5]
BindAddress = 0.0.0.0:1080
`;
  fs.writeFileSync("/etc/wireproxy.conf", config);
  console.log(`[wg-proxy] Starting WireGuard → ${endpoint}`);
  const wp = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
  wp.on("exit", (code) => {
    console.log(`[wg-proxy] wireproxy exited (code ${code}) for endpoint ${endpoint}`);
  });
  return wp;
}

async function waitForSocks5(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: SOCKS_HOST, port: SOCKS_PORT }, () => {
          s.write(Buffer.from([0x05, 0x01, 0x00]));
          s.once("data", (d) => {
            if (d.length >= 2 && d[0] === 0x05 && d[1] === 0x00) { s.end(); resolve(); }
            else { s.end(); reject(); }
          });
        });
        s.on("error", reject);
        s.setTimeout(3000, () => { s.destroy(); reject(new Error("timeout")); });
      });
      return true;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  return false;
}

async function rotateEndpoint() {
  if (WG_ENDPOINTS.length <= 1) return; // no rotation needed
  
  const newEndpoint = pickEndpoint();
  console.log(`[wg-proxy] Rotating endpoint → ${newEndpoint}`);
  
  // Kill old wireproxy
  if (currentWireProxy) {
    currentWireProxy.kill("SIGTERM");
    // Give it a moment to release the SOCKS5 port
    await new Promise((r) => setTimeout(r, 2000));
    if (currentWireProxy && !currentWireProxy.killed) {
      currentWireProxy.kill("SIGKILL");
    }
  }
  
  // Start new wireproxy with new endpoint
  currentWireProxy = startWireProxy(newEndpoint);
  
  // Wait for SOCKS5 to be ready
  const ready = await waitForSocks5(30000);
  if (ready) {
    console.log(`[wg-proxy] Rotation complete → ${newEndpoint} (SOCKS5 ready)`);
  } else {
    console.error(`[wg-proxy] Rotation failed — SOCKS5 not ready for ${newEndpoint}`);
  }
}

async function startRotationLoop() {
  if (WG_ENDPOINTS.length <= 1) {
    console.log(`[wg-proxy] Single endpoint (no rotation): ${WG_ENDPOINTS[0]}`);
    return;
  }
  console.log(`[wg-proxy] IP rotation enabled: ${WG_ENDPOINTS.join(", ")}`);
  console.log(`[wg-proxy] Rotation interval: ${ROTATION_INTERVAL_MS / 1000}s`);
  
  const rotate = async () => {
    await rotateEndpoint();
    rotationTimer = setTimeout(rotate, ROTATION_INTERVAL_MS);
  };
  rotationTimer = setTimeout(rotate, ROTATION_INTERVAL_MS);
}

// ── SOCKS5 through WireGuard ──
function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host: SOCKS_HOST, port: SOCKS_PORT }, () => {
      s.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state = 0, buf = Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 30000);
    const cleanup = () => { clearTimeout(timer); s.removeListener("data", onData); };
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      try {
        if (state === 0 && buf.length >= 2) {
          if (buf[1] !== 0x00) { cleanup(); s.destroy(); reject(new Error("auth fail")); return; }
          state = 1;
          const hb = Buffer.from(targetHost);
          s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]));
          buf = Buffer.alloc(0);
        } else if (state === 1 && buf.length >= 4) {
          cleanup();
          if (buf[1] !== 0x00) { s.destroy(); reject(new Error("reject:" + buf[1])); return; }
          resolve(s);
        }
      } catch (e) { cleanup(); reject(e); }
    };
    s.on("data", onData);
    s.on("error", (e) => { cleanup(); reject(e); });
    s.setTimeout(30000, () => { s.destroy(); cleanup(); reject(new Error("timeout")); });
  });
}

// ── HTTP + WebSocket server ──
const server = http.createServer((req, res) => {
  const health = {
    status: "ok",
    mode: "wg-proxy",
    socks5: `:${SOCKS_PORT}`,
    endpoints: WG_ENDPOINTS.length,
    currentEndpoint: WG_ENDPOINTS[currentEndpointIdx % WG_ENDPOINTS.length] || "unknown"
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(health));
});

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  let expectingConfig = true;
  let torSocket = null;

  ws.on("message", (data) => {
    if (expectingConfig) {
      try {
        const cfg = JSON.parse(data.toString());
        socks5Connect(cfg.host || "opencode.ai", cfg.port || 443)
          .then((ts) => {
            torSocket = ts;
            expectingConfig = false;
            ws.send(JSON.stringify({ status: "connected" }));
            ts.on("data", (td) => { try { if (ws.readyState === ws.OPEN) ws.send(td); } catch (e) {} });
            ts.on("error", cleanup);
            ts.on("close", cleanup);
          })
          .catch((err) => { try { ws.send(JSON.stringify({ error: err.message })); } catch (e) {} cleanup(); });
      } catch (e) { cleanup(); }
    } else if (torSocket) {
      try { torSocket.write(typeof data === "string" ? Buffer.from(data) : data); } catch (e) {}
    }
  });

  ws.on("close", () => cleanup());
  ws.on("error", () => cleanup());
  function cleanup() { try { ws.close(); } catch (e) {} try { torSocket?.end(); } catch (e) {} }
});

server.on("upgrade", (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
});

// HTTP CONNECT (fallback when WS relay fails)
server.on("connect", (req, socket, head) => {
  const [host, portStr] = req.url.split(":");
  const port = parseInt(portStr) || 443;
  socks5Connect(host, port)
    .then((ts) => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      ts.pipe(socket);
      socket.pipe(ts);
    })
    .catch(() => {
      socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      socket.end();
    });
});

// ── Start ──
async function main() {
  // Pick initial endpoint
  const initialEndpoint = WG_ENDPOINTS[0];
  console.log(`[wg-proxy] Starting WireGuard with ${WG_ENDPOINTS.length} endpoint(s)...`);
  
  currentWireProxy = startWireProxy(initialEndpoint);

  // Wait for SOCKS5
  console.log("[wg-proxy] Waiting for SOCKS5...");
  const ready = await waitForSocks5(45000);
  if (!ready) {
    console.error("[wg-proxy] SOCKS5 failed to start");
    process.exit(1);
  }
  console.log(`[wg-proxy] WireGuard ready (endpoint: ${initialEndpoint})`);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[wg-proxy] Proxy ready on :${PORT}`);
    console.log(`[wg-proxy]   WebSocket relay → WireGuard SOCKS5 :${SOCKS_PORT}`);
  });

  // Start IP rotation
  startRotationLoop();
}

main().catch((err) => { console.error("[wg-proxy] Fatal:", err); process.exit(1); });
