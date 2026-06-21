#!/usr/bin/env node
const http = require("http");
const net = require("net");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const SOCKS_HOST = "127.0.0.1";
const SOCKS_PORT = 1080;

// ── WireGuard rotation config ──
// WG_CONFIGS (JSON array) takes precedence over WG_ENDPOINTS/WG_ENDPOINT
// Each config: {"privateKey":"...","peerPublicKey":"...","endpoint":"ip:port"}
// Example WG_CONFIGS:
// [{"privateKey":"key1","peerPublicKey":"peer1","endpoint":"ip1:51820"},
//  {"privateKey":"key2","peerPublicKey":"peer2","endpoint":"ip2:51820"}]
const ROTATION_INTERVAL_MS = parseInt(process.env.WG_ROTATION_INTERVAL || "1800000"); // default 30 min

// Parse WG_CONFIGS or fall back to single key + endpoints
let WG_CONFIGS = [];
const userConfigs = process.env.WG_CONFIGS;
if (userConfigs) {
  try {
    WG_CONFIGS = JSON.parse(userConfigs);
    if (!Array.isArray(WG_CONFIGS) || WG_CONFIGS.length === 0) {
      console.error("[wg-proxy] WG_CONFIGS is not a non-empty array, falling back to env vars");
      WG_CONFIGS = [];
    }
  } catch (e) {
    console.error("[wg-proxy] Failed to parse WG_CONFIGS JSON:", e.message);
    WG_CONFIGS = [];
  }
}

// Fallback: build configs from WG_ENDPOINTS/WG_ENDPOINT + single key pair
if (WG_CONFIGS.length === 0) {
  const privateKey = process.env.WG_PRIVATE_KEY || "wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=";
  const peerPublicKey = process.env.WG_PEER_PUBLIC_KEY || "Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=";
  const endpointsRaw = process.env.WG_ENDPOINTS || process.env.WG_ENDPOINT || "146.70.202.34:51820";
  const endpoints = endpointsRaw.split(/[,;]/).map(s => s.trim()).filter(Boolean);
  WG_CONFIGS = endpoints.map(ep => ({ privateKey, peerPublicKey, endpoint: ep }));
}

let currentWireProxy = null;
let currentConfigIdx = 0;
let rotationTimer = null;

function pickConfig() {
  if (WG_CONFIGS.length <= 1) return WG_CONFIGS[0];
  currentConfigIdx = (currentConfigIdx + 1) % WG_CONFIGS.length;
  return WG_CONFIGS[currentConfigIdx];
}

function getCurrentEndpoint() {
  if (WG_CONFIGS.length === 0) return "none";
  const idx = currentConfigIdx % WG_CONFIGS.length;
  return WG_CONFIGS[idx].endpoint;
}

function writeWireProxyConfig(cfg) {
  const fs = require("fs");
  const config = `[Interface]
PrivateKey = ${cfg.privateKey}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ${cfg.peerPublicKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${cfg.endpoint}
PersistentKeepalive = 25

[Socks5]
BindAddress = 0.0.0.0:1080
`;
  fs.writeFileSync("/etc/wireproxy.conf", config);
}

function startWireProxy(cfg) {
  writeWireProxyConfig(cfg);
  console.log(`[wg-proxy] Starting WireGuard → ${cfg.endpoint}`);
  const wp = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
  wp.on("exit", (code) => {
    console.log(`[wg-proxy] wireproxy exited (code ${code}) for ${cfg.endpoint}`);
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

async function rotateConfig() {
  if (WG_CONFIGS.length <= 1) return;
  
  const newCfg = pickConfig();
  console.log(`[wg-proxy] Rotating → ${newCfg.endpoint}`);
  
  if (currentWireProxy) {
    currentWireProxy.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 2000));
    if (currentWireProxy && !currentWireProxy.killed) {
      currentWireProxy.kill("SIGKILL");
    }
  }
  
  currentWireProxy = startWireProxy(newCfg);
  const ready = await waitForSocks5(30000);
  if (ready) {
    console.log(`[wg-proxy] Rotation complete → ${newCfg.endpoint} (SOCKS5 ready)`);
  } else {
    console.error(`[wg-proxy] Rotation failed — SOCKS5 not ready for ${newCfg.endpoint}`);
  }
}

async function startRotationLoop() {
  if (WG_CONFIGS.length <= 1) {
    console.log(`[wg-proxy] Single config (no rotation): ${WG_CONFIGS[0]?.endpoint}`);
    return;
  }
  console.log(`[wg-proxy] IP rotation enabled: ${WG_CONFIGS.length} config(s)`);
  WG_CONFIGS.forEach((c, i) => console.log(`  ${i}: ${c.endpoint}`));
  console.log(`[wg-proxy] Rotation interval: ${ROTATION_INTERVAL_MS / 1000}s`);
  
  const rotate = async () => {
    await rotateConfig();
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
    configs: WG_CONFIGS.length,
    currentEndpoint: getCurrentEndpoint()
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
  if (WG_CONFIGS.length === 0) {
    console.error("[wg-proxy] No WireGuard configs available");
    process.exit(1);
  }
  
  const initialCfg = WG_CONFIGS[0];
  console.log(`[wg-proxy] Starting WireGuard with ${WG_CONFIGS.length} config(s)...`);
  
  currentWireProxy = startWireProxy(initialCfg);
  console.log("[wg-proxy] Waiting for SOCKS5...");
  const ready = await waitForSocks5(45000);
  if (!ready) {
    console.error("[wg-proxy] SOCKS5 failed to start");
    process.exit(1);
  }
  console.log(`[wg-proxy] WireGuard ready (endpoint: ${initialCfg.endpoint})`);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[wg-proxy] Proxy ready on :${PORT}`);
    console.log(`[wg-proxy]   WebSocket relay → WireGuard SOCKS5 :${SOCKS_PORT}`);
  });

  startRotationLoop();
}

main().catch((err) => { console.error("[wg-proxy] Fatal:", err); process.exit(1); });
