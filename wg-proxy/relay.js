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
let wireproxyRestartCount = 0;

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
    console.log(`[wg-proxy] wireproxy exited (code ${code}) for ${cfg.endpoint} -- restarting...`);
    setTimeout(() => {
      wireproxyRestartCount++;
      console.log(`[wg-proxy] Restarting wireproxy (attempt ${wireproxyRestartCount})...`);
      try {
        const cfg2 = WG_CONFIGS[currentConfigIdx % WG_CONFIGS.length];
        writeWireProxyConfig(cfg2);
        currentWireProxy = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
        currentWireProxy.on("exit", (code2) => {
          console.log(`[wg-proxy] Restarted wireproxy also exited (code ${code2})`);
        });
      } catch(e) { console.error('[wg-proxy] Restart failed:', e.message); }
    }, 3000);
  });
  return wp;
}

// Test if SOCKS5 tunnel is actually working via a real connect
async function testSocks5Working() {
  try {
    return await new Promise((resolve, reject) => {
      const s = net.createConnection({ host: SOCKS_HOST, port: SOCKS_PORT }, () => {
        s.write(Buffer.from([0x05, 0x01, 0x00]));
      });
      let state = 0, buf = Buffer.alloc(0);
      const timer = setTimeout(() => { s.destroy(); resolve(false); }, 10000);
      s.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        try {
          if (state === 0 && buf.length >= 2) {
            if (buf[1] !== 0x00) { clearTimeout(timer); s.destroy(); resolve(false); return; }
            state = 1;
            const testHost = "1.1.1.1";
            const testPort = 80;
            const hb = Buffer.from(testHost);
            s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(testPort >> 8) & 0xFF, testPort & 0xFF])]));
            buf = Buffer.alloc(0);
          } else if (state === 1 && buf.length >= 5) {
            clearTimeout(timer);
            if (buf[1] === 0x00) { s.end(); resolve(true); }
            else { s.destroy(); resolve(false); }
          }
        } catch(e) { clearTimeout(timer); s.destroy(); resolve(false); }
      });
      s.on("error", () => { clearTimeout(timer); resolve(false); });
    });
  } catch(e) { return false; }
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
      // SOCKS5 port is open — now verify the tunnel actually forwards traffic
      const tunnelOk = await testSocks5Working();
      if (tunnelOk) return true;
      // Tunnel not ready yet — keep waiting
    } catch (e) {
      // SOCKS5 port not open yet — keep waiting
    }
    await new Promise((r) => setTimeout(r, 1000));
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
    // Monitor wireproxy health every 60s — signal reconnect if tunnel drops
    setInterval(async () => {
      const ok = await testSocks5Working();
      if (!ok && currentWireProxy && currentWireProxy.exitCode === null) {
        console.log('[wg-proxy] SOCKS5 unresponsive — sending SIGUSR1 for reconnect');
        try { currentWireProxy.kill("SIGUSR1"); } catch (e) {}
      }
    }, 60000);
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
  const socksStart = Date.now();
  // Resolve DNS on relay side first to avoid WireGuard tunnel DNS failures
  const resolveHost = (host) => {
    return new Promise((res) => {
      // Check if already an IP address
      if (net.isIPv4(host) || net.isIPv6(host)) return res(host);
      dns.lookup(host, 4, (err, ip) => {
        if (err) {
          console.log(`[relay] DNS resolve FAILED for ${host}: ${err.code} — falling back to domain name`);
          return res(host);
        }
        console.log(`[relay] DNS resolved ${host} -> ${ip}`);
        return res(ip);
      });
    });
  };
  return resolveHost(targetHost).then((connectHost) => {
    return new Promise((resolve, reject) => {
      const s = net.createConnection({ host: SOCKS_HOST, port: SOCKS_PORT }, () => {
        console.log(`[relay] socks5 TCP connected to wireproxy (${SOCKS_HOST}:${SOCKS_PORT}) in ${Date.now() - socksStart}ms — sending auth`);
        s.write(Buffer.from([0x05, 0x01, 0x00]));
      });
      let state = 0, buf = Buffer.alloc(0);
      const timer = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 20000);
      const cleanup = () => { clearTimeout(timer); s.removeListener("data", onData); };
      const onData = (d) => {
        buf = Buffer.concat([buf, d]);
        try {
          if (state === 0 && buf.length >= 2) {
            if (buf[1] !== 0x00) { cleanup(); s.destroy(); reject(new Error("auth fail")); return; }
            console.log(`[relay] SOCKS5 auth OK for ${targetHost}:${targetPort} in ${Date.now() - socksStart}ms — sending connect`);
            state = 1;
            // Use IPv4 type (0x01) for resolved IPs, domain name type (0x03) as fallback
            let connectMsg;
            if (net.isIPv4(connectHost)) {
              const ipBytes = connectHost.split('.').map(Number);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x01]), Buffer.from(ipBytes), Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]);
            } else {
              const hb = Buffer.from(connectHost);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]);
            }
            s.write(connectMsg);
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
      s.setTimeout(20000, () => { s.destroy(); cleanup(); reject(new Error("timeout")); });
    });
  });
}

// ── HTTP + WebSocket server ──
const server = http.createServer((req, res) => {
  // Detailed SOCKS5 health check — tests actual tunnel connectivity
  if (req.url === "/health/socks5") {
    testSocks5Working().then((ok) => {
      res.writeHead(ok ? 200 : 503);
      res.end(JSON.stringify({ socks5: ok, mode: "wg-proxy" }));
    });
    return;
  }
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
  // Supports two modes:
  // 1. Legacy (single-connection): first msg is {host, port} (no type field)
  // 2. Multiplexed (multiple connections): connect/disconnect via {type, connId}
  //
  // Multiplexed binary frame format: [4-byte connId BE][payload]
  // Legacy binary format: raw data (no prefix)

  let isMultiplexed = false;
  let legacySocket = null; // Single SOCKS5 socket for legacy mode
  const connections = new Map(); // connId -> net.Socket (SOCKS5)

  ws.on("message", (data, isBinary) => {
    // ── Text frames (isBinary=false): JSON control messages ──
    if (!isBinary) {
      try {
        const msg = JSON.parse(data);

        // Detect mode on first message
        if (msg.type) isMultiplexed = true;

        // ── Legacy mode: {host, port} ──
        if (!msg.type && msg.host) {
          console.log(`[relay] Legacy connect request: ${msg.host}:${msg.port || 443}`);
          const startTime = Date.now();
          socks5Connect(msg.host, msg.port || 443)
            .then((ts) => {
              console.log(`[relay] Legacy connect SUCCEEDED for ${msg.host}:${msg.port || 443} in ${Date.now() - startTime}ms`);
              legacySocket = ts;
              ws.send(JSON.stringify({ status: "connected" }));
              ts.on("data", (td) => {
                try { if (ws.readyState === ws.OPEN) ws.send(td); } catch (e) {}
              });
              ts.on("error", () => { try { legacySocket?.end(); } catch(e) {} legacySocket = null; });
              ts.on("close", () => { legacySocket = null; });
            })
            .catch((err) => {
              console.error(`[relay] legacy socks5 FAILED for ${msg.host}:${msg.port || 443} after ${Date.now() - startTime}ms: "${err.message}"`);
              try { ws.send(JSON.stringify({ error: err.message })); } catch (e) {}
            });
          return;
        }

        // ── Multiplexed mode ──
        if (msg.type === 'connect' && msg.connId != null && msg.host) {
          const connId = msg.connId;
          console.log(`[relay] Mux connect request: connId=${connId} ${msg.host}:${msg.port || 443}`);
          const muxStart = Date.now();
          socks5Connect(msg.host, msg.port || 443)
            .then((socks) => {
              connections.set(connId, socks);
              ws.send(JSON.stringify({ type: "connected", connId }));

              socks.on("data", (socksData) => {
                try {
                  if (ws.readyState !== ws.OPEN) return;
                  const header = Buffer.alloc(4);
                  header.writeUInt32BE(connId);
                  ws.send(Buffer.concat([header, socksData]), { binary: true });
                } catch (e) { console.error('[relay] ws msg error:', e.message); }
              });
              socks.on("error", () => cleanupConn(connId));
              socks.on("close", () => cleanupConn(connId));
            })
            .catch((err) => {
              try { ws.send(JSON.stringify({ type: "error", connId, message: err.message })); } catch (e) {}
            });
        }

        if (msg.type === 'disconnect' && msg.connId != null) {
          cleanupConn(msg.connId);
        }
      } catch (e) { console.error('[relay] ws msg error:', e.message); }
    } else {
      // ── Binary frames ──
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

      if (isMultiplexed) {
        // Multiplexed: first 4 bytes = connId, rest = payload
        if (buf.length < 4) return;
        const connId = buf.readUInt32BE(0);
        const payload = buf.slice(4);
        const socks = connections.get(connId);
        if (socks) {
          try { socks.write(payload); } catch (e) {}
        }
      } else {
        // Legacy: raw data goes to the single SOCKS5 connection
        if (legacySocket) {
          try { legacySocket.write(buf); } catch (e) {}
        }
      }
    }
  });

  function cleanupConn(connId) {
    const socks = connections.get(connId);
    if (socks) {
      connections.delete(connId);
      try { socks.end(); } catch (e) {}
    }
  }

  function cleanupAll() {
    for (const [connId, socks] of connections) {
      try { socks.end(); } catch (e) {}
    }
    connections.clear();
    try { legacySocket?.end(); } catch (e) {}
    legacySocket = null;
  }

  ws.on("close", () => cleanupAll());
  ws.on("error", (e) => { console.error('[relay] ws error:', e.message); cleanupAll(); });
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
