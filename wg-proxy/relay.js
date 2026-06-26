#!/usr/bin/env node
const http = require("http");
const net = require("net");
const dns = require("dns");

// Shared DNS resolver: resolves hostname on the relay side to bypass
// WireGuard tunnel's internal DNS (10.2.0.1) which is unreliable.
// Returns the resolved IP (string) or the original hostname on failure/timeout.
function resolveHostname(targetHost) {
  if (net.isIPv4(targetHost) || net.isIPv6(targetHost)) return Promise.resolve(targetHost);
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      console.log(`[relay] DNS resolve TIMEOUT for ${targetHost} — using hostname directly`);
      resolve(targetHost);
    }, 5000);
    dns.resolve4(targetHost, (err, addresses) => {
      clearTimeout(t);
      if (err || !addresses || addresses.length === 0) {
        console.log(`[relay] DNS resolve FAILED for ${targetHost} — using hostname`);
        resolve(targetHost);
      } else {
        console.log(`[relay] DNS resolved ${targetHost} -> ${addresses[0]}`);
        resolve(addresses[0]);
      }
    });
  });
}

const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const SOCKS_HOST = "127.0.0.1";

// Dynamic SOCKS port for graceful dual-port IP rotation
let CURRENT_SOCKS_PORT = parseInt(process.env.WG_SOCKS_PORT || "1080");
const activeConnections = new Set(); // tracked by socks5Connect() for drain

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

// Optionally fetch configs from a URL (overrides WG_CONFIGS if successful)
async function fetchConfigsFromUrl() {
  if (!WG_CONFIGS_URL) return null;
  try {
    const { get } = require("http");
    const { get: getTls } = require("https");
    const fetcher = WG_CONFIGS_URL.startsWith("https") ? getTls : get;
    return await new Promise((resolve) => {
      fetcher(WG_CONFIGS_URL, (res) => {
        if (res.statusCode !== 200) { resolve(null); return; }
        let body = "";
        res.on("data", (c) => body += c);
        res.on("end", () => {
          try {
            const arr = JSON.parse(body);
            resolve(Array.isArray(arr) && arr.length > 0 ? arr : null);
          } catch (e) { resolve(null); }
        });
      }).on("error", () => resolve(null));
    });
  } catch (e) { return null; }
}

// Merge fresh configs into WG_CONFIGS, updating deadEndpoints
function mergeConfigs(fresh) {
  if (!fresh || fresh.length === 0) return false;
  const oldLen = WG_CONFIGS.length;
  const newEndpoints = new Set(fresh.map(c => c.endpoint));
  for (const ep of deadEndpoints.keys()) {
    if (!newEndpoints.has(ep)) deadEndpoints.delete(ep);
  }
  for (const cfg of fresh) {
    if (!WG_CONFIGS.some(c => c.endpoint === cfg.endpoint)) {
      deadEndpoints.delete(cfg.endpoint);
    }
  }
  WG_CONFIGS = fresh;
  console.log(`[wg-proxy] Configs refreshed: ${oldLen} → ${WG_CONFIGS.length} endpoint(s)`);
  return true;
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
let shuttingDown = false;
let isRotating = false; // prevents concurrent rotations

// Track endpoints that failed SOCKS5 verification (endpoint -> {failures, timestamp})
const deadEndpoints = new Map();
const DEAD_ENDPOINT_RETRY_MS = parseInt(process.env.WG_DEAD_RETRY || "300000"); // 5 min

// WireGuard tunnel MTU (env: WG_MTU, default 1384 — safe for Ethernet + WG overhead)
const WG_MTU = parseInt(process.env.WG_MTU || "1300");

// Health check targets (comma-separated host:port pairs, tried in sequence)
const HEALTH_CHECK_TARGETS = (process.env.HEALTH_CHECK_TARGETS || "1.1.1.1:80,8.8.8.8:80,opencode.ai:443,httpbin.org:80")
  .split(",")
  .map(s => { const [h, p] = s.trim().split(":"); return { host: h, port: parseInt(p) || 80 }; })
  .filter(t => t.host);

// Max multiplexed SOCKS5 streams per WebSocket client (env: MAX_CONN_PER_CLIENT)
const MAX_CONNECTIONS_PER_CLIENT = parseInt(process.env.MAX_CONN_PER_CLIENT || "256");

// Optional URL to fetch fresh WG_CONFIGS JSON (refreshed periodically)
const WG_CONFIGS_URL = process.env.WG_CONFIGS_URL || "";
const WG_CONFIGS_REFRESH_MS = parseInt(process.env.WG_CONFIGS_REFRESH || "1800000"); // 30 min
function pickConfig() {
  if (WG_CONFIGS.length <= 1) return WG_CONFIGS[0];
  // Try up to WG_CONFIGS.length times to find a live endpoint
  for (let attempt = 0; attempt < WG_CONFIGS.length; attempt++) {
    currentConfigIdx = (currentConfigIdx + 1) % WG_CONFIGS.length;
    const cfg = WG_CONFIGS[currentConfigIdx];
    if (!deadEndpoints.has(cfg.endpoint)) return cfg;
  }
  // All endpoints are dead — use the next one (oldest dead entry)
  currentConfigIdx = (currentConfigIdx + 1) % WG_CONFIGS.length;
  const fallback = WG_CONFIGS[currentConfigIdx];
  console.log(`[wg-proxy] All endpoints dead — falling back to ${fallback.endpoint}`);
  return fallback;
}

function getCurrentEndpoint() {
  if (WG_CONFIGS.length === 0) return "none";
  const idx = currentConfigIdx % WG_CONFIGS.length;
  return WG_CONFIGS[idx].endpoint;
}

function writeWireProxyConfig(cfg, port) {
  const fs = require("fs");
  const config = `[Interface]
PrivateKey = ${cfg.privateKey}
Address = 10.2.0.2/32
DNS = 10.2.0.1
MTU = ${WG_MTU}

[Peer]
PublicKey = ${cfg.peerPublicKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${cfg.endpoint}
PersistentKeepalive = 25

[Socks5]
BindAddress = 0.0.0.0:${port}
`;
  fs.writeFileSync("/etc/wireproxy.conf", config);
}

function startWireProxy(cfg, port) {
  writeWireProxyConfig(cfg, port);
  console.log(`[wg-proxy] Starting WireGuard -> ${cfg.endpoint} on SOCKS5 :${port}`);
  const wp = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
  wp.on("exit", async (code, signal) => {
    if (shuttingDown) return;
    // If this wireproxy was deliberately killed (rotation, shutdown), don't restart
    if (wp.wasKilled) return;
    const sig = signal ? ` (signal=${signal})` : '';
    console.log(`[wg-proxy] wireproxy exited (code=${code}${sig}) for ${cfg.endpoint} -- restarting...`);
    await new Promise(r => setTimeout(r, 2000));
    wireproxyRestartCount++;
    console.log(`[wg-proxy] Restarting wireproxy (attempt ${wireproxyRestartCount})...`);
    try {
      for (let i = 0; i < 15; i++) {
        const free = await new Promise(res => {
          const s = require("net").createConnection({host:"127.0.0.1",port:CURRENT_SOCKS_PORT});
          s.on("connect", () => { s.destroy(); res(false); });
          s.on("error", () => res(true));
        });
        if (free) break;
        await new Promise(r => setTimeout(r, 500));
      }
      const cfg2 = WG_CONFIGS[currentConfigIdx % WG_CONFIGS.length];
      writeWireProxyConfig(cfg2, CURRENT_SOCKS_PORT);
      currentWireProxy = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
      currentWireProxy.on("exit", (code2, sig2) => {
        const s2 = sig2 ? ` (signal=${sig2})` : '';
        console.log(`[wg-proxy] Restarted wireproxy also exited (code=${code2}${s2})`);
      });
    } catch(e) { console.error("[wg-proxy] Restart failed:", e.message); }
  });
  return wp;
}

// Test if SOCKS5 tunnel is actually working via a real connect
// Tries each HEALTH_CHECK_TARGETS entry in sequence, returns true if any succeeds.

// Lightweight SOCKS5 health check — just verifies the SOCKS5 port is open
// and responds to auth. Does NOT test tunnel forwarding (which Proton VPN
// blocks for many targets). Returns true if the SOCKS5 server is accepting
// connections and responds to auth negotiation.
function testSocks5Auth(port) {
  const targetPort = port || CURRENT_SOCKS_PORT;
  return new Promise((resolve) => {
    const s = net.createConnection({ host: SOCKS_HOST, port: targetPort }, () => {
      s.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    const timer = setTimeout(() => { s.destroy(); resolve(false); }, 3000);
    s.once("data", (d) => {
      clearTimeout(timer);
      if (d.length >= 2 && d[0] === 0x05 && d[1] === 0x00) { s.end(); resolve(true); }
      else { s.destroy(); resolve(false); }
    });
    s.on("error", () => { clearTimeout(timer); resolve(false); });
  });
}
async function testSocks5Working() {
  for (const target of HEALTH_CHECK_TARGETS) {
    try {
      const ok = await testConnect(target.host, target.port);
      if (ok) return true;
    } catch (e) {
      // continue to next target
    }
  }
  return false;
}

// Single SOCKS5 connect attempt to a specific host:port
function testConnect(host, port) {
  return resolveHostname(host).then((useHost) => {
    return new Promise((resolve) => {
      const s = net.createConnection({ host: SOCKS_HOST, port: CURRENT_SOCKS_PORT }, () => {
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
            let connectMsg;
            if (net.isIPv4(useHost)) {
              const ipBytes = useHost.split(".").map(Number);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x01]), Buffer.from(ipBytes), Buffer.from([(port >> 8) & 0xFF, port & 0xFF])]);
            } else {
              const hb = Buffer.from(useHost);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(port >> 8) & 0xFF, port & 0xFF])]);
            }
            s.write(connectMsg);
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
  });
}

async function waitForSocks5(timeoutMs = 30000, portOverride) {
  const port = portOverride || CURRENT_SOCKS_PORT;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: SOCKS_HOST, port }, () => {
          s.write(Buffer.from([0x05, 0x01, 0x00]));
          s.once("data", (d) => {
            if (d.length >= 2 && d[0] === 0x05 && d[1] === 0x00) { s.end(); resolve(); }
            else { s.end(); reject(); }
          });
        });
        s.on("error", reject);
        s.setTimeout(3000, () => { s.destroy(); reject(new Error("timeout")); });
      });
      // SOCKS5 port is open — tunnel is ready
      // (Don't require full tunnel forwarding — Proton VPN blocks many targets
      //  even when the tunnel is working. Just SOCKS5 auth success is enough.)
      return true;
    } catch (e) {
      // SOCKS5 port not open yet — keep waiting
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function killAllWireProxy() {
  // Kill wireproxy on both ports using lsof (more precise than pkill by name)
  // This avoids killing unrelated processes that happen to include "wireproxy"
  try {
    require("child_process").execSync("kill -9 $(lsof -ti:1080 2>/dev/null) 2>/dev/null; kill -9 $(lsof -ti:1081 2>/dev/null) 2>/dev/null", { stdio: "ignore" });
  } catch (e) { /* best effort */ }
}

async function waitForPortRelease(host, port, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const s = require("net").createConnection({ host, port }, () => {
          s.destroy();
          reject(new Error("port still in use"));
        });
        s.on("error", () => resolve(true));
        setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 2000);
      });
      return true;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  return false;
}

async function rotateConfig() {
  if (WG_CONFIGS.length <= 1) return;
  if (isRotating) { console.log('[wg-proxy] Rotation already in progress -- skipping'); return; }
  isRotating = true;

  const newCfg = pickConfig();
  const port = CURRENT_SOCKS_PORT;
  const fs = require("fs");

  console.log(`[wg-proxy] Rotating to ${newCfg.endpoint} (same port :${port})`);

  // 1. Kill the old wireproxy FIRST to avoid TUN address conflicts
  //    (all Proton VPN configs share the same 10.2.0.2/32 address)
  if (currentWireProxy) {
    console.log(`[wg-proxy] Killing current wireproxy on :${port}`);
    currentWireProxy.wasKilled = true;
    try {
      currentWireProxy.kill("SIGTERM");
      await new Promise((r) => setTimeout(r, 1500));
      if (!currentWireProxy.killed) currentWireProxy.kill("SIGKILL");
    } catch (e) {}
    // Force-kill any leftover holding the port
    try {
      require("child_process").execSync(
        `kill -9 $(lsof -ti:${port} 2>/dev/null) 2>/dev/null`,
        { stdio: "ignore" }
      );
    } catch (e) {}
    // Wait for port to be released
    await waitForPortRelease(SOCKS_HOST, port, 5000);
  }

  // 2. Write config and start new wireproxy on the SAME port
  writeWireProxyConfig(newCfg, port);
  console.log(`[wg-proxy] Starting wireproxy on :${port} -> ${newCfg.endpoint}`);
  const newProxy = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });

  newProxy.on("exit", (code, signal) => {
    if (newProxy.wasKilled || shuttingDown) return;
    const sig = signal ? ` (signal=${signal})` : '';
    console.log(`[wg-proxy] wireproxy (port ${port}) exited (code=${code}${sig}) -- restarting in 2s...`);
    setTimeout(() => {
      if (shuttingDown) return;
      const cfgRestart = WG_CONFIGS[currentConfigIdx % WG_CONFIGS.length];
      writeWireProxyConfig(cfgRestart, port);
      const newWp = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
      newWp.on("exit", (c2, s2) => {
        const sig2 = s2 ? ` (signal=${s2})` : '';
        console.log(`[wg-proxy] Restarted wireproxy on :${port} exited (code=${c2}${sig2})`);
      });
      if (currentWireProxy === newProxy || !currentWireProxy) {
        currentWireProxy = newWp;
      }
    }, 2000);
  });

  currentWireProxy = newProxy;

  // 3. Wait for SOCKS5 to be ready
  const ready = await waitForSocks5(30000);
  if (!ready) {
    isRotating = false;
    console.error(`[wg-proxy] Rotation failed -- SOCKS5 not ready on :${port} for ${newCfg.endpoint}`);
    deadEndpoints.set(newCfg.endpoint, Date.now());
    console.log(`[wg-proxy] Marked ${newCfg.endpoint} as dead (${deadEndpoints.size} dead endpoint(s))`);
    newProxy.wasKilled = true;
    try { newProxy.kill("SIGTERM"); } catch (e) {}
    return;
  }

  isRotating = false;
  console.log(`[wg-proxy] Rotation complete -> ${newCfg.endpoint} (SOCKS5 :${port})`);
}

async function startRotationLoop() {
  if (WG_CONFIGS.length <= 1) {
    console.log(`[wg-proxy] Single config (no rotation): ${WG_CONFIGS[0]?.endpoint}`);
    // Monitor wireproxy health every 60s — signal reconnect if tunnel drops
    setInterval(async () => {
      const ok = await testSocks5Auth();
      if (!ok && currentWireProxy && currentWireProxy.exitCode === null) {
        console.log('[wg-proxy] SOCKS5 unresponsive — sending SIGUSR1 for reconnect');
        try { currentWireProxy.kill("SIGUSR1"); } catch (e) {}
      }
    }, 60000);
    return;
  }
  // Clean up expired dead-endpoint entries every 60s
  setInterval(() => {
    const now = Date.now();
    for (const [ep, ts] of deadEndpoints) {
      if (now - ts >= DEAD_ENDPOINT_RETRY_MS) {
        deadEndpoints.delete(ep);
        console.log(`[wg-proxy] Endpoint ${ep} removed from dead list (cooldown expired)`);
      }
    }
  }, 60000);

  // Monitor active tunnel health every 30s — check SOCKS5 port status
  // Note: We explicitly do NOT trigger rotation on forwarding failure because
  // Proton VPN free tier frequently blocks external targets even when the
  // tunnel itself is operational. Only rotate on actual SOCKS5 port failure.
  setInterval(async () => {
    const socksOk = await testSocks5Auth();
    if (!socksOk && !shuttingDown) {
      if (isRotating) { console.log('[wg-proxy] SOCKS5 port dead — rotation in progress'); return; }
      console.log(`[wg-proxy] SOCKS5 port unresponsive — triggering early rotation`);
      if (rotationTimer) clearTimeout(rotationTimer);
      await rotateConfig();
      rotationTimer = setTimeout(rotate, ROTATION_INTERVAL_MS);
    }
  }, 30000);

  console.log(`[wg-proxy] IP rotation enabled: ${WG_CONFIGS.length} config(s)`);
  WG_CONFIGS.forEach((c, i) => console.log(`  ${i}: ${c.endpoint}`));
  console.log(`[wg-proxy] Rotation interval: ${ROTATION_INTERVAL_MS / 1000}s`);
  
  const rotate = async () => {
    await rotateConfig();
    rotationTimer = setTimeout(rotate, ROTATION_INTERVAL_MS);
  };
  rotationTimer = setTimeout(rotate, ROTATION_INTERVAL_MS);
}

// If WG_CONFIGS_URL is set, try to fetch fresh configs on startup (replaces WG_CONFIGS)
if (WG_CONFIGS_URL) {
  fetchConfigsFromUrl().then((fresh) => {
    if (fresh) {
      mergeConfigs(fresh);
      console.log(`[wg-proxy] Startup configs fetched from ${WG_CONFIGS_URL}`);
    } else {
      console.warn(`[wg-proxy] Failed to fetch configs from ${WG_CONFIGS_URL} — using ${WG_CONFIGS.length} static config(s)`);
    }
  });
}

// Periodic config refresh from URL
if (WG_CONFIGS_URL && WG_CONFIGS_REFRESH_MS > 0) {
  setInterval(async () => {
    const fresh = await fetchConfigsFromUrl();
    if (fresh) {
      mergeConfigs(fresh);
      console.log(`[wg-proxy] Configs refreshed from ${WG_CONFIGS_URL}`);
    }
  }, WG_CONFIGS_REFRESH_MS);
}


// ── SOCKS5 through WireGuard ──
function socks5Connect(targetHost, targetPort) {
  const socksStart = Date.now();

  // Resolve hostname on relay side (bypasses Proton VPN's broken tunnel DNS)
  return resolveHostname(targetHost).then((useHost) => {
    return new Promise((resolve, reject) => {
      const s = net.createConnection({ host: SOCKS_HOST, port: CURRENT_SOCKS_PORT }, () => {
        s.setNoDelay(true);
        console.log(`[relay] socks5 TCP connected to wireproxy (${SOCKS_HOST}:${CURRENT_SOCKS_PORT}) in ${Date.now() - socksStart}ms — sending auth`);
        s.write(Buffer.from([0x05, 0x01, 0x00]));
      });
      let state = 0, buf = Buffer.alloc(0);
      const timer = setTimeout(() => { s.destroy(); reject(new Error("socks5 timeout")); }, 20000);
      const cleanup = () => { clearTimeout(timer); s.removeListener("data", onData); };
      const onData = (d) => {
        buf = Buffer.concat([buf, d]);
        try {
          if (state === 0 && buf.length >= 2) {
            if (buf[1] !== 0x00) { cleanup(); s.destroy(); reject(new Error("socks5 auth fail")); return; }
            console.log(`[relay] SOCKS5 auth OK for ${useHost}:${targetPort} in ${Date.now() - socksStart}ms — sending connect`);
            state = 1;
            // Use IPv4 type (0x01) for IP addresses, domain name type (0x03) for hostnames
            let connectMsg;
            if (net.isIPv4(useHost)) {
              const ipBytes = useHost.split(".").map(Number);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x01]), Buffer.from(ipBytes), Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]);
            } else {
              const hb = Buffer.from(useHost);
              connectMsg = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([(targetPort >> 8) & 0xFF, targetPort & 0xFF])]);
            }
            s.write(connectMsg);
            buf = Buffer.alloc(0);
          } else if (state === 1 && buf.length >= 4) {
            cleanup();
            if (buf[1] !== 0x00) { s.destroy(); reject(new Error("socks5 reject:" + buf[1])); return; }
            activeConnections.add(s);
            s.on("close", () => { activeConnections.delete(s); });
            resolve(s);
          }
        } catch (e) { cleanup(); reject(e); }
      };
      s.on("data", onData);
      s.on("error", (e) => { cleanup(); reject(e); });
      s.setTimeout(20000, () => { s.destroy(); cleanup(); reject(new Error("socks5 timeout")); });
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
    socks5: `:${CURRENT_SOCKS_PORT}`,
    configs: WG_CONFIGS.length,
    currentEndpoint: getCurrentEndpoint()
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(health));
});

// WS ping/pong keepalive prevents Cloudflare, Render, and NAT gateways
// from silently dropping idle WebSocket connections (typical timeout: 60-120s).
// During LLM streaming, token bursts are separated by idle gaps (model thinking,
// tool calls) that can trigger proxy timeouts. 25s ping / 10s pong keeps the
// connection alive through these gaps.
const WS_PING_INTERVAL = parseInt(process.env.WS_PING_INTERVAL || "25000");
const WS_PONG_TIMEOUT = parseInt(process.env.WS_PONG_TIMEOUT || "10000");
const wss = new WebSocketServer({ noServer: true, pingInterval: WS_PING_INTERVAL, pingTimeout: WS_PONG_TIMEOUT });

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
  // Tracks SOCKS5 sockets whose write() returned false (buffer full)
  const blockedSocks = new Set();

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
                try {
                  if (ws.readyState !== ws.OPEN) return;
                  ws.send(td, { binary: true });
                  // Backpressure: check WebSocket send buffer, pause SOCKS5 socket if full
                  if (ws.bufferedAmount > 64 * 1024) {
                    ts.pause();
                    ws.once('drain', () => { if (!ts.destroyed) ts.resume(); });
                  }
                } catch (e) {}
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
          // Enforce per-client connection limit to prevent fd exhaustion
          if (connections.size >= MAX_CONNECTIONS_PER_CLIENT) {
            console.log(`[relay] Mux connect REJECTED — ${msg.host}:${msg.port || 443} (connId=${connId}): at limit (${MAX_CONNECTIONS_PER_CLIENT})`);
            try { ws.send(JSON.stringify({ type: "error", connId, message: "connection limit reached" })); } catch (e) {}
            return;
          }
          console.log(`[relay] Mux connect request: connId=${connId} ${msg.host}:${msg.port || 443} (${connections.size}/${MAX_CONNECTIONS_PER_CLIENT})`);
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
                  // Backpressure: check WebSocket send buffer, pause SOCKS5 socket if full
                  if (ws.bufferedAmount > 64 * 1024) {
                    socks.pause();
                    ws.once('drain', () => { if (!socks.destroyed) socks.resume(); });
                  }
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
          try {
            if (!socks.write(payload)) {
              blockedSocks.add(socks);
              ws.pause();
              socks.once("drain", () => {
                blockedSocks.delete(socks);
                if (blockedSocks.size === 0) ws.resume();
              });
            }
          } catch (e) {}
        }
      } else {
        // Legacy: raw data goes to the single SOCKS5 connection
        if (legacySocket) {
          try {
            if (!legacySocket.write(buf)) {
              blockedSocks.add(legacySocket);
              ws.pause();
              legacySocket.once("drain", () => {
                blockedSocks.delete(legacySocket);
                if (blockedSocks.size === 0) ws.resume();
              });
            }
          } catch (e) {}
        }
      }
    }
  });

  function cleanupConn(connId) {
    const socks = connections.get(connId);
    if (socks) {
      connections.delete(connId);
      blockedSocks.delete(socks);
      try { socks.end(); } catch (e) {}
      if (blockedSocks.size === 0) ws.resume();
    }
  }

  function cleanupAll() {
    for (const [connId, socks] of connections) {
      try { socks.end(); } catch (e) {}
    }
    connections.clear();
    blockedSocks.clear();
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
  // Parse host:port with IPv6 support — e.g. [2001:db8::1]:443
  const lastColon = req.url.lastIndexOf(":");
  const host = req.url.slice(0, lastColon).replace(/^\[|\]$/g, "");
  const port = parseInt(req.url.slice(lastColon + 1)) || 443;
  socks5Connect(host, port)
    .then((ts) => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // Forward any initial data that arrived with the CONNECT request
      // (TLS-in-CONNECT, Expect: 100-continue, etc.)
      if (head && head.length > 0) ts.write(head);
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
  
  currentWireProxy = startWireProxy(initialCfg, CURRENT_SOCKS_PORT);
  console.log("[wg-proxy] Waiting for SOCKS5...");
  const ready = await waitForSocks5(45000);
  if (!ready) {
    console.error("[wg-proxy] SOCKS5 failed to start");
    process.exit(1);
  }
  console.log(`[wg-proxy] WireGuard ready (endpoint: ${initialCfg.endpoint})`);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[wg-proxy] Proxy ready on :${PORT}`);
    console.log(`[wg-proxy]   WebSocket relay → WireGuard SOCKS5 :${CURRENT_SOCKS_PORT}`);
  });

  startRotationLoop();
}

// ── Graceful shutdown ──
const SHUTDOWN_GRACE_MS = 10000;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[wg-proxy] Received ${signal} — starting graceful shutdown...`);

  // 1. Stop accepting new connections
  server.close(() => {
    console.log("[wg-proxy] HTTP server closed");
  });

  // 2. Close all WebSocket clients (sends close frame, triggers cleanupAll)
  for (const ws of [...wss.clients]) {
    ws.close(1001, "Server shutting down");
  }

  // 3. Kill wireproxy
  if (currentWireProxy) {
    currentWireProxy.wasKilled = true;
    currentWireProxy.kill("SIGTERM");
  }

  // 4. Force exit after grace period
  setTimeout(() => {
    console.log("[wg-proxy] Shutdown timeout — forcing exit");
    process.exit(0);
  }, SHUTDOWN_GRACE_MS);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));


main().catch((err) => { console.error("[wg-proxy] Fatal:", err); process.exit(1); });
