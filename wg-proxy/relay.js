#!/usr/bin/env node
const http = require("http");
const net = require("net");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 10000;
const SOCKS_HOST = "127.0.0.1";
const SOCKS_PORT = 1080;

// ── WireGuard config from env ──
const WG_PRIVATE_KEY = process.env.WG_PRIVATE_KEY || "wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=";
const WG_PEER_PUBLIC_KEY = process.env.WG_PEER_PUBLIC_KEY || "Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=";
const WG_ENDPOINT = process.env.WG_ENDPOINT || "146.70.202.34:51820";

function startWireProxy() {
  const fs = require("fs");
  const config = `[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ${WG_PEER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${WG_ENDPOINT}
PersistentKeepalive = 25

[Socks5]
BindAddress = 0.0.0.0:1080
`;
  fs.writeFileSync("/etc/wireproxy.conf", config);
  const wp = spawn("wireproxy", ["-c", "/etc/wireproxy.conf"], { stdio: "inherit" });
  wp.on("exit", (code) => { console.log("wireproxy exited:", code); process.exit(1); });
  return wp;
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
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", mode: "wg-proxy", socks5: `:${SOCKS_PORT}` }));
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

// ── Start ──
async function main() {
  // Start WireGuard
  console.log("[wg-proxy] Starting WireGuard...");
  startWireProxy();

  // Wait for SOCKS5
  for (let i = 0; i < 15; i++) {
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
      console.log(`[wg-proxy] WireGuard ready after ${i + 1}s`);
      break;
    } catch (e) {
      if (i < 14) await new Promise((r) => setTimeout(r, 1000));
    }
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[wg-proxy] Proxy ready on :${PORT}`);
    console.log(`[wg-proxy]   WebSocket relay → WireGuard SOCKS5 :${SOCKS_PORT}`);
  });
}

main().catch((err) => { console.error("[wg-proxy] Fatal:", err); process.exit(1); });
