#!/bin/sh
set -e

# Generate wireproxy config from env vars
: "${WG_PRIVATE_KEY:?WG_PRIVATE_KEY required}"
: "${WG_PEER_PUBLIC_KEY:?WG_PEER_PUBLIC_KEY required}"
: "${WG_ENDPOINT:?WG_ENDPOINT required}"

cat > /etc/wireproxy.conf <<EOF
[Interface]
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
EOF

# Start wireproxy in background
wireproxy -c /etc/wireproxy.conf &
WIREPROXY_PID=$!

# Wait for SOCKS5 port
for i in $(seq 1 15); do
  nc -z 127.0.0.1 1080 2>/dev/null && break
  sleep 1
done
echo "WireGuard SOCKS5 ready on 127.0.0.1:1080"

# Node.js: HTTP CONNECT + WS relay through WireGuard SOCKS5
node -e "
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { Duplex } = require('stream');
const PORT = process.env.PORT || 10000;
const SOCKS_HOST = '127.0.0.1';
const SOCKS_PORT = 1080;
const WS_GUID = '258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6';

function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({host:SOCKS_HOST, port:SOCKS_PORT}, () => {
      s.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state=0, buf=Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, 30000);
    s.on('data', (d) => {
      buf = Buffer.concat([buf,d]);
      try {
        if (state===0 && buf.length>=2) {
          if (buf[1]!==0x00) { clearTimeout(timer); s.destroy(); reject(new Error('auth')); return; }
          state=1; const hb = Buffer.from(targetHost);
          s.write(Buffer.concat([Buffer.from([0x05,0x01,0x00,0x03,hb.length]), hb, Buffer.from([(targetPort>>8)&0xFF, targetPort&0xFF])]));
          buf=Buffer.alloc(0);
        } else if (state===1 && buf.length>=4) {
          clearTimeout(timer);
          if (buf[1]!==0x00) { s.destroy(); reject(new Error('reject:'+buf[1])); return; }
          resolve(s);
        }
      } catch(e) { clearTimeout(timer); reject(e); }
    });
    s.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function sendWsFrame(socket, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const hdr = buf.length < 126 ? Buffer.from([0x82, buf.length]) : (() => { const h = Buffer.alloc(4); h[0]=0x82; h[1]=126; h.writeUInt16BE(buf.length,2); return h; })();
  try { socket.write(Buffer.concat([hdr, buf])); } catch(e) {}
}

const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type':'application/json'});
  res.end(JSON.stringify({status:'ok',mode:'wg-proxy'}));
});

// HTTP CONNECT: cloudflare-proxy.js uses tlsConnectProxy fallback
server.on('connect', (req, socket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr) || 443;
  socks5Connect(host, port)
    .then((ts) => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      ts.pipe(socket); socket.pipe(ts);
    })
    .catch(() => { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.end(); });
});

// WebSocket WS: cloudflare-proxy.js tries wsConnectProxy first
server.on('upgrade', (req, socket, head) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');

  let expectingConfig = true;
  let torSocket = null;
  let frameBuf = Buffer.isBuffer(head) ? head : Buffer.alloc(0);

  function processFrame() {
    while (frameBuf.length >= 2) {
      const op = frameBuf[0] & 0x0F;
      const masked = (frameBuf[1] & 0x80) !== 0;
      let len = frameBuf[1] & 0x7F, off = 2;
      if (len === 126) { if (frameBuf.length < 4) return; len = frameBuf.readUInt16BE(2); off = 4; }
      if (masked) off += 4;
      if (frameBuf.length < off + len) return;
      const p = frameBuf.slice(off, off+len);
      const mk = masked ? frameBuf.slice(off-4, off) : null;
      if (mk) { for(let i=0;i<p.length;i++) p[i] ^= mk[i%4]; }
      frameBuf = frameBuf.slice(off+len);
      if (op === 0x8) { cleanup(); return; }
      if (op === 0x9) continue;

      if (expectingConfig) {
        try {
          const cfg = JSON.parse(p.toString());
          socks5Connect(cfg.host || 'opencode.ai', cfg.port || 443)
            .then((ts) => {
              torSocket = ts;
              expectingConfig = false;
              sendWsFrame(socket, JSON.stringify({status:'connected'}));
              ts.on('data', (d) => sendWsFrame(socket, d));
              ts.on('error', cleanup);
              ts.on('close', cleanup);
            })
            .catch((err) => { try { sendWsFrame(socket, JSON.stringify({error:err.message})); } catch(e) {} cleanup(); });
        } catch(e) { cleanup(); }
      } else if (torSocket) {
        try { torSocket.write(p); } catch(e) {}
      }
    }
  }

  function cleanup() { socket.removeListener('data', onData); try { socket.destroy(); } catch(e) {} try { torSocket?.end(); } catch(e) {} }
  const onData = (d) => { frameBuf = Buffer.concat([frameBuf, d]); processFrame(); };
  socket.on('data', onData);
  socket.on('error', cleanup);
  socket.on('close', cleanup);
  processFrame();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Proxy ready on 0.0.0.0:' + PORT);
  console.log('  HTTP CONNECT + WebSocket + health');
  console.log('  Upstream: WireGuard SOCKS5 :' + SOCKS_PORT);
});
" &

wait $WIREPROXY_PID
