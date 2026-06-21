#!/bin/sh
set -e

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

wireproxy -c /etc/wireproxy.conf &
WIREPROXY_PID=$!

for i in $(seq 1 15); do
  nc -z 127.0.0.1 1080 2>/dev/null && break
  sleep 1
done
echo "WireGuard SOCKS5 ready"

# net.createServer — full byte control (no http.Server interference)
node -e "
const net = require('net');
const crypto = require('crypto');
const { Duplex } = require('stream');
const PORT = process.env.PORT || 10000;
const SOCKS_HOST = '127.0.0.1';
const SOCKS_PORT = 1080;
const WS_GUID = '258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6';

function socks5Connect(host, port) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({host:SOCKS_HOST, port:SOCKS_PORT}, () => {
      s.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state=0, buf=Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, 30000);
    const cleanup = () => { clearTimeout(timer); s.removeListener('data', onData); };
    const onData = (d) => {
      buf = Buffer.concat([buf,d]);
      try {
        if (state===0 && buf.length>=2) {
          if (buf[1]!==0x00) { cleanup(); s.destroy(); reject(new Error('auth')); return; }
          state=1; const hb=Buffer.from(host);
          s.write(Buffer.concat([Buffer.from([0x05,0x01,0x00,0x03,hb.length]),hb,Buffer.from([(port>>8)&0xFF,port&0xFF])]));
          buf=Buffer.alloc(0);
        } else if (state===1 && buf.length>=4) {
          cleanup();
          if (buf[1]!==0x00) { s.destroy(); reject(new Error('reject:'+buf[1])); return; }
          resolve(s);
        }
      } catch(e) { cleanup(); reject(e); }
    };
    s.on('data', onData);
    s.on('error', (e) => { cleanup(); reject(e); });
    s.setTimeout(30000, () => { s.destroy(); cleanup(); reject(new Error('timeout')); });
  });
}

function sendWs(socket, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const hdr = buf.length < 126 ? Buffer.from([0x82, buf.length]) : (()=>{const h=Buffer.alloc(4);h[0]=0x82;h[1]=126;h.writeUInt16BE(buf.length,2);return h;})();
  try { socket.write(Buffer.concat([hdr,buf])); } catch(e) {}
}

const srv = net.createServer((socket) => {
  socket.once('data', (data) => {
    const raw = data.toString();
    const first = data[0];

    // Health check (GET / or HEAD /)
    if (raw.startsWith('GET ') || raw.startsWith('HEAD ')) {
      const body = JSON.stringify({status:'ok',mode:'wg-proxy'});
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\nConnection: close\r\n\r\n' + body);
      socket.end();
      return;
    }

    // HTTP CONNECT (for TLS tunneling through Render)
    if (raw.startsWith('CONNECT ')) {
      const m = raw.match(/^CONNECT\s+([^:]+):(\d+)\s+/i);
      if (!m) { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.end(); return; }
      const th=m[1], tp=parseInt(m[2]);
      socks5Connect(th, tp).then((ts) => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        ts.pipe(socket); socket.pipe(ts);
      }).catch(() => { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.end(); });
      return;
    }

    // WebSocket upgrade
    if (raw.includes('Upgrade: websocket') || raw.includes('upgrade: websocket')) {
      const key = raw.match(/Sec-WebSocket-Key:\s*(\S+)/i);
      if (!key) { socket.end(); return; }
      const accept = crypto.createHash('sha1').update(key[1]+WS_GUID).digest('base64');
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');

      const idx = data.indexOf('\r\n\r\n');
      let frameBuf = idx>=0 ? data.slice(idx+4) : Buffer.alloc(0);
      let expectingConfig = true;
      let torSocket = null;

      const onData = (d) => {
        frameBuf = Buffer.concat([frameBuf, d]);
        while (frameBuf.length >= 2) {
          const op = frameBuf[0] & 0x0F;
          const masked = (frameBuf[1] & 0x80) !== 0;
          let len = frameBuf[1] & 0x7F, off = 2;
          if (len === 126) { if (frameBuf.length < 4) return; len = frameBuf.readUInt16BE(2); off = 4; }
          if (len === 127) { if (frameBuf.length < 10) return; len = Number(frameBuf.readBigUInt64BE(2)); off = 10; }
          if (masked) off += 4;
          if (frameBuf.length < off + len) return;
          const p = Buffer.from(frameBuf.slice(off, off+len));
          const mk = masked ? frameBuf.slice(off-4, off) : null;
          if (mk) { for(let i=0;i<p.length;i++) p[i] ^= mk[i%4]; }
          frameBuf = frameBuf.slice(off+len);
          if (op === 0x8) { cleanup(); return; }
          if (op === 0x9) continue;

          if (expectingConfig) {
            try {
              const cfg = JSON.parse(p.toString());
              socks5Connect(cfg.host||'opencode.ai', cfg.port||443).then((ts) => {
                torSocket = ts; expectingConfig = false;
                sendWs(socket, JSON.stringify({status:'connected'}));
                ts.on('data', (td) => sendWs(socket, td));
                ts.on('error', cleanup); ts.on('close', cleanup);
              }).catch((err) => { try { sendWs(socket, JSON.stringify({error:err.message})); } catch(e){} cleanup(); });
            } catch(e) { cleanup(); }
          } else if (torSocket) {
            try { torSocket.write(p); } catch(e) {}
          }
        }
      };
      const cleanup = () => { socket.removeListener('data', onData); try { socket.destroy(); } catch(e){} try { torSocket?.end(); } catch(e){} };
      socket.on('data', onData); socket.on('error', cleanup); socket.on('close', cleanup);

      // Process any initial data
      if (frameBuf.length > 0) setTimeout(() => { try { onData(Buffer.alloc(0)); } catch(e) {} }, 10);
      return;
    }

    socket.end();
  });
});

srv.listen(PORT, '0.0.0.0', () => {
  console.log('Proxy ready on 0.0.0.0:' + PORT);
  console.log('  health / CONNECT / WS');
  console.log('  Upstream: WireGuard SOCKS5 :' + SOCKS_PORT);
});
" &

wait $WIREPROXY_PID
