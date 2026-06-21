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

# SOCKS5 chain function via Node.js
# Handles both HTTP health checks AND HTTP CONNECT proxy
# that chains through WireGuard SOCKS5
node -e "
const net = require('net');
const http = require('http');
const PORT = process.env.PORT || 10000;
const SOCKS_HOST = '127.0.0.1';
const SOCKS_PORT = 1080;

// HTTP CONNECT proxy -> WireGuard SOCKS5
function socks5Connect(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({host:SOCKS_HOST, port:SOCKS_PORT}, () => {
      s.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let state=0, buf=Buffer.alloc(0);
    s.on('data', (d) => {
      buf = Buffer.concat([buf,d]);
      if (state===0 && buf.length>=2) {
        if (buf[1]!==0x00) { s.destroy(); reject(new Error('auth fail')); return; }
        state=1;
        const hb = Buffer.from(targetHost);
        s.write(Buffer.concat([Buffer.from([0x05,0x01,0x00,0x03,hb.length]), hb, Buffer.from([(targetPort>>8)&0xFF, targetPort&0xFF])]));
        buf=Buffer.alloc(0);
      } else if (state===1 && buf.length>=4) {
        if (buf[1]!==0x00) { s.destroy(); reject(new Error('reject:'+buf[1])); return; }
        resolve(s);
      }
    });
    s.on('error', reject);
    s.setTimeout(30000, () => { s.destroy(); reject(new Error('timeout')); });
  });
}

// HTTP server (health + CONNECT)
const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type':'application/json'});
  res.end(JSON.stringify({status:'ok',mode:'wg-proxy'}));
});

server.on('connect', (req, socket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr) || 443;
  socks5Connect(host, port)
    .then((ts) => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      ts.pipe(socket);
      socket.pipe(ts);
    })
    .catch(() => {
      socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      socket.end();
    });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Proxy ready on 0.0.0.0:' + PORT);
  console.log('  HTTP CONNECT + health');
  console.log('  Upstream: WireGuard SOCKS5 :' + SOCKS_PORT);
});
" &

wait $WIREPROXY_PID
