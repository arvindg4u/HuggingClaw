/**
 * Discord Loopback HTTP CONNECT Proxy
 *
 * HF Spaces blocks outbound connections to Discord servers.
 * OpenClaw's Discord plugin requires a loopback proxy URL for validation.
 * This proxy runs on 127.0.0.1 and accepts HTTP CONNECT requests.
 * It then connects to the target via net.connect, which is intercepted
 * by cloudflare-proxy.js for routed domains (discord.com, gateway.discord.gg).
 *
 * Flow:
 *   Discord Plugin → HttpsProxyAgent(http://127.0.0.1:31285)
 *     → CONNECT target:443 → this proxy → net.connect → cf-proxy intercepts
 *     → WebSocket → wg-proxy → WireGuard → Proton VPN → target
 *
 * Environment:
 *   DISCORD_LOOPBACK_PORT  – Listen port (default: 31285)
 */
'use strict';

const net = require('net');
const http = require('http');

const PORT = parseInt(process.env.DISCORD_LOOPBACK_PORT || '31285', 10);
const LISTEN_ADDR = '127.0.0.1';

const server = http.createServer((req, res) => {
  // Only CONNECT method is handled
  res.writeHead(405, { 'Content-Type': 'text/plain' });
  res.end('HTTP CONNECT proxy only');
});

server.on('connect', (req, clientSocket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;

  if (!host) {
    clientSocket.destroy(new Error('Invalid CONNECT target'));
    return;
  }

  // Connect to the target using net.connect.
  // cloudflare-proxy.js intercepts this for domains in ROUTE_TARGETS
  // (discord.com, gateway.discord.gg, etc.) and routes through WireGuard.
  const targetSocket = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // Relay duplex
    targetSocket.pipe(clientSocket);
    clientSocket.pipe(targetSocket);
  });

  targetSocket.on('error', (err) => {
    console.error(`[discord-loopback] connect error to ${host}:${port}: ${err.message}`);
    clientSocket.destroy(err);
  });

  clientSocket.on('error', (err) => {
    console.error(`[discord-loopback] client error: ${err.message}`);
    targetSocket.destroy();
  });

  // Forward any data already buffered
  if (head && head.length > 0) {
    targetSocket.write(head);
  }
});

server.listen(PORT, LISTEN_ADDR, () => {
  console.log(`[discord-loopback] Listening on ${LISTEN_ADDR}:${PORT}`);
  console.log(`[discord-loopback] Routes CONNECT targets through net.connect (cf-proxy intercepts routed domains)`);
});

// Graceful shutdown
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
