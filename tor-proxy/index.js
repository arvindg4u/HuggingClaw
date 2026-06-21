#!/usr/bin/env node
const net = require("net");
const crypto = require("crypto");
const PORT = process.env.PORT || 10000;
const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6";

const server = net.createServer((socket) => {
  socket.once("data", (data) => {
    const raw = data.toString();
    if (raw.includes("Upgrade: websocket") || raw.includes("upgrade: websocket")) {
      const key = raw.match(/Sec-WebSocket-Key:\s*(\S+)/i);
      if (!key) { socket.destroy(); return; }
      const accept = crypto.createHash("sha1").update(key[1] + WS_GUID).digest("base64");
      socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");

      // Echo server — unmask incoming frames, echo back unmasked
      let buf = Buffer.alloc(0);
      socket.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 2) {
          const op = buf[0] & 0x0F;
          const masked = (buf[1] & 0x80) !== 0;
          let len = buf[1] & 0x7F, off = 2;
          if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
          if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
          if (masked) off += 4;
          if (buf.length < off + len) return;
          const p = buf.slice(off, off + len);
          const mk = masked ? buf.slice(off - 4, off) : null;
          if (mk) { for (let i = 0; i < p.length; i++) p[i] ^= mk[i % 4]; }
          buf = buf.slice(off + len);
          if (op === 0x8) { socket.end(); return; }
          if (op === 0x9) continue;
          // Echo back
          const hdr = len < 126 ? Buffer.from([0x82, len]) : (() => { const h = Buffer.alloc(4); h[0] = 0x82; h[1] = 126; h.writeUInt16BE(len, 2); return h; })();
          socket.write(Buffer.concat([hdr, p]));
        }
      });
    } else {
      const body = JSON.stringify({ status: "echo", version: "1" });
      socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(body) + "\r\nConnection: close\r\n\r\n" + body);
      socket.end();
    }
  });
});

server.listen(PORT, "0.0.0.0", () => console.log(`Echo server on :${PORT}`));
