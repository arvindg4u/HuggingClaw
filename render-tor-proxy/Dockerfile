# ── WebSocket-to-Tor Proxy for Render (Free Tier) ──
# Render + Cloudflare block raw TCP/SOCKS5. WebSocket works through both.
# This runs a WebSocket server that tunnels connections through Tor SOCKS5.
FROM alpine:3.19

RUN apk add --no-cache tor python3 py3-pip
# No external Python packages needed — pure stdlib asyncio

# WebSocket-to-Tor proxy
COPY <<'PYEOF' /proxy.py
#!/usr/bin/env python3
"""WebSocket-to-Tor proxy via asyncio — handles both HTTP health checks AND WebSocket.
   Does NOT depend on the 'websockets' library (avoids its HTTP method restrictions).
   
   Render platform + cron-job.org send HEAD/GET probes → handled as HTTP 200 OK.
   HuggingClaw sends WebSocket upgrade with JSON config → tunnels through Tor SOCKS5."""
import asyncio, os, socket, struct, json, subprocess, hashlib, base64

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 9050
HTTP_PORT = int(os.environ.get("PORT", 10000))
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-5AB5E4BE6AC6"

# ── WebSocket frame helpers ──

async def _readn(reader, n):
    buf = b''
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

async def read_ws_msg(reader):
    """Read one complete WebSocket message (assembles continuation frames).
       Returns None on close/error."""
    payload = b''
    while True:
        hdr = await _readn(reader, 2)
        if hdr is None: return None
        b0, b1 = hdr
        fin = (b0 & 0x80) != 0
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        length = b1 & 0x7F
        if length == 126:
            ext = await _readn(reader, 2)
            if ext is None: return None
            length = struct.unpack('>H', ext)[0]
        elif length == 127:
            ext = await _readn(reader, 8)
            if ext is None: return None
            length = struct.unpack('>Q', ext)[0]
        if masked:
            mk = await _readn(reader, 4)
            if mk is None: return None
        else:
            mk = None
        raw = await _readn(reader, length)
        if raw is None: return None
        if mk:
            raw = bytes(b ^ mk[i % 4] for i, b in enumerate(raw))
        if opcode == 0x8:  # Close
            return None
        if opcode in (0x9, 0xA):  # Ping/Pong — skip
            continue
        payload += raw
        if fin:
            break
    return payload

async def write_ws_msg(writer, data):
    """Send a WebSocket binary message (unmasked server→client)."""
    length = len(data)
    hdr = bytearray([0x82])  # FIN + opcode binary
    if length < 126:
        hdr.append(length)
    elif length < 65536:
        hdr.append(126)
        hdr.extend(struct.pack('>H', length))
    else:
        hdr.append(127)
        hdr.extend(struct.pack('>Q', length))
    writer.write(bytes(hdr) + data)
    await writer.drain()

# ── SOCKS5 through Tor ──

def socks5_connect_sync(target_host, target_port):
    """Synchronous SOCKS5 connect through local Tor (runs in executor)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(bytes([0x05, 0x01, 0x00]))
        resp = s.recv(2)
        if resp != bytes([0x05, 0x00]): s.close(); return None
        hbuf = target_host.encode()
        req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + target_port.to_bytes(2, 'big')
        s.sendall(req)
        resp = s.recv(4)
        if len(resp) < 4 or resp[1] != 0x00: s.close(); return None
        atyp = resp[3]
        if atyp == 0x01:    s.recv(6)
        elif atyp == 0x03:  s.recv(s.recv(1)[0] + 2)
        elif atyp == 0x04:  s.recv(18)
        # s stays in blocking mode for executor thread
        return s
    except:
        try: s.close()
        except: pass
        return None

# ── Connection handler ──

async def handle_conn(reader, writer):
    """Handle one TCP connection: HTTP health check or WebSocket proxy."""
    # Read until we have the complete HTTP headers (ended by \r\n\r\n)
    try:
        data = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=15)
    except asyncio.TimeoutError:
        writer.close(); return
    except asyncio.IncompleteReadError as e:
        data = e.partial
        if not data:
            writer.close(); return
    except ConnectionError:
        writer.close(); return

    # Peek: is this a WebSocket upgrade or plain HTTP?
    is_ws_upgrade = b'upgrade: websocket' in data.lower()

    if not is_ws_upgrade:
        # Health check — any HTTP method (GET, HEAD, etc.)
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK')
        await writer.drain()
        writer.close()
        return

    # ── WebSocket upgrade ──
    request = data.decode('utf-8', errors='replace')
    key = None
    for line in request.split('\r\n'):
        if line.lower().startswith('sec-websocket-key:'):
            key = line.split(':', 1)[1].strip()
            break
    if not key:
        writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        await writer.drain()
        writer.close()
        return

    accept = base64.b64encode(
        hashlib.sha1((key + WEBSOCKET_GUID).encode()).digest()
    ).decode()
    writer.write((
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Accept: {accept}\r\n'
        '\r\n'
    ).encode())
    await writer.drain()

    # Read JSON config from client
    msg = await read_ws_msg(reader)
    if msg is None:
        writer.close(); return
    try:
        cfg = json.loads(msg.decode())
    except:
        writer.close(); return
    target_host = cfg.get("host", "opencode.ai")
    target_port = cfg.get("port", 443)

    # Connect through Tor SOCKS5
    loop = asyncio.get_event_loop()
    tcp = await loop.run_in_executor(None, socks5_connect_sync, target_host, target_port)
    if tcp is None:
        await write_ws_msg(writer, json.dumps({"error": "proxy connect failed"}).encode())
        writer.close(); return

    await write_ws_msg(writer, json.dumps({"status": "connected"}).encode())

    # ── Bidirectional relay ──
    ws2tcp_task = asyncio.create_task(_ws2tcp(reader, tcp, loop))
    tcp2ws_task = asyncio.create_task(_tcp2ws(tcp, writer, loop))
    await asyncio.gather(ws2tcp_task, tcp2ws_task)
    try: tcp.close()
    except: pass
    try: writer.close()
    except: pass

async def _ws2tcp(reader, tcp, loop):
    try:
        while True:
            m = await read_ws_msg(reader)
            if m is None: break
            await loop.run_in_executor(None, tcp.sendall, m)
    except: pass

async def _tcp2ws(tcp, writer, loop):
    try:
        while True:
            d = await loop.run_in_executor(None, tcp.recv, 65536)
            if not d: break
            await write_ws_msg(writer, d)
    except: pass

# ── Main ──

async def main():
    print(f"WebSocket proxy on 0.0.0.0:{HTTP_PORT}")
    # Start Tor
    tor = await asyncio.create_subprocess_exec(
        "tor", "-f", "/tmp/torrc",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(5)

    server = await asyncio.start_server(handle_conn, "0.0.0.0", HTTP_PORT)
    async with server:
        print(f"Proxy ready — HTTP health + WebSocket via Tor")
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())

PYEOF

# Tor config
RUN mkdir -p /tmp/tor-data && chmod 700 /tmp/tor-data
RUN echo 'SOCKSPort 127.0.0.1:9050\nDataDirectory /tmp/tor-data\nLog notice stdout\nClientOnly 1\nExitRelay 0\nBridgeRelay 0' > /tmp/torrc

EXPOSE 10000
CMD ["python3", "/proxy.py"]
