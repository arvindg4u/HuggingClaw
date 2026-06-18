# ── WebSocket-to-Tor Proxy for Render (Free Tier) ──
# Render + Cloudflare block raw TCP/SOCKS5. WebSocket works through both.
# This runs a WebSocket server that tunnels connections through Tor SOCKS5.
FROM alpine:3.19

RUN apk add --no-cache tor python3 py3-pip
RUN pip3 install --no-cache-dir --break-system-packages "websockets>=13"

# WebSocket-to-Tor proxy
COPY <<'PYEOF' /proxy.py
#!/usr/bin/env python3
"""WebSocket-to-Tor proxy — connects through Cloudflare + Render, tunnels through Tor.
   Uses websockets>=13 which properly handles HTTP health checks via process_request."""
import asyncio, os, socket, struct, json, subprocess
import websockets

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 9050
HTTP_PORT = int(os.environ.get("PORT", 10000))

async def socks5_connect(target_host, target_port):
    loop = asyncio.get_event_loop()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        await loop.run_in_executor(None, s.connect, (SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(bytes([0x05, 0x01, 0x00]))
        resp = s.recv(2)
        if resp != bytes([0x05, 0x00]): s.close(); return None
        hbuf = target_host.encode()
        req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + target_port.to_bytes(2, 'big')
        s.sendall(req)
        resp = s.recv(4)
        if len(resp) < 4 or resp[1] != 0x00: s.close(); return None
        atyp = resp[3]
        if atyp == 0x01: await loop.run_in_executor(None, s.recv, 6)
        elif atyp == 0x03:
            dl = await loop.run_in_executor(None, s.recv, 1)
            await loop.run_in_executor(None, s.recv, dl[0] + 2)
        elif atyp == 0x04: await loop.run_in_executor(None, s.recv, 18)
        return s
    except: return None

async def relay(ws, tcp_sock):
    loop = asyncio.get_event_loop()
    async def ws_to_tcp():
        try:
            async for msg in ws:
                if isinstance(msg, bytes):
                    await loop.run_in_executor(None, tcp_sock.sendall, msg)
        except: pass
    async def tcp_to_ws():
        try:
            while True:
                data = await loop.run_in_executor(None, tcp_sock.recv, 65536)
                if not data: break
                await ws.send(data)
        except: pass
    await asyncio.gather(ws_to_tcp(), tcp_to_ws())

async def handle_ws(ws):
    try:
        msg = await asyncio.wait_for(ws.recv(), timeout=15)
        config = json.loads(msg if isinstance(msg, str) else msg.decode())
        target_host = config.get("host", "opencode.ai")
        target_port = config.get("port", 443)

        tcp_sock = await socks5_connect(target_host, target_port)
        if not tcp_sock:
            await ws.send(json.dumps({"error": "proxy connect failed"}))
            return

        await ws.send(json.dumps({"status": "connected"}))
        await relay(ws, tcp_sock)
        tcp_sock.close()
    except Exception as e:
        try: await ws.send(json.dumps({"error": str(e)}))
        except: pass

async def health_check(connection, request):
    """Handle HTTP health checks (GET and HEAD). websockets>=13 calls this for non-GET methods too."""
    if request.path == "/" or request.path == "/health" or request.path == "/proxy":
        return websockets.HTTPResponse(200, {"Content-Type": "text/plain"}, b"OK")
    return None  # Not a health check path — proceed with WebSocket upgrade

async def main():
    print(f"WebSocket proxy on 0.0.0.0:{HTTP_PORT}")
    # Start Tor
    proc = await asyncio.create_subprocess_exec(
        "tor", "-f", "/tmp/torrc",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(5)

    async def handler(ws):
        await handle_ws(ws)

    async with websockets.serve(handler, "0.0.0.0", HTTP_PORT, process_request=health_check):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
PYEOF

# Tor config
RUN mkdir -p /tmp/tor-data && chmod 700 /tmp/tor-data
RUN echo 'SOCKSPort 127.0.0.1:9050\nDataDirectory /tmp/tor-data\nLog notice stdout\nClientOnly 1\nExitRelay 0\nBridgeRelay 0' > /tmp/torrc

EXPOSE 10000
CMD ["python3", "/proxy.py"]
