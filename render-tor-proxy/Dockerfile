# ── Tor + HTTP CONNECT Proxy for Render (Free Tier) ──
# Render only exposes $PORT (HTTPS/HTTP). This runs an HTTP CONNECT proxy
# that tunnels through Tor — compatible with Render's port exposure.
FROM alpine:3.19

RUN apk add --no-cache tor python3

# HTTP CONNECT proxy script (accepts CONNECT + health checks, tunnels through Tor)
COPY <<'PYEOF' /proxy.py
#!/usr/bin/env python3
import socket, threading, os, subprocess, time

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 9050
HTTP_PORT = int(os.environ.get("PORT", 10000))

def socks5_connect(target_host, target_port):
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
        if atyp == 0x01: s.recv(6)
        elif atyp == 0x03:
            dl = s.recv(1)[0]
            s.recv(dl + 2)
        elif atyp == 0x04: s.recv(18)
        return s
    except: return None

def handle_client(conn):
    try:
        data = conn.recv(4096)
        if not data: conn.close(); return
        first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        # Health check
        if first_line.startswith('GET') or first_line.startswith('HEAD'):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            conn.close(); return
        # CONNECT
        if first_line.startswith('CONNECT'):
            parts = first_line.split(' ')
            if len(parts) >= 2:
                hp = parts[1].split(':')
                th = hp[0]; tp = int(hp[1]) if len(hp) > 1 else 443
                ts = socks5_connect(th, tp)
                if ts:
                    conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    def relay(s, d):
                        try:
                            while True:
                                b = s.recv(65536)
                                if not b: break
                                d.sendall(b)
                        except: pass
                    t1 = threading.Thread(target=relay, args=(conn, ts))
                    t1.daemon = True
                    t2 = threading.Thread(target=relay, args=(ts, conn))
                    t2.daemon = True
                    t1.start(); t2.start(); t1.join(); t2.join()
                    ts.close()
                else:
                    conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        else:
            conn.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
    except: pass
    finally:
        try: conn.close()
        except: pass

def main():
    subprocess.Popen(["tor", "-f", "/tmp/torrc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", HTTP_PORT))
    server.listen(50)
    print(f"HTTP CONNECT proxy on 0.0.0.0:{HTTP_PORT} (tunnels through Tor SOCKS5)")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    main()
PYEOF

# Tor config
RUN mkdir -p /tmp/tor-data && chmod 700 /tmp/tor-data
RUN echo 'SOCKSPort 127.0.0.1:9050\nDataDirectory /tmp/tor-data\nLog notice stdout\nClientOnly 1\nExitRelay 0\nBridgeRelay 0' > /tmp/torrc

EXPOSE 10000
CMD ["python3", "/proxy.py"]
