# ── Tor + HTTP CONNECT Proxy for Render (Free Tier) ──
# Render only exposes $PORT (HTTPS/HTTP). SOCKS5 is raw TCP and won't work.
# HTTP CONNECT proxy accepts standard HTTPS requests on $PORT and tunnels
# them through Tor — compatible with Render's port exposure.
FROM alpine:3.19

RUN apk add --no-cache tor

# HTTP CONNECT proxy script (accepts CONNECT and forwards through Tor)
RUN cat > /proxy.py << 'PYEOF'
#!/usr/bin/env python3
"""HTTP CONNECT proxy that tunnels through Tor SOCKS5."""
import socket
import threading
import os

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 9050
HTTP_PORT = int(os.environ.get("PORT", 10000))

def socks5_connect(target_host, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((SOCKS5_HOST, SOCKS5_PORT))
    s.sendall(bytes([0x05, 0x01, 0x00]))
    resp = s.recv(2)
    if resp != bytes([0x05, 0x00]):
        s.close()
        return None
    hbuf = target_host.encode()
    req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + target_port.to_bytes(2, 'big')
    s.sendall(req)
    resp = s.recv(4)
    if len(resp) < 4 or resp[1] != 0x00:
        s.close()
        return None
    atyp = resp[3]
    if atyp == 0x01: s.recv(6)
    elif atyp == 0x03:
        dl = s.recv(1)[0]
        s.recv(dl + 2)
    elif atyp == 0x04: s.recv(18)
    return s

def handle_client(conn):
    try:
        data = conn.recv(4096)
        if not data:
            conn.close()
            return
        
        # Parse HTTP CONNECT request
        first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        
        # Health check: respond with HTTP 200
        if first_line.startswith('GET') or first_line.startswith('HEAD'):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            conn.close()
            return
        
        # CONNECT tunnel
        if first_line.startswith('CONNECT'):
            parts = first_line.split(' ')
            if len(parts) >= 2:
                host_port = parts[1].split(':')
                target_host = host_port[0]
                target_port = int(host_port[1]) if len(host_port) > 1 else 443
                
                tor_sock = socks5_connect(target_host, target_port)
                if tor_sock:
                    conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    
                    # Bidirectional relay
                    def relay(src, dst):
                        try:
                            while True:
                                d = src.recv(65536)
                                if not d: break
                                dst.sendall(d)
                        except: pass
                    
                    t1 = threading.Thread(target=relay, args=(conn, tor_sock))
                    t1.daemon = True
                    t2 = threading.Thread(target=relay, args=(tor_sock, conn))
                    t2.daemon = True
                    t1.start(); t2.start()
                    t1.join(); t2.join()
                    tor_sock.close()
                else:
                    conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            conn.close()
        else:
            conn.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            conn.close()
    except:
        try: conn.close()
        except: pass

def main():
    # Start Tor
    import subprocess
    subprocess.Popen(["tor", "-f", "/tmp/torrc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    import time
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
RUN cat > /tmp/torrc << 'TOREOC'
SOCKSPort 127.0.0.1:9050
DataDirectory /tmp/tor-data
Log notice stdout
ClientOnly 1
ExitRelay 0
BridgeRelay 0
TOREOC

EXPOSE 10000

CMD ["python3", "/proxy.py"]
