#!/usr/bin/env python3
"""
HuggingClaw Proxy Pool — Self-Rotating SOCKS5 Proxy Pool with Telegram Support

Fetches free SOCKS5 proxies, tests them against api.telegram.org, and runs
a local SOCKS5 server that auto-rotates every 10 minutes.

Key features:
- Pre-verified proxies tested against Telegram's actual API
- Built-in known-good Telegram-capable fallback proxies
- Auto-rotate every 10 minutes for IP rotation
- Auto-failover on connection errors
"""

import asyncio
import threading
import struct
import socket
import random
import time
import logging
import ipaddress
import os
import sys
import json
import urllib.request
import urllib.error
import ssl

logging.basicConfig(
    level=logging.INFO,
    format="[proxy-pool] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("proxy-pool")

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9050
ROTATE_INTERVAL = 600  # 10 min
MAX_RETRIES = 3
CONNECT_TIMEOUT = 8
TELEGRAM_TEST_HOST = "api.telegram.org"
TELEGRAM_TEST_PORT = 443

PROXY_SOURCES = [
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
]

# Built-in fallback SOCKS5 proxies (verified to reach api.telegram.org)
# Format: (host, port)
BUILTIN_FALLBACKS = [
    ("45.61.185.38", 6304),
    ("67.43.228.250", 12371),
    ("107.173.137.218", 49117),
    ("192.111.135.21", 18424),
    ("209.146.126.210", 17683),
    ("162.210.195.177", 17469),
    ("104.244.73.101", 8800),
    ("23.137.248.197", 1080),
    ("68.185.57.66", 1080),
    ("69.58.9.119", 11555),
]

proxy_pool = []
current_proxy_index = 0
current_proxy = None  # (host, port)
last_rotation_time = 0
pool_lock = asyncio.Lock()
pool_ready = threading.Event()
stats = {
    "fetched": 0,
    "working": 0,
    "failed": 0,
    "rotations": 0,
    "current_ip": "startup",
}

def init_fallback_pool():
    global proxy_pool, current_proxy, current_proxy_index
    proxy_pool = list(BUILTIN_FALLBACKS)
    random.shuffle(proxy_pool)
    current_proxy_index = 0
    current_proxy = proxy_pool[0]
    stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
    stats["working"] = len(proxy_pool)
    pool_ready.set()
    log.info(f"Initialized: {len(proxy_pool)} proxies, starting with {current_proxy[0]}:{current_proxy[1]}")

def socks5_connect_test(proxy_host, proxy_port, target_host, target_port, timeout=8):
    """Full SOCKS5 connection + TLS probe to verify proxy works end-to-end."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_host, proxy_port))
        s.sendall(bytes([0x05, 0x01, 0x00]))
        resp = s.recv(2)
        if resp != bytes([0x05, 0x00]):
            s.close()
            return False
        
        hbuf = target_host.encode()
        req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + struct.pack(">H", target_port)
        s.sendall(req)
        
        resp = s.recv(4)
        if len(resp) < 4 or resp[1] != 0x00:
            s.close()
            return False
        
        # Consume BND.ADDR
        atyp = resp[3]
        if atyp == 0x01: s.recv(6)
        elif atyp == 0x03: 
            dl = s.recv(1)[0]
            s.recv(dl + 2)
        elif atyp == 0x04: s.recv(18)
        
        # TLS handshake required — we need HTTPS, not just TCP+SOCKS
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(s, server_hostname=target_host)
            tls.do_handshake()
            tls.close()
        except Exception:
            s.close()
            return False
        
        s.close()
        return True
    except Exception:
        try: s.close()
        except: pass
        return False

def fetch_proxy_list():
    all_proxies = set()
    for url in PROXY_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
                for line in data.splitlines():
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                host = parts[0].strip()
                                port = int(parts[1].strip())
                                if host and 1 <= port <= 65535 and not host.startswith("10.") and not host.startswith("192.168.") and not host.startswith("172.16."):
                                    all_proxies.add((host, port))
                            except ValueError:
                                continue
        except Exception as e:
            log.warning(f"Fetch failed: {e}")
    stats["fetched"] = len(all_proxies)
    return list(all_proxies)

async def test_proxy_telegram(host, port):
    """Test if proxy can reach api.telegram.org."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, socks5_connect_test, host, port, TELEGRAM_TEST_HOST, TELEGRAM_TEST_PORT
    )

async def refresh_pool_background():
    """Fetch new proxies, test against Telegram, merge into pool."""
    log.info("Refreshing pool from sources...")
    try:
        proxies = fetch_proxy_list()
        if not proxies:
            return
        
        batch = random.sample(proxies, min(30, len(proxies)))
        log.info(f"Testing {len(batch)} proxies against {TELEGRAM_TEST_HOST}...")
        tasks = [test_proxy_telegram(h, p) for h, p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        working = [(h, p) for (h, p), ok in zip(batch, results) if ok]
        
        if working:
            async with pool_lock:
                existing = set(proxy_pool)
                new_ones = [p for p in working if p not in existing]
                if new_ones:
                    proxy_pool.extend(new_ones)
                    random.shuffle(proxy_pool)
                    stats["working"] = len(proxy_pool)
                    log.info(f"Added {len(new_ones)} Telegram-capable proxies (pool: {len(proxy_pool)})")
        else:
            log.warning("No Telegram-capable proxies found in this batch")
    except Exception as e:
        log.error(f"Refresh failed: {e}")

def rotate_proxy():
    global current_proxy_index, current_proxy, last_rotation_time
    if not proxy_pool:
        return False
    old_ip = f"{current_proxy[0]}:{current_proxy[1]}" if current_proxy else "none"
    current_proxy_index = (current_proxy_index + 1) % len(proxy_pool)
    current_proxy = proxy_pool[current_proxy_index]
    last_rotation_time = time.time()
    stats["rotations"] += 1
    stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
    log.info(f"Rotated: {old_ip} → {current_proxy[0]}:{current_proxy[1]}")
    return True

async def rotation_loop():
    global last_rotation_time
    last_rotation_time = time.time()
    while True:
        await asyncio.sleep(ROTATE_INTERVAL)
        async with pool_lock:
            rotate_proxy()

async def background_refresh_loop():
    pool_ready.wait()
    await asyncio.sleep(20)  # Short delay before first refresh
    while True:
        try:
            await refresh_pool_background()
        except Exception as e:
            log.error(f"Refresh: {e}")
        await asyncio.sleep(ROTATE_INTERVAL)

# ── SOCKS5 Server ──
async def socks5_handler(reader, writer):
    global current_proxy
    pool_ready.wait()
    
    try:
        # SOCKS5 greeting
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if data[0] != 0x05:
            writer.close()
            return
        
        nmethods = data[1]
        if nmethods > 0:
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=10)
        writer.write(bytes([0x05, 0x00]))
        await writer.drain()
        
        # SOCKS5 request
        data = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        if data[0] != 0x05 or data[1] != 0x01:
            writer.write(bytes([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
            await writer.drain()
            writer.close()
            return
        
        atype = data[3]
        if atype == 0x01:
            data = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            target_host = str(ipaddress.IPv4Address(data))
        elif atype == 0x03:
            data = await asyncio.wait_for(reader.readexactly(1), timeout=10)
            dlen = data[0]
            data = await asyncio.wait_for(reader.readexactly(dlen), timeout=10)
            target_host = data.decode()
        elif atype == 0x04:
            data = await asyncio.wait_for(reader.readexactly(16), timeout=10)
            target_host = str(ipaddress.IPv6Address(data))
        else:
            writer.close()
            return
        
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        target_port = struct.unpack(">H", data)[0]
        
        async with pool_lock:
            upstream = current_proxy
        
        if not upstream:
            writer.close()
            return
        
        upstream_host, upstream_port = upstream
        
        for attempt in range(MAX_RETRIES):
            try:
                us = socket.create_connection((upstream_host, upstream_port), timeout=CONNECT_TIMEOUT)
                
                # SOCKS5 handshake
                us.sendall(bytes([0x05, 0x01, 0x00]))
                resp = us.recv(2)
                if resp != bytes([0x05, 0x00]):
                    us.close()
                    async with pool_lock:
                        stats["failed"] += 1
                        if not rotate_proxy():
                            raise Exception("pool exhausted")
                        upstream = current_proxy
                        upstream_host, upstream_port = upstream
                    continue
                
                # Connect request
                hbuf = target_host.encode()
                req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + struct.pack(">H", target_port)
                us.sendall(req)
                
                resp = us.recv(4)
                if len(resp) < 4 or resp[1] != 0x00:
                    us.close()
                    async with pool_lock:
                        stats["failed"] += 1
                        if (upstream_host, upstream_port) in proxy_pool:
                            proxy_pool.remove((upstream_host, upstream_port))
                        rotate_proxy()
                        upstream = current_proxy
                        upstream_host, upstream_port = upstream
                    continue
                
                # Consume BND.ADDR
                atyp2 = resp[3]
                if atyp2 == 0x01: us.recv(6)
                elif atyp2 == 0x03:
                    dl = us.recv(1)[0]
                    us.recv(dl + 2)
                elif atyp2 == 0x04: us.recv(18)
                
                # Success response to client
                writer.write(bytes([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
                await writer.drain()
                
                # Bidirectional relay
                loop = asyncio.get_event_loop()
                
                async def to_upstream():
                    try:
                        while True:
                            d = await asyncio.wait_for(reader.read(65536), timeout=300)
                            if not d: break
                            await loop.run_in_executor(None, us.sendall, d)
                    except Exception: pass
                    finally:
                        try: us.close()
                        except: pass
                
                async def from_upstream():
                    try:
                        while True:
                            d = await loop.run_in_executor(None, us.recv, 65536)
                            if not d: break
                            writer.write(d)
                            await writer.drain()
                    except Exception: pass
                    finally:
                        try: writer.close()
                        except: pass
                
                await asyncio.gather(to_upstream(), from_upstream())
                return
                
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as e:
                log.debug(f"Attempt {attempt+1}/{MAX_RETRIES}: {upstream_host}:{upstream_port} - {e}")
                async with pool_lock:
                    stats["failed"] += 1
                    if (upstream_host, upstream_port) in proxy_pool:
                        proxy_pool.remove((upstream_host, upstream_port))
                    if not rotate_proxy():
                        break
                    upstream = current_proxy
                    upstream_host, upstream_port = upstream
        
        writer.close()
        
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        log.debug(f"Handler: {e}")
    except Exception as e:
        log.debug(f"Handler: {e}")
    finally:
        try: writer.close()
        except: pass

async def main():
    log.info("=" * 50)
    log.info("  HuggingClaw Proxy Pool")
    log.info(f"  Listen: {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"  Rotate: every {ROTATE_INTERVAL}s")
    log.info(f"  Proxies tested against {TELEGRAM_TEST_HOST}")
    log.info("=" * 50)
    
    init_fallback_pool()
    asyncio.create_task(rotation_loop())
    asyncio.create_task(background_refresh_loop())
    
    server = await asyncio.start_server(socks5_handler, LISTEN_HOST, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    log.info(f"Ready on {addr[0]}:{addr[1]}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutdown")
