#!/usr/bin/env python3
"""
HuggingClaw Proxy Pool — Self-Rotating SOCKS5 Proxy Pool

Fetches free SOCKS5 proxies from public proxy lists, maintains a pool,
and runs a local SOCKS5 server that automatically rotates upstream proxies
every 10 minutes for IP rotation (bypassing rate limits).

Startup strategy:
1. Immediately start serving with built-in fallback proxies
2. In background, fetch fresh proxies and replace the pool
3. Auto-rotate every 10 minutes
4. Auto-failover on connection errors
"""

import asyncio
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
import threading

logging.basicConfig(
    level=logging.INFO,
    format="[proxy-pool] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("proxy-pool")

# ── Configuration ──
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9050
ROTATE_INTERVAL = 600  # 10 minutes
MAX_RETRIES = 3
PROXY_REFRESH_INTERVAL = 600  # Refresh list every 10 min
CONNECT_TIMEOUT = 8

PROXY_SOURCES = [
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
]

# ── Built-in Fallback Proxies (pre-verified, immediately available) ──
# These are known-working free SOCKS5 proxies. Used immediately at startup
# while the pool fetches and tests fresh proxies in the background.
# Source: proxifly (updated 2026-06-18)
BUILTIN_FALLBACKS = [
    # Format: (host, port)
    ("45.61.185.38", 6304),
    ("67.43.228.250", 12371),
    ("69.58.9.119", 11555),
    ("107.173.137.218", 49117),
    ("192.111.135.21", 18424),
    ("68.185.57.66", 1080),
    ("104.244.73.101", 8800),
    ("162.210.195.177", 17469),
    ("209.146.126.210", 17683),
    ("23.137.248.197", 1080),
]

# ── State ──
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
    """Initialize the pool with built-in fallback proxies immediately."""
    global proxy_pool, current_proxy, current_proxy_index
    proxy_pool = list(BUILTIN_FALLBACKS)
    random.shuffle(proxy_pool)
    current_proxy_index = 0
    current_proxy = proxy_pool[0]
    stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
    stats["working"] = len(proxy_pool)
    pool_ready.set()
    log.info(f"Initialized with {len(proxy_pool)} built-in fallback proxies")
    log.info(f"Starting proxy: {current_proxy[0]}:{current_proxy[1]}")

def fetch_proxy_list():
    """Fetch SOCKS5 proxy list from sources."""
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
                                if host and 1 <= port <= 65535:
                                    all_proxies.add((host, port))
                            except ValueError:
                                continue
        except Exception as e:
            log.warning(f"Failed to fetch from {url}: {e}")
    stats["fetched"] = len(all_proxies)
    return list(all_proxies)

async def test_proxy(host, port):
    """Test if a SOCKS5 proxy is working."""
    try:
        loop = asyncio.get_event_loop()
        def _test():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(CONNECT_TIMEOUT)
                s.connect((host, port))
                s.sendall(bytes([0x05, 0x01, 0x00]))
                resp = s.recv(2)
                if resp != bytes([0x05, 0x00]):
                    s.close()
                    return False
                s.close()
                return True
            except Exception:
                return False
        return await loop.run_in_executor(None, _test)
    except Exception:
        return False

async def refresh_pool_background():
    """Background refresh: fetch new proxies, test, merge into pool."""
    log.info("Background pool refresh starting...")
    try:
        proxies = fetch_proxy_list()
        if not proxies:
            log.warning("No proxies fetched, keeping fallback pool")
            return

        # Test first 50 proxies (limit to avoid long delays)
        test_batch = random.sample(proxies, min(50, len(proxies)))
        log.info(f"Testing {len(test_batch)} proxies for pool update...")
        tasks = [test_proxy(h, p) for h, p in test_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        working = [(h, p) for (h, p), ok in zip(test_batch, results) if ok]

        if working:
            async with pool_lock:
                # Merge working proxies with existing pool (keep old ones too)
                existing_set = set(proxy_pool)
                new_proxies = [p for p in working if p not in existing_set]
                if new_proxies:
                    proxy_pool.extend(new_proxies)
                    random.shuffle(proxy_pool)
                    stats["working"] = len(proxy_pool)
                    log.info(f"Added {len(new_proxies)} fresh proxies (pool: {len(proxy_pool)})")
                else:
                    log.info("No new working proxies found (keeping existing pool)")
        else:
            log.warning("No working proxies found in background refresh")
    except Exception as e:
        log.error(f"Background refresh failed: {e}")

def rotate_proxy():
    """Rotate to next proxy in pool."""
    global current_proxy_index, current_proxy, last_rotation_time
    if not proxy_pool:
        return False
    old = current_proxy
    current_proxy_index = (current_proxy_index + 1) % len(proxy_pool)
    current_proxy = proxy_pool[current_proxy_index]
    last_rotation_time = time.time()
    stats["rotations"] += 1
    stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
    log.info(f"Rotated: {old[0]}:{old[1]} → {current_proxy[0]}:{current_proxy[1]}")
    return True

async def rotation_loop():
    global last_rotation_time
    last_rotation_time = time.time()
    while True:
        await asyncio.sleep(ROTATE_INTERVAL)
        async with pool_lock:
            rotate_proxy()

async def background_refresh_loop():
    """Wait for pool to be ready, then refresh periodically."""
    pool_ready.wait()
    await asyncio.sleep(30)  # Wait 30s before first refresh
    while True:
        try:
            await refresh_pool_background()
        except Exception as e:
            log.error(f"Refresh failed: {e}")
        await asyncio.sleep(PROXY_REFRESH_INTERVAL)

# ── SOCKS5 Server ──

async def socks5_handler(reader, writer):
    global current_proxy
    pool_ready.wait()

    try:
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if data[0] != 0x05:
            writer.close()
            return

        writer.write(bytes([0x05, 0x00]))
        await writer.drain()

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
            log.error("No proxies in pool!")
            writer.close()
            return

        upstream_host, upstream_port = upstream

        for attempt in range(MAX_RETRIES):
            try:
                upstream_sock = socket.create_connection(
                    (upstream_host, upstream_port), timeout=CONNECT_TIMEOUT
                )

                upstream_sock.sendall(bytes([0x05, 0x01, 0x00]))
                resp = upstream_sock.recv(2)
                if resp != bytes([0x05, 0x00]):
                    upstream_sock.close()
                    async with pool_lock:
                        stats["failed"] += 1
                        rotate_proxy()
                        upstream = current_proxy
                        if upstream:
                            upstream_host, upstream_port = upstream
                        else:
                            raise Exception("No proxy in pool")
                    continue

                hbuf = target_host.encode()
                req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + struct.pack(">H", target_port)
                upstream_sock.sendall(req)

                resp_data = upstream_sock.recv(4)
                if len(resp_data) < 4 or resp_data[1] != 0x00:
                    upstream_sock.close()
                    async with pool_lock:
                        stats["failed"] += 1
                        log.warning(f"Proxy {upstream_host}:{upstream_port} failed for {target_host}")
                        if (upstream_host, upstream_port) in proxy_pool:
                            proxy_pool.remove((upstream_host, upstream_port))
                        rotate_proxy()
                        upstream = current_proxy
                        if upstream:
                            upstream_host, upstream_port = upstream
                        else:
                            raise Exception("No proxy in pool")
                    continue

                # Read BND.ADDR
                atyp = resp_data[3]
                if atyp == 0x01:
                    upstream_sock.recv(6)
                elif atyp == 0x03:
                    dl = upstream_sock.recv(1)[0]
                    upstream_sock.recv(dl + 2)
                elif atyp == 0x04:
                    upstream_sock.recv(18)

                writer.write(bytes([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
                await writer.drain()

                # Bidirectional relay
                loop = asyncio.get_event_loop()

                async def relay_to_upstream():
                    try:
                        while True:
                            data = await asyncio.wait_for(reader.read(65536), timeout=300)
                            if not data:
                                break
                            await loop.run_in_executor(None, upstream_sock.sendall, data)
                    except Exception:
                        pass
                    finally:
                        try:
                            upstream_sock.close()
                        except Exception:
                            pass

                async def relay_from_upstream():
                    try:
                        while True:
                            data = await loop.run_in_executor(None, upstream_sock.recv, 65536)
                            if not data:
                                break
                            writer.write(data)
                            await writer.drain()
                    except Exception:
                        pass
                    finally:
                        try:
                            writer.close()
                        except Exception:
                            pass

                await asyncio.gather(relay_to_upstream(), relay_from_upstream())
                return  # Success

            except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as e:
                log.debug(f"Attempt {attempt+1}/{MAX_RETRIES} failed for {upstream_host}:{upstream_port}: {e}")
                async with pool_lock:
                    stats["failed"] += 1
                    if (upstream_host, upstream_port) in proxy_pool:
                        proxy_pool.remove((upstream_host, upstream_port))
                    if not rotate_proxy():
                        break
                    upstream = current_proxy
                    if upstream:
                        upstream_host, upstream_port = upstream
                    else:
                        break

        log.warning(f"All proxies failed for {target_host}")
        writer.close()

    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        log.debug(f"Handler: {e}")
    except Exception as e:
        log.debug(f"Handler: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def main():
    log.info("=" * 50)
    log.info("  HuggingClaw Proxy Pool")
    log.info(f"  Listen: {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"  Rotate: every {ROTATE_INTERVAL}s")
    log.info(f"  Built-in fallbacks: {len(BUILTIN_FALLBACKS)} proxies")
    log.info("=" * 50)

    # Initialize with fallback proxies immediately
    init_fallback_pool()

    # Start background tasks
    asyncio.create_task(rotation_loop())
    asyncio.create_task(background_refresh_loop())

    # Start SOCKS5 server
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
