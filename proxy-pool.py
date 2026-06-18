#!/usr/bin/env python3
"""
HuggingClaw Proxy Pool — Self-Rotating SOCKS5 Proxy Pool

Fetches free SOCKS5 proxies from public proxy lists, verifies them,
and runs a local SOCKS5 server that automatically rotates upstream proxies.

Features:
- Fetches fresh proxy list every 10 minutes from proxifly
- Tests each proxy before adding to pool
- Auto-rotates upstream proxy every 8-12 minutes
- Auto-failover on connection errors
- No external dependencies (uses asyncio + built-in modules)
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

logging.basicConfig(
    level=logging.INFO,
    format="[proxy-pool] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("proxy-pool")

# ── Configuration ──
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9050
ROTATE_INTERVAL = 600  # 10 minutes (600 seconds)
FAILOVER_RETRIES = 3
PROXY_REFRESH_INTERVAL = 600  # Refresh proxy list every 10 min
CONNECT_TIMEOUT = 10  # Seconds to wait for proxy connection test
PROXY_TEST_URL = "http://httpbin.org/ip"
PROXY_SOURCES = [
    # proxifly SOCKS5 list (raw text, ip:port per line)
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    # Alternative: proxyscrape SOCKS5
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
]

# ── Proxy Pool State ──
proxy_pool = []
current_proxy_index = 0
current_proxy = None  # (host, port)
last_rotation_time = 0
pool_lock = asyncio.Lock()
stats = {
    "fetched": 0,
    "working": 0,
    "failed": 0,
    "rotations": 0,
    "current_ip": "unknown",
}

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
    log.info(f"Fetched {len(all_proxies)} unique proxies from sources")
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
                
                # SOCKS5 handshake: no auth
                s.sendall(bytes([0x05, 0x01, 0x00]))
                resp = s.recv(2)
                if resp != bytes([0x05, 0x00]):
                    s.close()
                    return False
                
                # Connection test to a known host
                test_host = "httpbin.org"
                test_port = 80
                hbuf = test_host.encode()
                req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + struct.pack(">H", test_port)
                s.sendall(req)
                resp = s.recv(4)
                if len(resp) < 4 or resp[1] != 0x00:
                    s.close()
                    return False
                
                s.close()
                return True
            except Exception:
                return False
        
        result = await loop.run_in_executor(None, _test)
        return result
    except Exception:
        return False

async def refresh_pool():
    """Refresh the proxy pool with fresh proxies."""
    global proxy_pool
    
    log.info("Refreshing proxy pool...")
    proxies = fetch_proxy_list()
    
    if not proxies:
        log.warning("No proxies fetched, keeping existing pool")
        return
    
    # Test proxies concurrently (limit to 20 at a time)
    log.info(f"Testing {len(proxies)} proxies (this may take a moment)...")
    working = []
    batch_size = 20
    
    for i in range(0, len(proxies), batch_size):
        batch = proxies[i:i+batch_size]
        tasks = [test_proxy(h, p) for h, p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for (host, port), ok in zip(batch, results):
            if ok:
                working.append((host, port))
    
    stats["working"] = len(working)
    log.info(f"Found {len(working)} working proxies out of {len(proxies)}")
    
    if working:
        async with pool_lock:
            proxy_pool = working
            # Reset current index to get a fresh proxy
            global current_proxy_index, current_proxy
            current_proxy_index = random.randint(0, len(proxy_pool) - 1)
            current_proxy = proxy_pool[current_proxy_index]
            stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
            log.info(f"Initial proxy: {current_proxy[0]}:{current_proxy[1]}")

def rotate_proxy():
    """Rotate to the next working proxy."""
    global current_proxy_index, current_proxy, last_rotation_time
    
    if not proxy_pool:
        log.warning("No proxies in pool to rotate")
        return False
    
    old = current_proxy
    current_proxy_index = (current_proxy_index + 1) % len(proxy_pool)
    current_proxy = proxy_pool[current_proxy_index]
    last_rotation_time = time.time()
    stats["rotations"] += 1
    stats["current_ip"] = f"{current_proxy[0]}:{current_proxy[1]}"
    log.info(f"Rotated proxy: {old} → {current_proxy[0]}:{current_proxy[1]}")
    return True

async def rotation_loop():
    """Background task that rotates the proxy every ROTATE_INTERVAL seconds."""
    global last_rotation_time
    last_rotation_time = time.time()
    
    while True:
        await asyncio.sleep(ROTATE_INTERVAL)
        async with pool_lock:
            rotate_proxy()

async def refresh_loop():
    """Background task that refreshes the proxy pool every PROXY_REFRESH_INTERVAL."""
    while True:
        await asyncio.sleep(PROXY_REFRESH_INTERVAL)
        try:
            await refresh_pool()
        except Exception as e:
            log.error(f"Pool refresh failed: {e}")

# ── SOCKS5 Server ──

async def socks5_handler(reader, writer):
    """Handle an incoming SOCKS5 connection."""
    global current_proxy, current_proxy_index
    
    try:
        # Read SOCKS5 greeting
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if data[0] != 0x05:
            writer.close()
            return
        
        # We only support no-auth (0x00)
        writer.write(bytes([0x05, 0x00]))
        await writer.drain()
        
        # Read request
        data = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        if data[0] != 0x05 or data[1] != 0x01:
            writer.write(bytes([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
            await writer.drain()
            writer.close()
            return
        
        atype = data[3]
        if atype == 0x01:  # IPv4
            data = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            target_host = str(ipaddress.IPv4Address(data))
        elif atype == 0x03:  # Domain name
            data = await asyncio.wait_for(reader.readexactly(1), timeout=10)
            dlen = data[0]
            data = await asyncio.wait_for(reader.readexactly(dlen), timeout=10)
            target_host = data.decode()
        elif atype == 0x04:  # IPv6
            data = await asyncio.wait_for(reader.readexactly(16), timeout=10)
            target_host = str(ipaddress.IPv6Address(data))
        else:
            writer.close()
            return
        
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        target_port = struct.unpack(">H", data)[0]
        
        # Get current upstream proxy
        async with pool_lock:
            upstream = current_proxy
        
        if not upstream:
            # No proxy available, try direct connection
            log.warning("No upstream proxy — trying direct connection")
            try:
                upstream_sock = socket.create_connection(
                    (target_host, target_port), timeout=CONNECT_TIMEOUT
                )
                # SOCKS5 success response
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
                            data = await loop.run_in_executor(
                                None, upstream_sock.recv, 65536
                            )
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
            except Exception as e:
                log.error(f"Direct connect failed: {e}")
                writer.close()
            return
        
        # Connect through upstream SOCKS5 proxy
        upstream_host, upstream_port = upstream
        
        try:
            upstream_sock = socket.create_connection(
                (upstream_host, upstream_port), timeout=CONNECT_TIMEOUT
            )
            
            # SOCKS5 handshake with upstream
            upstream_sock.sendall(bytes([0x05, 0x01, 0x00]))
            resp = upstream_sock.recv(2)
            if resp != bytes([0x05, 0x00]):
                # Auth failed, rotate proxy
                upstream_sock.close()
                async with pool_lock:
                    stats["failed"] += 1
                    if not rotate_proxy():
                        raise Exception("No proxy available")
                writer.close()
                return
            
            # Connect request to target
            hbuf = target_host.encode()
            req = bytes([0x05, 0x01, 0x00, 0x03, len(hbuf)]) + hbuf + struct.pack(">H", target_port)
            upstream_sock.sendall(req)
            
            # Read response
            resp_data = upstream_sock.recv(4)
            if len(resp_data) < 4 or resp_data[1] != 0x00:
                # Upstream proxy failed to connect, rotate
                upstream_sock.close()
                async with pool_lock:
                    stats["failed"] += 1
                    log.warning(f"Upstream proxy {upstream_host}:{upstream_port} failed to connect to {target_host}")
                    if not rotate_proxy():
                        raise Exception("No proxy available")
                writer.close()
                return
            
            # Read remaining response based on BND.ATYPE
            atyp = resp_data[3]
            if atyp == 0x01:
                await asyncio.wait_for(reader.readexactly(6), timeout=5)
            elif atyp == 0x03:
                dlen_data = upstream_sock.recv(1)
                dlen = dlen_data[0] if dlen_data else 0
                upstream_sock.recv(dlen + 2)
            elif atyp == 0x04:
                await asyncio.wait_for(reader.readexactly(18), timeout=5)
            
            # Send success response to client
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
                        data = await loop.run_in_executor(
                            None, upstream_sock.recv, 65536
                        )
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
            
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as e:
            log.warning(f"Upstream proxy {upstream_host}:{upstream_port} failed: {e}")
            async with pool_lock:
                stats["failed"] += 1
                # Remove failed proxy from pool
                if (upstream_host, upstream_port) in proxy_pool:
                    proxy_pool.remove((upstream_host, upstream_port))
                rotate_proxy()
            writer.close()
            return
    
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        log.debug(f"Handler error: {e}")
    except Exception as e:
        log.debug(f"Handler exception: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def main():
    log.info("=" * 50)
    log.info("  HuggingClaw Proxy Pool Starting...")
    log.info(f"  Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"  Rotating upstream every {ROTATE_INTERVAL}s")
    log.info(f"  Refreshing pool every {PROXY_REFRESH_INTERVAL}s")
    log.info("=" * 50)
    
    # Initial proxy fetch
    try:
        await refresh_pool()
    except Exception as e:
        log.warning(f"Initial proxy fetch failed: {e}")
        log.warning("Will retry in background...")
    
    # Start background tasks
    asyncio.create_task(rotation_loop())
    asyncio.create_task(refresh_loop())
    
    # Start SOCKS5 server
    server = await asyncio.start_server(
        socks5_handler, LISTEN_HOST, LISTEN_PORT
    )
    
    addr = server.sockets[0].getsockname()
    log.info(f"SOCKS5 proxy pool ready on {addr[0]}:{addr[1]}")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down...")
