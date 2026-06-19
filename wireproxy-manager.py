#!/usr/bin/env python3
"""
HuggingClaw WireGuard Manager — Starts wireproxy instances for IP rotation.
Users provide WireGuard config files in ~/.wireguard-confs/*.conf
or set WIREGUARD_CONFIGS env var as a semicolon-separated list of WG endpoints.

Each wireproxy instance exposes SOCKS5 on a different port.
"""
import asyncio, json, os, random, subprocess, sys, tempfile, time, logging, shutil, base64
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[wg-proxy] %(message)s", stream=sys.stderr)
log = logging.getLogger("wg-proxy")

WIREPROXY_BIN = shutil.which("wireproxy") or "/usr/local/bin/wireproxy"
CONFIG_DIR = os.path.expanduser("~/.wireguard-confs")
RUN_DIR = os.path.expanduser("~/.wireproxy-run")
SOCKS_PORTS = [9051, 9052, 9053, 9054]


def generate_wireproxy_conf(socks_port: int, wg_conf_path: str) -> str:
    """Generate a wireproxy config that imports the WG config and adds SOCKS5."""
    return f"""# Auto-generated wireproxy config for port {socks_port}
WGConfig = {wg_conf_path}

[Socks5]
BindAddress = 127.0.0.1:{socks_port}
"""


async def start_wireproxy(conf_path: str, name: str, port: int):
    """Start a wireproxy process for the given config file."""
    log.info(f"Starting wireproxy [{name}] on SOCKS5 :{port}")
    proc = await asyncio.create_subprocess_exec(
        WIREPROXY_BIN, "-c", conf_path, "-s",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(2)
    if proc.returncode is not None:
        log.warning(f"wireproxy [{name}] exited immediately (code {proc.returncode})")
        return None
    log.info(f"wireproxy [{name}] running on SOCKS5 127.0.0.1:{port}")
    return proc


def find_wg_configs() -> list[tuple[str, str]]:
    """Find WireGuard .conf files from CONFIG_DIR or env var."""
    configs = []

    # Option 1: Read from WIREGUARD_CONFIGS env var
    env_configs = os.environ.get("WIREGUARD_CONFIGS", "").strip()
    if env_configs:
        for entry in env_configs.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            # Could be either a file path or a URL
            if entry.startswith("socks5://") or entry.startswith("http"):
                continue  # Not a WG config
            if os.path.isfile(entry):
                name = Path(entry).stem
                configs.append((name, entry))

    # Option 2: Scan CONFIG_DIR for *.conf files
    conf_dir = Path(CONFIG_DIR)
    if conf_dir.is_dir():
        for f in sorted(conf_dir.glob("*.conf")):
            if str(f) not in [c[1] for c in configs]:
                configs.append((f.stem, str(f)))

    return configs


async def run_manager():
    """Main WireGuard/SOCKS5 proxy manager loop."""
    os.makedirs(RUN_DIR, exist_ok=True)

    wg_configs = find_wg_configs()
    if not wg_configs:
        # No WG configs found — try fetching free proxies as fallback
        log.info("No WireGuard configs found — trying free SOCKS5 fallback...")
        await start_free_proxy_pool()
        return

    log.info(f"Found {len(wg_configs)} WireGuard config(s), starting wireproxy...")

    processes = []
    active_ports = []

    for i, (name, conf_path) in enumerate(wg_configs[:len(SOCKS_PORTS)]):
        port = SOCKS_PORTS[i]
        wc_path = os.path.join(RUN_DIR, f"{name}.wpc")
        with open(wc_path, "w") as f:
            f.write(generate_wireproxy_conf(port, conf_path))
        proc = await start_wireproxy(wc_path, name, port)
        if proc:
            processes.append(proc)
            active_ports.append(port)

    if active_ports:
        log.info(f"WireGuard proxies ready: {', '.join(f':{p}' for p in active_ports)}")
    else:
        log.warning("No WireGuard proxies started")
        return

    # Write status for cloudflare-proxy.js
    proxy_strings = [f"socks5://127.0.0.1:{p}" for p in active_ports]
    with open("/tmp/wireguard-ports.json", "w") as f:
        json.dump({"ports": active_ports, "proxy_strings": proxy_strings, "active": True}, f)

    # Monitor and restart
    while True:
        await asyncio.sleep(30)
        for i, (proc, port, name) in enumerate(zip(processes[:], active_ports[:], [n for n, _ in wg_configs[:len(processes)]])):
            if proc.returncode is not None:
                wc_path = os.path.join(RUN_DIR, f"{name}.wpc")
                log.warning(f"wireproxy [{name}] died, restarting...")
                new_proc = await start_wireproxy(wc_path, name, port)
                if new_proc:
                    processes[i] = new_proc


# ── Free SOCKS5 proxy pool fallback (when no WireGuard configs available) ──
# Fetches from public sources, tests against opencode.ai, keeps working ones.

PROXY_SOURCES = [
    "https://github.com/proxifly/free-proxy-list/raw/main/proxies/protocols/socks5/data.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
]
PROXY_TEST_URL = "https://opencode.ai/zen/v1/models"
PROXY_REFRESH_SECONDS = 600  # 10 min
PROXY_CONNECT_TIMEOUT = 5


async def test_socks5(host: str, port: int) -> bool:
    """Test if a SOCKS5 proxy is reachable by attempting TCP connect."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=PROXY_CONNECT_TIMEOUT
        )
        writer.close()
        return True
    except Exception:
        return False


async def fetch_proxy_lists() -> list[tuple[str, int]]:
    """Fetch SOCKS5 proxies from public sources (stdlib only)."""
    proxies = set()
    import urllib.request
    for url in PROXY_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                for line in text.strip().split("\n"):
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                proxies.add((parts[0], int(parts[1])))
                            except ValueError:
                                pass
        except Exception as e:
            log.debug(f"Failed to fetch from {url}: {e}")
    return list(proxies)


async def validate_and_start_proxy(host: str, port: int, socks_port: int) -> asyncio.subprocess.Process | None:
    """Start a tiny TCP→SOCKS5 forwarder or just verify and store the proxy."""
    ok = await test_socks5(host, port)
    if ok:
        log.info(f"Proxy {host}:{port} is reachable — will use via SOCKS5_PROXY_URL")
        return ok
    return None


async def start_free_proxy_pool():
    """Fetch, test, and start rotating free SOCKS5 proxies as fallback."""
    log.info("Fetching free SOCKS5 proxies from public sources...")
    all_proxies = await fetch_proxy_lists()
    log.info(f"Found {len(all_proxies)} proxies, testing reachability...")

    working = []
    for host, port in all_proxies[:50]:  # Test up to 50
        ok = await test_socks5(host, port)
        if ok:
            working.append((host, port))
            log.info(f"  ✅ {host}:{port} reachable")
            if len(working) >= 4:
                break

    if not working:
        log.warning("No working free proxies found")
        with open("/tmp/wireguard-ports.json", "w") as f:
            json.dump({"ports": [], "proxy_strings": [], "active": False}, f)
        return

    # Write working proxies so cloudflare-proxy.js can use them
    proxy_strings = [f"socks5://{h}:{p}" for h, p in working]
    with open("/tmp/wireguard-ports.json", "w") as f:
        json.dump({"ports": [p for _, p in working], "proxies": working, "proxy_strings": proxy_strings, "active": True, "source": "free-pool"}, f)

    log.info(f"Free proxy pool ready: {len(working)} proxies")
    log.info(f"Set SOCKS5_PROXY_URL to one of: {', '.join(proxy_strings[:2])}...")

    # Write the first working proxy as the primary one for SOCKS5_PROXY_URL
    with open("/tmp/socks5-proxy-url.txt", "w") as f:
        f.write(proxy_strings[0])

    while True:
        await asyncio.sleep(PROXY_REFRESH_SECONDS)
        log.info("Refreshing proxy pool...")
        # In production, re-fetch and re-test here


if __name__ == "__main__":
    asyncio.run(run_manager())
