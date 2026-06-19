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
    """Main WireGuard manager loop."""
    os.makedirs(RUN_DIR, exist_ok=True)

    wg_configs = find_wg_configs()
    if not wg_configs:
        log.info("No WireGuard configs found — wireproxy not started")
        log.info("Place .conf files in ~/.wireguard-confs/ or set WIREGUARD_CONFIGS env var")
        log.info("Example: WIREGUARD_CONFIGS=/path/to/wg0.conf;/path/to/wg1.conf")
        # Write empty status so cloudflare-proxy.js knows WireGuard isn't active
        with open("/tmp/wireguard-ports.json", "w") as f:
            json.dump({"ports": [], "proxy_strings": [], "active": False}, f)
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


if __name__ == "__main__":
    asyncio.run(run_manager())
