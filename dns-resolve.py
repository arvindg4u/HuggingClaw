#!/usr/bin/env python3
"""
DNS-over-HTTPS resolver for HF Spaces.

Resolves WhatsApp + Telegram domains via multiple DoH providers and writes
results to /etc/hosts (for undici/fetch) and /tmp/dns-resolved.json
(for dns-fix.cjs's dns.lookup patch).

This runs at container startup before OpenClaw starts.
"""
import json
import os
import ssl
import sys
import urllib.request
import socket

# Multiple DoH endpoints for redundancy
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://1.1.1.1/dns-query",
    "https://dns.google/dns-query",
    "https://8.8.8.8/dns-query",
]

# Domains that WhatsApp/Baileys and Telegram/grammY need
DOMAINS = [
    # WhatsApp Web (Baileys)
    "web.whatsapp.com",
    "wss.web.whatsapp.com",
    "g.whatsapp.net",
    "mmg.whatsapp.net",
    "pps.whatsapp.net",
    "static.whatsapp.net",
    "media.fmed1-1.fna.whatsapp.net",
    "media.fmed2-1.fna.whatsapp.net",
    # Telegram Bot API
    "api.telegram.org",
]

# Hardcoded fallback IPs when DoH fails entirely
FALLBACK_IPS = {
    "web.whatsapp.com": "157.240.221.52",
    "wss.web.whatsapp.com": "157.240.221.52",
    "g.whatsapp.net": "31.13.66.51",
    "mmg.whatsapp.net": "31.13.66.56",
    "pps.whatsapp.net": "57.145.3.32",
    "static.whatsapp.net": "57.144.75.32",
    "api.telegram.org": "149.154.167.220",
}


def resolve_via_doh(domain: str, endpoint: str, timeout: int = 8) -> str | None:
    """Resolve a domain via DNS-over-HTTPS, return first IPv4 address."""
    url = f"{endpoint}?name={domain}&type=A"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = json.loads(r.read().decode())
            for a in data.get("Answer", []):
                if a.get("type") == 1:  # A record
                    return a["data"]
    except Exception:
        return None
    return None


def resolve_domain(domain: str) -> str | None:
    """Try multiple DoH endpoints until one succeeds."""
    for endpoint in DOH_ENDPOINTS:
        ip = resolve_via_doh(domain, endpoint)
        if ip:
            return ip
    return None


def test_system_dns():
    """Check if system DNS can resolve critical domains at all."""
    for domain in ["web.whatsapp.com", "api.telegram.org"]:
        try:
            socket.getaddrinfo(domain, 443, socket.AF_INET)
            return True
        except (socket.gaierror, OSError):
            continue
    return False


def main() -> None:
    output_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/dns-resolved.json"

    # Quick check: if system DNS works, no DoH needed
    if test_system_dns():
        print("[dns-resolve] System DNS works — DoH pre-resolution not needed")
        # Still write empty file so consumers know we ran
        with open(output_file, "w") as f:
            json.dump({}, f)
        return

    print("[dns-resolve] System DNS blocked — resolving via DoH...")

    results = {}
    # Try DoH first
    for domain in DOMAINS:
        ip = resolve_domain(domain)
        if ip:
            results[domain] = ip
            print(f"  [dns-resolve] {domain} -> {ip} (DoH)")
        else:
            print(f"  [dns-resolve] {domain} -> DoH FAILED")

    # Fall back to hardcoded IPs for any domains that DoH couldn't resolve
    for domain, ip in FALLBACK_IPS.items():
        if domain not in results:
            results[domain] = ip
            print(f"  [dns-resolve] {domain} -> {ip} (hardcoded fallback)")

    # Write to /etc/hosts — this benefits undici/fetch (Telegram) and
    # any process that reads /etc/hosts directly
    if results:
        try:
            with open("/etc/hosts", "a") as f:
                f.write("\n# === HuggingClaw DoH resolved domains ===\n")
                for domain, ip in results.items():
                    f.write(f"{ip} {domain}\n")
            print(f"[dns-resolve] Wrote {len(results)} entries to /etc/hosts")
        except PermissionError:
            print("[dns-resolve] WARNING: Cannot write /etc/hosts")

    # Write JSON for dns-fix.cjs (dns.lookup patch) to consume
    with open(output_file, "w") as f:
        json.dump(results, f)

    print(f"[dns-resolve] Done — {len(results)} domains resolved")


if __name__ == "__main__":
    main()
