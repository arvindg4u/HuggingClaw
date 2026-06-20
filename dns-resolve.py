#!/usr/bin/env python3
"""
DNS-over-HTTPS resolver for HF Spaces.
Resolves WhatsApp + Telegram domains and writes to /etc/hosts + JSON file.
"""
import json, os, ssl, sys, urllib.request, socket, struct

DOH = "https://cloudflare-dns.com/dns-query"
DOMAINS = [
    "web.whatsapp.com", "wss.web.whatsapp.com",
    "g.whatsapp.net", "mmg.whatsapp.net",
    "pps.whatsapp.net", "static.whatsapp.net",
    "api.telegram.org",
]

def resolve(domain):
    url = f"{DOH}?name={domain}&type=A"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as r:
            data = json.loads(r.read())
            for a in data.get("Answer", []):
                if a.get("type") == 1:
                    return a["data"]
    except: pass
    return None

def main():
    results = {}

    # First test if system DNS works
    for d in DOMAINS[:1]:
        try:
            socket.getaddrinfo(d, 443, socket.AF_INET)
            print(f"[dns-resolve] System DNS works for {d}")
        except socket.gaierror:
            print(f"[dns-resolve] System DNS FAILED for {d} — using DoH")

    print("[dns-resolve] Resolving domains via Cloudflare DoH...")
    for domain in DOMAINS:
        ip = resolve(domain)
        if ip:
            results[domain] = ip
            print(f"  {domain} -> {ip}")
        else:
            print(f"  {domain} -> FAILED")

    # Write to /etc/hosts (needed for fetch/undici which bypass dns.lookup)
    if results:
        try:
            hosts_entry = "\n# HuggingClaw DoH resolved\n"
            for domain, ip in results.items():
                hosts_entry += f"{ip} {domain}\n"
            with open("/etc/hosts", "a") as f:
                f.write(hosts_entry)
            print(f"[dns-resolve] Wrote {len(results)} entries to /etc/hosts")
        except PermissionError:
            print("[dns-resolve] Cannot write /etc/hosts (will use dns.lookup patch)")

    # Write JSON for cloudflare-proxy.js to consume
    with open("/tmp/dns-resolved.json", "w") as f:
        json.dump(results, f)

    print(f"[dns-resolve] Done — {len(results)} domains resolved")

if __name__ == "__main__":
    main()
