#!/bin/bash
# ════════════════════════════════════════════════════════════════
# package-manifest.sh — Track & reinstall CLI tools across restarts
# ════════════════════════════════════════════════════════════════
# HF Spaces are ephemeral Docker containers — anything you install
# (apt, npm -g, pip) is lost on restart.
#
# This script saves a manifest of your installed packages into
# ~/.openclaw/ which is automatically backed up to HF Dataset.
# On restart, it reinstalls any missing packages.
#
# Usage:
#   package-manifest.sh save     — save current packages to manifest
#   package-manifest.sh restore  — reinstall packages from manifest
# ════════════════════════════════════════════════════════════════

MANIFEST="/home/node/.openclaw/package-manifest.json"

save() {
  echo "📦 Saving package manifest..."
  mkdir -p "$(dirname "$MANIFEST")"
  
  python3 << 'PYEOF'
import json, subprocess, sys

manifest = {}

# 1. APT packages (manually installed / explicitly marked)
try:
    r = subprocess.run(["apt", "list", "--installed", "2>/dev/null"],
                       capture_output=True, text=True, timeout=30)
    # Filter user-installed: those NOT in auto-installed or base system
    apt_pkgs = []
    for line in r.stdout.splitlines():
        if "/" not in line:
            continue
        pkg = line.split("/")[0]
        # Skip lib*, kernel*, base-files, etc.
        if pkg.startswith(("lib", "linux-", "python3-", "node", "perl", "ruby")):
            continue
        apt_pkgs.append(pkg)
    manifest["apt"] = sorted(apt_pkgs)
except Exception as e:
    print(f"  Warning: apt scan failed: {e}", file=sys.stderr)
    manifest["apt"] = []

# 2. npm global packages
try:
    r = subprocess.run(["npm", "list", "-g", "--depth=0", "--json"],
                       capture_output=True, text=True, timeout=15)
    data = json.loads(r.stdout)
    deps = data.get("dependencies", {})
    npm_pkgs = [k for k, v in deps.items() if not v.get("extraneous")]
    manifest["npm"] = sorted(npm_pkgs)
except Exception as e:
    print(f"  Warning: npm scan failed: {e}", file=sys.stderr)
    manifest["npm"] = []

# 3. pip packages
try:
    r = subprocess.run(["pip", "list", "--format=json"],
                       capture_output=True, text=True, timeout=15)
    pip_pkgs = [p["name"] for p in json.loads(r.stdout)]
    manifest["pip"] = sorted(pip_pkgs)
except Exception as e:
    print(f"  Warning: pip scan failed: {e}", file=sys.stderr)
    manifest["pip"] = []

with open("/home/node/.openclaw/package-manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

print(f"  ✅ Saved {len(manifest['apt'])} apt, {len(manifest['npm'])} npm, {len(manifest['pip'])} pip packages")
PYEOF
}

restore() {
  if [ ! -f "$MANIFEST" ]; then
    echo "📋 No package manifest found."
    echo "   Install your tools, then run: package-manifest.sh save"
    echo "   On next restart they'll be restored automatically."
    return 0
  fi
  
  echo "📦 Restoring packages from manifest..."
  
  python3 << 'PYEOF'
import json, subprocess, sys, os

manifest_path = "/home/node/.openclaw/package-manifest.json"
try:
    with open(manifest_path) as f:
        manifest = json.load(f)
except Exception as e:
    print(f"  Error reading manifest: {e}")
    sys.exit(1)

total_installed = 0

# 1. APT packages
apt_pkgs = manifest.get("apt", [])
if apt_pkgs:
    missing = []
    try:
        r = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=15)
        installed = set()
        for line in r.stdout.splitlines():
            if line.startswith("ii "):
                installed.add(line.split()[1])
        for pkg in apt_pkgs:
            if pkg not in installed:
                missing.append(pkg)
    except:
        missing = apt_pkgs
    
    if missing:
        print(f"  Installing apt packages: {' '.join(missing)}")
        try:
            subprocess.run(["sudo", "apt-get", "update", "-qq"], check=True, timeout=60)
            subprocess.run(["sudo", "apt-get", "install", "-y", "-qq"] + missing, check=True, timeout=120)
            print(f"  ✅ Installed {len(missing)} apt packages")
            total_installed += len(missing)
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  apt install failed: {e}")
    else:
        print(f"  ✅ All {len(apt_pkgs)} apt packages already present")
else:
    print(f"  ℹ️  No apt packages in manifest")

# 2. npm global packages
npm_pkgs = manifest.get("npm", [])
if npm_pkgs:
    missing = []
    try:
        r = subprocess.run(["npm", "list", "-g", "--depth=0", "--json"],
                          capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout)
        installed = set(data.get("dependencies", {}).keys())
        for pkg in npm_pkgs:
            if pkg not in installed:
                missing.append(pkg)
    except:
        missing = npm_pkgs
    
    if missing:
        print(f"  Installing npm global packages: {' '.join(missing)}")
        try:
            subprocess.run(["npm", "install", "-g"] + missing, check=True, timeout=120)
            print(f"  ✅ Installed {len(missing)} npm packages")
            total_installed += len(missing)
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  npm install failed: {e}")
    else:
        print(f"  ✅ All {len(npm_pkgs)} npm packages already present")
else:
    print(f"  ℹ️  No npm packages in manifest")

# 3. pip packages
pip_pkgs = manifest.get("pip", [])
if pip_pkgs:
    missing = []
    try:
        r = subprocess.run(["pip", "list", "--format=json"],
                          capture_output=True, text=True, timeout=15)
        installed = {p["name"].lower() for p in json.loads(r.stdout)}
        for pkg in pip_pkgs:
            if pkg.lower() not in installed and pkg.lower().replace("-", "_") not in installed:
                missing.append(pkg)
    except:
        missing = pip_pkgs
    
    if missing:
        print(f"  Installing pip packages: {' '.join(missing)}")
        try:
            pip_cmd = ["pip", "install"]
            subprocess.run(pip_cmd + missing, check=False, timeout=120)
            subprocess.run(pip_cmd + ["--break-system-packages"] + missing, check=False, timeout=120)
            print(f"  ✅ Installed {len(missing)} pip packages")
            total_installed += len(missing)
        except:
            print(f"  ⚠️  Some pip packages may have failed")
else:
    print(f"  ℹ️  No pip packages in manifest")

if total_installed > 0:
    print(f"\n  ✅ Restored {total_installed} package(s)")
else:
    print(f"\n  ✅ All packages already present, nothing to restore")
PYEOF
}

case "${1:-}" in
  save)
    save
    ;;
  restore)
    restore
    ;;
  *)
    echo "Usage: $0 {save|restore}"
    echo ""
    echo "  save     - Save current installed packages to manifest"
    echo "             (manifest is auto-backed up to HF Dataset)"
    echo "  restore  - Reinstall packages from manifest"
    echo ""
    echo "First time:"
    echo "  1. Install your tools:  sudo apt install gh"
    echo "  2. Save manifest:       $0 save"
    echo "  3. On next restart, packages restore automatically"
    exit 1
    ;;
esac
