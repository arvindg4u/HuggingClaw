/**
 * DNS fix preload script for HF Spaces.
 *
 * HF Spaces containers cannot resolve certain domains (e.g. web.whatsapp.com,
 * api.telegram.org) via the default DNS resolver.  OpenClaw's WhatsApp plugin
 * uses Baileys which relies on standard Node.js dns.lookup — so this patch
 * works for WhatsApp.
 *
 * Strategy:
 *   1. Check pre-resolved domains from /tmp/dns-resolved.json (populated by
 *      dns-resolve.py at startup via DoH).
 *   2. Fall back to DNS-over-HTTPS (Cloudflare 1.1.1.1) for any other
 *      unresolvable domain.
 *
 * Also writes resolved IPs to /etc/hosts so undici/fetch can benefit too
 * (handled by dns-resolve.py, but we also cache in-memory here).
 *
 * Loaded via: NODE_OPTIONS="--require /path/to/dns-fix.cjs"
 */
'use strict';

const dns = require('dns');
const https = require('https');
const fs = require('fs');

// ── Pre-resolved domains (populated by dns-resolve.py) ──
let preResolved = {};
try {
  const raw = fs.readFileSync('/tmp/dns-resolved.json', 'utf8');
  preResolved = JSON.parse(raw);
  const count = Object.keys(preResolved).length;
  if (count > 0) {
    console.log(`[dns-fix] Loaded ${count} pre-resolved domains`);
  }
} catch {
  // File not found — proceed without cache
}

// ── In-memory cache for runtime DoH resolutions ──
const dohCache = new Map(); // hostname -> { ip, expiry }

// ── DNS-over-HTTPS resolver (Cloudflare) ──
function dohResolve(hostname, callback) {
  const cached = dohCache.get(hostname);
  if (cached && cached.expiry > Date.now()) {
    return callback(null, cached.ip, 4);
  }

  const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
  const req = https.get(
    url,
    { headers: { Accept: 'application/dns-json' }, timeout: 10000 },
    (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          const aRecords = (data.Answer || []).filter((a) => a.type === 1);
          if (aRecords.length === 0) {
            return callback(new Error(`DoH: no A record for ${hostname}`));
          }
          const ip = aRecords[0].data;
          const ttl = Math.max((aRecords[0].TTL || 300) * 1000, 60000);
          dohCache.set(hostname, { ip, expiry: Date.now() + ttl });
          callback(null, ip, 4);
        } catch (e) {
          callback(new Error(`DoH parse error: ${e.message}`));
        }
      });
    }
  );
  req.on('error', (e) => callback(new Error(`DoH request failed: ${e.message}`)));
  req.on('timeout', () => { req.destroy(); callback(new Error('DoH timed out')); });
}

// ── Monkey-patch dns.lookup ──
const origLookup = dns.lookup;

dns.lookup = function patchedLookup(hostname, options, callback) {
  // Normalize arguments
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (typeof options === 'number') {
    options = { family: options };
  }
  options = options || {};

  // Skip patching for localhost, IPs, and internal domains
  if (
    !hostname ||
    hostname === 'localhost' ||
    hostname === '0.0.0.0' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ||
    /^::/.test(hostname) ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.startsWith('consul') ||
    hostname.endsWith('.svc.cluster.local')
  ) {
    return origLookup.call(dns, hostname, options, callback);
  }

  // 1) Check pre-resolved cache
  if (preResolved[hostname]) {
    const ip = preResolved[hostname];
    if (options.all) {
      return process.nextTick(() => callback(null, [{ address: ip, family: 4 }]));
    }
    return process.nextTick(() => callback(null, ip, 4));
  }

  // 2) Try system DNS
  origLookup.call(dns, hostname, options, (err, address, family) => {
    if (!err && address) {
      return callback(null, address, family);
    }

    // 3) System DNS failed — fall back to DoH
    if (err && (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN')) {
      dohResolve(hostname, (dohErr, ip) => {
        if (dohErr || !ip) {
          return callback(err); // Return original error
        }
        if (options.all) {
          return callback(null, [{ address: ip, family: 4 }]);
        }
        callback(null, ip, 4);
      });
    } else {
      callback(err, address, family);
    }
  });
};

console.log('[dns-fix] Active — DoH fallback enabled for WhatsApp & other domains');
