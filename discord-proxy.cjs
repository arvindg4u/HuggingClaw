/**
 * Discord proxy preload script for HF Spaces.
 *
 * HF Spaces blocks outbound connections to discord.com.
 * This script intercepts:
 *   1. globalThis.fetch() for Discord HTTP API calls → routes through Render proxy
 *   2. https.request() for Discord REST API (discord.js uses it) → routes through Render proxy
 *
 * DISCORD_PROXY_BASE env var controls the target (set by start.sh).
 * WebSocket gateway (gateway.discord.gg) is handled by cloudflare-proxy.js
 * via ROUTE_TARGETS when DISCORD_BOT_TOKEN is set.
 *
 * Loaded via: NODE_OPTIONS="--require /path/to/discord-proxy.cjs"
 */
'use strict';

const PROXY_BASE = (process.env.DISCORD_PROXY_BASE || '').replace(/\/+$/, '');

const DISCORD_DOMAINS = [
  'discord.com',
  'cdn.discord.com',
  'cdn.discordapp.com',
  'media.discordapp.net',
  'discord.gg',
];

function isDiscordDomain(hostname) {
  if (!hostname) return false;
  const hn = hostname.toLowerCase().replace(/^wss?:\/\//, '').split('/')[0];
  return DISCORD_DOMAINS.some(d => hn === d || hn.endsWith('.' + d));
}

if (!PROXY_BASE) {
  console.log('[discord-proxy] Loaded (no proxy configured — DISCORD_PROXY_BASE not set)');
  module.exports = {};
  return;
}

const proxyUrl = new URL(PROXY_BASE);
const proxyHost = proxyUrl.hostname;
const proxyOrigin = proxyUrl.origin;
const proxyBasePath = proxyUrl.pathname.replace(/\/+$/, '');

let logged = false;
function logOnce(msg) {
  if (!logged) { console.log(`[discord-proxy] ${msg}`); logged = true; }
}

console.log(`[discord-proxy] Active: discord.com → ${proxyHost}${proxyBasePath}`);

// ── Helper: rewrite a Discord URL to the Render proxy ──────────────────
function rewriteUrl(urlStr) {
  return urlStr.replace(
    /https?:\/\/(?:[^.]+\.)*(?:discord\.com|discordapp\.net|discord\.gg)(?::\d+)?/i,
    proxyOrigin + proxyBasePath
  );
}

// ── 1. Patch globalThis.fetch() for Discord API calls ─────────────────────
const originalFetch = globalThis.fetch;
globalThis.fetch = function patchedDiscordFetch(input, init) {
  let urlStr;
  if (typeof input === 'string') urlStr = input;
  else if (input instanceof URL) urlStr = input.toString();
  else if (input && typeof input === 'object' && input.url) urlStr = input.url;
  else return originalFetch.call(this, input, init);

  try {
    const parsed = new URL(urlStr);
    if (!isDiscordDomain(parsed.hostname)) {
      return originalFetch.call(this, input, init);
    }
    logOnce(`fetch → ${proxyHost}${proxyBasePath} (dc: ${parsed.hostname}${parsed.pathname})`);
    const newUrl = rewriteUrl(urlStr);
    const headers = new Headers((input instanceof Request ? input.headers : (init?.headers || {})));
    headers.set('x-target-host', parsed.hostname);
    headers.set('x-hc', 'true');
    const newInit = {
      method: (input instanceof Request ? input.method : init?.method) || 'GET',
      headers,
      body: (input instanceof Request ? input.body : init?.body) || undefined,
      redirect: 'follow',
    };
    if (typeof input === 'string') return originalFetch.call(this, newUrl, newInit);
    return originalFetch.call(this, new Request(newUrl, newInit));
  } catch {
    return originalFetch.call(this, input, init);
  }
};

// ── 2. Patch https.request for Discord REST API calls ──────────────────
// Discord.js (used by OpenClaw Discord plugin) makes REST API calls via
// https.request. We intercept these and route through Render proxy.
const https = require('https');
const origHttpsRequest = https.request;

https.request = function patchedDiscordHttpsRequest(...args) {
  let opts, cb;
  if (typeof args[0] === 'string' || args[0] instanceof URL) {
    const u = typeof args[0] === 'string' ? new URL(args[0]) : args[0];
    opts = { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET', headers: {} };
    if (typeof args[1] === 'object' && args[1]) { Object.assign(opts, args[1]); cb = args[2]; }
    else { cb = args[1]; }
  } else { opts = { ...args[0] }; cb = args[1]; }

  const hn = opts.hostname || (opts.host ? String(opts.host).split(':')[0] : '');
  if (!hn || opts._dc_proxied || !isDiscordDomain(hn)) {
    return origHttpsRequest.call(this, ...args);
  }

  logOnce(`https.request → ${proxyHost}${proxyBasePath} (dc: ${hn}${opts.path || ''})`);

  // Route through Render proxy: add /discord prefix to path
  const origPath = opts.path || '/';
  const newPath = proxyBasePath + origPath;

  const nopts = {
    ...opts,
    _dc_proxied: true,
    hostname: proxyHost,
    host: proxyHost,
    port: parseInt(proxyUrl.port) || 443,
    path: newPath,
    headers: {
      ...(opts.headers || {}),
      'x-target-host': hn,
      'x-hc': 'true',
    },
  };
  if (nopts.headers.host) nopts.headers.host = proxyHost;

  return origHttpsRequest.call(this, nopts, cb);
};

module.exports = {};
