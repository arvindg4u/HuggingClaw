/**
 * Discord proxy preload script for HF Spaces.
 *
 * HF Spaces blocks outbound connections to discord.com.
 * This script intercepts globalThis.fetch() for Discord API calls
 * and routes them through the Render proxy.
 *
 * DISCORD_PROXY_BASE env var controls the target (set by start.sh).
 * Loaded via: NODE_OPTIONS="--require /path/to/discord-proxy.cjs"
 */
'use strict';

const PROXY_BASE = (process.env.DISCORD_PROXY_BASE || '').replace(/\/+$/, '');

function isDiscordApi(url) {
  if (!url) return false;
  const hostname = typeof url === 'string' ? url : (url.hostname || '');
  return hostname === 'discord.com' || hostname.endsWith('.discord.com');
}

if (!PROXY_BASE) {
  console.log('[discord-proxy] Loaded (no proxy configured — DISCORD_PROXY_BASE not set)');
  module.exports = {};
  return;
}

const proxyUrl = new URL(PROXY_BASE);
console.log('[discord-proxy] Active: discord.com → ' + proxyUrl.hostname);

// ── Patch globalThis.fetch() for Discord API calls ─────────────────────
const originalFetch = globalThis.fetch;
globalThis.fetch = function patchedDiscordFetch(input, init) {
  const reqUrl = typeof input === 'string' ? input : (input?.url || '');
  if (!isDiscordApi(reqUrl)) {
    return originalFetch(input, init);
  }
  // Rewrite discord.com URLs to proxy
  const rewritten = reqUrl.replace(/https?:\/\/discord(\.com)?/i, PROXY_BASE);
  const newInput = typeof input === 'string' ? rewritten : new URL(rewritten);
  return originalFetch(newInput, init);
};

module.exports = {};
