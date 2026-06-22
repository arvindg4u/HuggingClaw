/**
 * Telegram API proxy preload script for HF Spaces.
 *
 * HF Spaces blocks DNS for api.telegram.org.  OpenClaw's Telegram plugin
 * uses grammY which relies on Node 22's built-in fetch (undici).  undici
 * does its own DNS resolution — it ignores /etc/hosts AND dns.lookup
 * monkey-patches.
 *
 * The only reliable fix: intercept globalThis.fetch() and rewrite
 * api.telegram.org URLs to a reachable endpoint.
 *
 * TELEGRAM_API_BASE env var controls the target.  Set by start.sh after
 * probing reachable endpoints at boot.
 *
 * Loaded via: NODE_OPTIONS="--require /path/to/telegram-proxy.cjs"
 */
'use strict';

const TELEGRAM_API_BASE = (process.env.TELEGRAM_API_BASE || '').replace(/\/+$/, '');
const ORIGINAL_API = 'https://api.telegram.org';

// Nothing to do if TELEGRAM_API_BASE is unset or equals official endpoint
if (TELEGRAM_API_BASE && TELEGRAM_API_BASE.replace(/\/+$/, '') !== ORIGINAL_API) {
  const base = TELEGRAM_API_BASE.replace(/\/+$/, '') + '/';
  const baseHost = (() => { try { return new URL(base).hostname; } catch { return 'mirror'; } })();
  const originalFetch = globalThis.fetch;
  let logged = false;

  globalThis.fetch = function patchedFetch(input, init) {
    let urlStr;
    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      urlStr = input.toString();
    } else if (input && typeof input === 'object' && input.url) {
      urlStr = input.url;
    } else {
      return originalFetch.call(this, input, init);
    }

    if (urlStr.startsWith(ORIGINAL_API + '/')) {
      const newUrl = base + urlStr.slice(ORIGINAL_API.length + 1);
      if (!logged) {
        console.log(`[telegram-proxy] api.telegram.org → ${baseHost}`);
        logged = true;
      }
      if (typeof input === 'string') {
        return originalFetch.call(this, newUrl, init);
      }
      if (input instanceof Request) {
        const newReq = new Request(newUrl, input);
        return originalFetch.call(this, newReq, init);
      }
      return originalFetch.call(this, newUrl, init);
    }

    return originalFetch.call(this, input, init);
  };

  console.log(`[telegram-proxy] Active: api.telegram.org → ${baseHost}`);
} else {
  // Even without a mirror, log that we're loaded
  console.log('[telegram-proxy] Loaded (no mirror configured)');
}
