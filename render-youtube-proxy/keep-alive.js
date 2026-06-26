#!/usr/bin/env node
/**
 * Render Keep-Alive Ping
 *
 * Deploy as Render Cron Job (free) to ping the service every 10 min.
 *
 * Render → Cron Job → Settings:
 *   Command: node keep-alive.js
 *   Schedule: */10 * * * *
 *
 * Or run locally:
 *   node keep-alive.js
 */

const TARGET = process.env.PING_URL || "https://render-youtube-proxy.onrender.com/health";

fetch(TARGET)
  .then((r) => r.text())
  .then((body) => {
    console.log(`[keep-alive] ${new Date().toISOString()} — ${TARGET} → ${body}`);
  })
  .catch((err) => {
    console.error(`[keep-alive] ${new Date().toISOString()} — ${TARGET} → FAIL: ${err.message}`);
    process.exit(1);
  });
