/**
 * MCP YouTube Transcript Server
 *
 * Two modes:
 * 1. Local — calls yt-transcript.py (yt-dlp) directly
 * 2. Vercel — calls Vercel-hosted API as fallback
 */

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.resolve(__dirname, "../../yt-transcript.py");
const VERIFY_BASE = process.env.YT_API_BASE || "https://yt-transcript-proxy.vercel.app";
const VERIFY_TOKEN = process.env.YT_API_TOKEN || "";

/**
 * Try local yt-dlp first, fallback to Vercel API.
 */
async function fetchTranscript(videoId, lang, mode = "text") {
  // Try local yt-dlp
  try {
    const resp = await callLocalYT(videoId, lang, mode);
    if (resp?.result?.content?.[0]?.text) {
      return { source: "local", text: resp.result.content[0].text };
    }
  } catch {}

  // Fallback to Vercel
  if (VERIFY_BASE) {
    try {
      const endpoint = mode === "text"
        ? `${VERIFY_BASE}/transcript/${videoId}/text?lang=${lang}`
        : `${VERIFY_BASE}/transcript/${videoId}?lang=${lang}`;
      const res = await fetch(endpoint, {
        headers: VERIFY_TOKEN ? { "X-Proxy-Token": VERIFY_TOKEN } : {},
      });
      if (res.ok) {
        const data = await res.json();
        const text = data.text || data.segments?.map((s) => s.text).join(" ") || "";
        return { source: "vercel", text };
      }
    } catch {}
  }

  throw new Error("Transcript unavailable from all sources");
}

function callLocalYT(videoId, lang, mode) {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [SCRIPT], {
      stdio: ["pipe", "pipe", "inherit"],
      timeout: 90_000,
    });
    let output = "";
    proc.stdout.on("data", (chunk) => (output += chunk.toString()));
    proc.on("close", (code) => {
      if (code !== 0 && !output.trim()) return reject(new Error(`exit ${code}`));
      const lines = output.trim().split("\n").filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        try { return resolve(JSON.parse(lines[i])); } catch {}
      }
      reject(new Error("No valid response"));
    });
    proc.on("error", reject);
    proc.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0", id: 1,
        method: "tools/call",
        params: { name: mode === "text" ? "get_transcript_text" : "get_transcript", arguments: { videoId, lang } },
      }) + "\n"
    );
    proc.stdin.end();
  });
}

// ── MCP Server ────────────────────────────────────────────────────────────
const server = new McpServer({ name: "youtube-transcript", version: "1.0.0" });

server.tool(
  "get_transcript",
  { videoId: z.string().describe("YouTube video ID or URL"), lang: z.string().optional().default("en") },
  async ({ videoId, lang }) => {
    const { source, text } = await fetchTranscript(videoId, lang, "detailed");
    return { content: [{ type: "text", text: `[${source}] ${text}` }] };
  },
);

server.tool(
  "get_transcript_text",
  { videoId: z.string().describe("YouTube video ID or URL"), lang: z.string().optional().default("en") },
  async ({ videoId, lang }) => {
    const { source, text } = await fetchTranscript(videoId, lang, "text");
    return { content: [{ type: "text", text: `[${source}] ${text}` }] };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[yt-mcp] Server started — local yt-dlp + Vercel fallback (${VERIFY_BASE})`);
}

main().catch((err) => { console.error("[yt-mcp] Fatal:", err); process.exit(1); });
