/**
 * MCP YouTube Transcript Server — uses yt-dlp directly, no proxies.
 *
 * Calls the local yt-transcript.py (which wraps yt-dlp with android/tv/web clients).
 * No Render proxy needed. Runs entirely local.
 */

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.resolve(__dirname, "../../yt-transcript.py");

/**
 * Call the local yt-transcript.py MCP server via stdio.
 * We send a JSON-RPC request and get the response back.
 */
function callYTscript(request) {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [SCRIPT], {
      stdio: ["pipe", "pipe", "inherit"],
      timeout: 120_000,
    });

    let output = "";
    proc.stdout.on("data", (chunk) => (output += chunk.toString()));

    proc.on("close", (code) => {
      if (code !== 0 && !output.trim()) {
        reject(new Error(`yt-transcript.py exited with code ${code}`));
        return;
      }
      // Parse the last JSON line (response)
      const lines = output.trim().split("\n").filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const parsed = JSON.parse(lines[i]);
          if (parsed.id === request.id) {
            resolve(parsed);
            return;
          }
        } catch {}
      }
      reject(new Error("No valid JSON-RPC response from yt-transcript.py"));
    });

    proc.on("error", reject);
    proc.stdin.write(JSON.stringify(request) + "\n");
    proc.stdin.end();
  });
}

// ── MCP Server ────────────────────────────────────────────────────────────
const server = new McpServer({
  name: "youtube-transcript",
  version: "1.0.0",
});

server.tool(
  "get_transcript",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
    lang: z.string().optional().default("en").describe("Language code"),
  },
  async ({ videoId, lang }) => {
    const resp = await callYTscript({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "get_transcript_text", arguments: { videoId, lang } },
    });
    const text = resp?.result?.content?.[0]?.text || "No transcript available";
    return { content: [{ type: "text", text }] };
  },
);

server.tool(
  "get_transcript_text",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
    lang: z.string().optional().default("en").describe("Language code"),
  },
  async ({ videoId, lang }) => {
    const resp = await callYTscript({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "get_transcript_text", arguments: { videoId, lang } },
    });
    const text = resp?.result?.content?.[0]?.text || "No transcript available";
    return { content: [{ type: "text", text }] };
  },
);

server.tool(
  "get_video_info",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
  },
  async ({ videoId }) => {
    const resp = await callYTscript({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "get_video_info", arguments: { videoId } },
    });
    const text = resp?.result?.content?.[0]?.text || "No info available";
    return { content: [{ type: "text", text }] };
  },
);

// ── Start ─────────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[yt-mcp] Server started — using yt-dlp directly");
}

main().catch((err) => {
  console.error("[yt-mcp] Fatal:", err);
  process.exit(1);
});
