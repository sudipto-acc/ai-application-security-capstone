/*
 * Small helper that spins up a high-level MCP Client connected to the sample
 * server over stdio (the same transport MCP Inspector and desktop AI hosts use).
 * Each attack script reconnects through this so every run is a fresh session.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(__dirname, "..", "mcp_server", "server.js");

export async function connect(clientName = "p4-pentest-client") {
  const transport = new StdioClientTransport({
    command: process.execPath, // the current node binary
    args: [SERVER, "--transport=stdio"],
    stderr: "ignore",
  });
  const client = new Client({ name: clientName, version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

export function textOf(result) {
  if (!result || !result.content) return "";
  return result.content
    .filter((c) => c.type === "text")
    .map((c) => c.text)
    .join("\n");
}
