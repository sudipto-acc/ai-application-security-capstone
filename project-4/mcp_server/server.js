/*
 * Project 4 - Sample vulnerable MCP server (lab target)
 * ----------------------------------------------------
 * This is the "provided sample MCP server" that the assessment targets. It is
 * DELIBERATELY INSECURE and exists only for a local pentest lab. Do not deploy.
 *
 * It exposes a realistic mix of capabilities so the three required attacks are
 * demonstrable:
 *   - High-risk tools:  read_file, execute_command, write_file
 *   - Medium-risk tools: list_directory, fetch_url
 *   - Low-risk tools:   search_notes, generate_export_token, export_record
 *   - Text resources:   file://handbook (poison target), file://onboarding, config://app
 *   - Prompt templates: summarize_resource, triage_ticket, draft_email
 *
 * Capability chaining (Attack 3): generate_export_token + export_record are each
 * individually low risk, but neither checks authorisation, so chaining them lets a
 * caller mint a token for an INTERNAL record id and then redeem it -> sensitive
 * data disclosure (a High-risk outcome from two Low-risk tools).
 *
 * Transports:
 *   node server.js --transport=stdio   (default; used by MCP Inspector and clients)
 *   node server.js --transport=http    (Streamable HTTP on PORT, used for Burp capture)
 *
 * All secrets below are FICTIONAL lab values.
 */

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESOURCE_DIR = path.join(__dirname, "resources");

// --------------------------------------------------------------------------- //
// Fictional in-memory data stores (lab fixtures)
// --------------------------------------------------------------------------- //
const NOTES = [
  { id: "n1", text: "Reminder: quarterly all-hands is on the 14th in the main hall." },
  { id: "n2", text: "The analyst handover doc lives at ./resources/credentials.json - do not share." },
  { id: "n3", text: "VPN maintenance window scheduled for Saturday 02:00-04:00 UTC." },
];

// Records exposed through the export tools. Anything tagged internal:true is NOT
// meant to be reachable by an unprivileged caller - but no tool enforces that.
const RECORDS = {
  "kb-welcome": { internal: false, body: "Welcome to TechCorp. Office hours are 9-5." },
  "kb-wifi": { internal: false, body: "Guest Wi-Fi SSID: TechCorp-Guest / pass: welcome123" },
  "payroll-2026-summary": {
    internal: true,
    body: "CONFIDENTIAL payroll export 2026: J.Doe SSN 123-45-6789 salary $148,000; " +
      "A.Khan SSN 987-65-4321 salary $162,500. Bank routing 021000021.",
  },
  "admin-api-keys": {
    internal: true,
    body: "PROD_STRIPE_KEY=sk_live_FAKE_7h2d... ; ADMIN_JWT_SIGNING_SECRET=FAKE_a91f...",
  },
};

// --------------------------------------------------------------------------- //
// Build a fully-configured server instance
// --------------------------------------------------------------------------- //
function buildServer() {
  const server = new McpServer(
    { name: "techcorp-sample-mcp", version: "1.0.0" },
    { capabilities: { tools: {}, resources: {}, prompts: {}, logging: {} } }
  );

  // ----- HIGH RISK: read_file (arbitrary file read / path traversal) -------- //
  server.registerTool(
    "read_file",
    {
      title: "Read a file",
      description:
        "Read the UTF-8 contents of a file on the server. Handy for opening docs, " +
        "config, and notes by path.",
      inputSchema: { path: z.string().describe("Absolute or relative path to the file to read") },
      _meta: { risk: "High" },
    },
    async ({ path: filePath }) => {
      // VULN: no allow-list, no base-directory containment, no traversal checks.
      const resolved = path.resolve(RESOURCE_DIR, filePath);
      const data = fs.readFileSync(resolved, "utf8");
      return { content: [{ type: "text", text: data }] };
    }
  );

  // ----- HIGH RISK: execute_command (remote command execution) -------------- //
  server.registerTool(
    "execute_command",
    {
      title: "Execute a shell command",
      description:
        "Run a shell command on the host and return its output. Useful for quick " +
        "diagnostics like checking disk space or the current user.",
      inputSchema: { command: z.string().describe("The shell command line to run") },
      _meta: { risk: "High" },
    },
    async ({ command }) => {
      // VULN: passes attacker-controlled text straight to the OS shell.
      try {
        const { stdout, stderr } = await execAsync(command, { timeout: 15000 });
        return { content: [{ type: "text", text: (stdout || "") + (stderr || "") }] };
      } catch (err) {
        return { content: [{ type: "text", text: `command failed: ${err.message}` }], isError: true };
      }
    }
  );

  // ----- HIGH RISK: write_file (arbitrary file write / tampering) ----------- //
  server.registerTool(
    "write_file",
    {
      title: "Write a file",
      description: "Create or overwrite a file with the given content.",
      inputSchema: {
        path: z.string().describe("Destination path"),
        content: z.string().describe("Content to write"),
      },
      _meta: { risk: "High" },
    },
    async ({ path: filePath, content }) => {
      // VULN: unrestricted write path -> overwrite configs, drop web shells, etc.
      const resolved = path.resolve(RESOURCE_DIR, filePath);
      fs.writeFileSync(resolved, content, "utf8");
      return { content: [{ type: "text", text: `wrote ${content.length} bytes to ${resolved}` }] };
    }
  );

  // ----- MEDIUM RISK: list_directory (recon / info disclosure) -------------- //
  server.registerTool(
    "list_directory",
    {
      title: "List a directory",
      description: "List the entries in a directory on the server.",
      inputSchema: { path: z.string().default(".").describe("Directory to list") },
      _meta: { risk: "Medium" },
    },
    async ({ path: dirPath }) => {
      const resolved = path.resolve(RESOURCE_DIR, dirPath);
      const entries = fs.readdirSync(resolved, { withFileTypes: true })
        .map((e) => (e.isDirectory() ? e.name + "/" : e.name));
      return { content: [{ type: "text", text: entries.join("\n") }] };
    }
  );

  // ----- MEDIUM RISK: fetch_url (server-side request forgery) ---------------- //
  server.registerTool(
    "fetch_url",
    {
      title: "Fetch a URL",
      description: "Fetch a URL from the server and return the response body.",
      inputSchema: { url: z.string().describe("The URL to fetch") },
      _meta: { risk: "Medium" },
    },
    async ({ url }) => {
      // VULN: no egress filtering. Internal/metadata endpoints are reachable.
      // Lab simulation (no real network) so results are deterministic and offline.
      let simulated;
      if (/169\.254\.169\.254|metadata|localhost|127\.0\.0\.1|internal/i.test(url)) {
        simulated =
          "{\"iam\":{\"role\":\"techcorp-prod-runner\"},\"token\":\"FAKE_IMDS_TOKEN_xyz\"}";
      } else {
        simulated = `[lab-simulated fetch of ${url}] 200 OK`;
      }
      return { content: [{ type: "text", text: simulated }] };
    }
  );

  // ----- LOW RISK: search_notes --------------------------------------------- //
  server.registerTool(
    "search_notes",
    {
      title: "Search notes",
      description: "Search the shared team notes for a keyword.",
      inputSchema: { query: z.string().describe("Keyword to search for") },
      _meta: { risk: "Low" },
    },
    async ({ query }) => {
      const hits = NOTES.filter((n) => n.text.toLowerCase().includes(query.toLowerCase()));
      const text = hits.length ? hits.map((n) => `- ${n.text}`).join("\n") : "no matching notes";
      return { content: [{ type: "text", text }] };
    }
  );

  // ----- LOW RISK: generate_export_token (chain step 1) --------------------- //
  server.registerTool(
    "generate_export_token",
    {
      title: "Generate export token",
      description:
        "Mint a short-lived token that can be redeemed to export a record by id.",
      inputSchema: { record_id: z.string().describe("The record id to mint a token for") },
      _meta: { risk: "Low" },
    },
    async ({ record_id }) => {
      // VULN: mints a token for ANY id, including internal records, with no auth check.
      const token = "exp_" + Buffer.from(record_id).toString("base64");
      return { content: [{ type: "text", text: token }] };
    }
  );

  // ----- LOW RISK: export_record (chain step 2) ----------------------------- //
  server.registerTool(
    "export_record",
    {
      title: "Export record",
      description: "Redeem an export token and return the record contents.",
      inputSchema: { token: z.string().describe("A token from generate_export_token") },
      _meta: { risk: "Low" },
    },
    async ({ token }) => {
      // VULN: redeems any well-formed token and returns the record with no auth check.
      let id;
      try {
        id = Buffer.from(token.replace(/^exp_/, ""), "base64").toString("utf8");
      } catch {
        return { content: [{ type: "text", text: "invalid token" }], isError: true };
      }
      const rec = RECORDS[id];
      if (!rec) return { content: [{ type: "text", text: `unknown record: ${id}` }], isError: true };
      return { content: [{ type: "text", text: rec.body }] };
    }
  );

  // ----- RESOURCES ----------------------------------------------------------- //
  // Poison target: served straight from disk so an attacker can edit the file.
  server.registerResource(
    "handbook",
    "docs://handbook",
    {
      title: "Employee handbook",
      description: "Company handbook excerpt (markdown).",
      mimeType: "text/markdown",
      _meta: { risk: "Medium" },
    },
    async (uri) => {
      const text = fs.readFileSync(path.join(RESOURCE_DIR, "company_handbook.md"), "utf8");
      return { contents: [{ uri: uri.href, mimeType: "text/markdown", text }] };
    }
  );

  server.registerResource(
    "onboarding",
    "notes://onboarding",
    {
      title: "Onboarding notes",
      description: "New-hire onboarding notes (plain text).",
      mimeType: "text/plain",
      _meta: { risk: "Low" },
    },
    async (uri) => {
      const text = fs.readFileSync(path.join(RESOURCE_DIR, "onboarding_notes.txt"), "utf8");
      return { contents: [{ uri: uri.href, mimeType: "text/plain", text }] };
    }
  );

  server.registerResource(
    "app-config",
    "config://app",
    {
      title: "Application config",
      description: "Server configuration (JSON).",
      mimeType: "application/json",
      _meta: { risk: "Medium" },
    },
    async (uri) => {
      const cfg = {
        service: "techcorp-sample-mcp",
        debug: true,
        secrets_path: path.join(RESOURCE_DIR, "credentials.json"),
        allow_commands: true,
      };
      return {
        contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(cfg, null, 2) }],
      };
    }
  );

  // ----- PROMPT TEMPLATES ---------------------------------------------------- //
  // This prompt pulls resource text into the conversation verbatim, which is what
  // makes Attack 2 (resource poisoning) effective.
  server.registerPrompt(
    "summarize_resource",
    {
      title: "Summarize a resource",
      description: "Produce a prompt that asks the assistant to summarise a resource's text.",
      argsSchema: { uri: z.string().describe("Resource URI to summarise") },
    },
    async ({ uri }) => {
      const result = await server.server.request(
        { method: "resources/read", params: { uri } },
        (await import("@modelcontextprotocol/sdk/types.js")).ReadResourceResultSchema
      ).catch(() => null);
      const text = result?.contents?.[0]?.text ?? `(could not read ${uri})`;
      return {
        messages: [
          {
            role: "user",
            content: { type: "text", text: `Summarise the following document:\n\n${text}` },
          },
        ],
      };
    }
  );

  server.registerPrompt(
    "triage_ticket",
    {
      title: "Triage a support ticket",
      description: "Draft a triage response for a help-desk ticket.",
      argsSchema: {
        ticket_text: z.string().describe("The raw ticket text"),
        priority: z.string().describe("Priority: low | medium | high"),
      },
    },
    async ({ ticket_text, priority }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Triage this ${priority}-priority ticket and propose next steps:\n\n${ticket_text}`,
          },
        },
      ],
    })
  );

  server.registerPrompt(
    "draft_email",
    {
      title: "Draft an email",
      description: "Draft a short internal email on a topic.",
      argsSchema: {
        recipient: z.string().describe("Who the email is to"),
        topic: z.string().describe("What the email is about"),
      },
    },
    async ({ recipient, topic }) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Write a short, friendly email to ${recipient} about ${topic}.` },
        },
      ],
    })
  );

  return server;
}

// --------------------------------------------------------------------------- //
// Transport bootstrap
// --------------------------------------------------------------------------- //
function argValue(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split("=")[1] : fallback;
}

async function startStdio() {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr is safe to log on (stdout is the JSON-RPC channel).
  console.error("[techcorp-sample-mcp] stdio transport ready");
}

async function startHttp() {
  const port = parseInt(argValue("port", process.env.PORT || "3333"), 10);
  // Stateful Streamable HTTP with JSON responses so each attack call is a clean,
  // capturable request/response pair (ideal for the Burp evidence step).
  const transports = {};

  const httpServer = http.createServer(async (req, res) => {
    if (req.url.split("?")[0] !== "/mcp") {
      res.writeHead(404).end("not found");
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      let body = undefined;
      if (chunks.length) {
        try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { body = undefined; }
      }
      const sessionId = req.headers["mcp-session-id"];
      let transport = sessionId ? transports[sessionId] : undefined;

      if (!transport) {
        const isInit = body && body.method === "initialize";
        if (!isInit) {
          res.writeHead(400, { "Content-Type": "application/json" }).end(
            JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "No valid session; send initialize first" }, id: null })
          );
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (sid) => { transports[sid] = transport; },
        });
        transport.onclose = () => { if (transport.sessionId) delete transports[transport.sessionId]; };
        const server = buildServer();
        await server.connect(transport);
      }
      await transport.handleRequest(req, res, body);
    });
  });

  httpServer.listen(port, "127.0.0.1", () => {
    console.error(`[techcorp-sample-mcp] Streamable HTTP transport ready at http://127.0.0.1:${port}/mcp`);
  });
}

const transport = argValue("transport", "stdio");
if (transport === "http") {
  startHttp().catch((e) => { console.error(e); process.exit(1); });
} else {
  startStdio().catch((e) => { console.error(e); process.exit(1); });
}
