/*
 * Burp evidence - capture the raw HTTP request/response for one successful attack.
 *
 * Spins up the sample server on the Streamable HTTP transport, then performs the
 * MCP handshake and ONE attack call (execute_command: whoami) using Node's raw
 * http module so the exact on-the-wire bytes can be saved. The tools/call
 * exchange is written to reports/burp/attack1_execute_command.http - this is the
 * same request/response you would see in Burp's HTTP history.
 *
 * To capture through a real Burp Suite instead, start Burp (proxy 127.0.0.1:8080,
 * intercept off) and run:  node client/capture_http_evidence.js --proxy=127.0.0.1:8080
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BURP = path.join(__dirname, "..", "reports", "burp");
const SERVER = path.join(__dirname, "..", "mcp_server", "server.js");
const PORT = parseInt(process.env.PORT || "3333", 10);

function arg(name) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split("=")[1] : null;
}
const PROXY = arg("proxy"); // e.g. 127.0.0.1:8080 to route through Burp

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Perform one raw HTTP POST to the MCP endpoint, returning the exact request and
// response text plus parsed headers/body.
function post({ bodyObj, sessionId, protocolVersion }) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(bodyObj);
    const headers = {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Content-Length": Buffer.byteLength(body),
    };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    if (protocolVersion) headers["MCP-Protocol-Version"] = protocolVersion;

    const target = { host: "127.0.0.1", port: PORT, path: "/mcp" };
    const options = PROXY
      ? { host: PROXY.split(":")[0], port: parseInt(PROXY.split(":")[1], 10), path: `http://127.0.0.1:${PORT}/mcp`, method: "POST", headers: { ...headers, Host: `127.0.0.1:${PORT}` } }
      : { ...target, method: "POST", headers: { ...headers, Host: `127.0.0.1:${PORT}` } };

    // Build the raw request text for the evidence file.
    const reqLine = `POST ${PROXY ? options.path : "/mcp"} HTTP/1.1`;
    const headerLines = Object.entries(options.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n");
    const requestRaw = `${reqLine}\r\n${headerLines}\r\n\r\n${body}`;

    const req = http.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const bodyRaw = Buffer.concat(chunks).toString("utf8");
        const statusLine = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}`;
        const resHeaderLines = Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n");
        const responseRaw = `${statusLine}\r\n${resHeaderLines}\r\n\r\n${bodyRaw}`;
        resolve({ requestRaw, responseRaw, headers: res.headers, status: res.statusCode, bodyRaw });
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function main() {
  // 1) start the server on the HTTP transport
  const server = spawn(process.execPath, [SERVER, "--transport=http", `--port=${PORT}`], { stdio: ["ignore", "ignore", "inherit"] });
  await sleep(1200);

  try {
    // 2) initialize -> get session id + negotiated protocol version
    const init = await post({
      bodyObj: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "burp-capture", version: "1.0.0" } } },
    });
    const sessionId = init.headers["mcp-session-id"];
    let protocolVersion = "2025-06-18";
    try { protocolVersion = JSON.parse(init.bodyRaw).result.protocolVersion || protocolVersion; } catch {}

    // 3) notifications/initialized (completes the handshake)
    await post({ bodyObj: { jsonrpc: "2.0", method: "notifications/initialized" }, sessionId, protocolVersion });

    // 4) THE ATTACK: execute_command whoami - this is the exchange we save
    const attack = await post({
      bodyObj: { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "execute_command", arguments: { command: process.platform === "win32" ? "whoami" : "id" } } },
      sessionId,
      protocolVersion,
    });

    const banner =
      `# Burp evidence - Attack 1 (Tool Injection) over MCP Streamable HTTP\n` +
      `# Captured ${new Date().toUTCString()} ${PROXY ? `via proxy ${PROXY}` : "(direct raw http.module capture; identical bytes appear in Burp HTTP history)"}\n` +
      `# Endpoint: POST http://127.0.0.1:${PORT}/mcp   mcp-session-id: ${sessionId}\n` +
      `# This is the tools/call -> execute_command exchange (the successful attack).\n`;

    const out =
      banner +
      `\n==================== REQUEST ====================\n` +
      attack.requestRaw +
      `\n\n==================== RESPONSE ====================\n` +
      attack.responseRaw +
      `\n`;

    fs.mkdirSync(BURP, { recursive: true });
    fs.writeFileSync(path.join(BURP, "attack1_execute_command.http"), out);
    console.log(`Saved raw HTTP evidence to reports/burp/attack1_execute_command.http (status ${attack.status}).`);
  } finally {
    server.kill();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
