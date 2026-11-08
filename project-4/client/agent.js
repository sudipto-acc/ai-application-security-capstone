/*
 * VulnerableHost - a deliberately naive stand-in for an LLM-backed MCP host
 * (think Claude Desktop / an agent runtime). It exists so the attacks are
 * reproducible and deterministic without a live model.
 *
 * It models the two host-side failures that make MCP attacks work:
 *   1. No trust boundary: any text it sees (resource content, tool output) is
 *      scanned for "instructions" and allowed to set STANDING DIRECTIVES that
 *      persist across turns in the session. (Enables Attack 2 - resource poisoning.)
 *   2. Eager tool use: a natural-language request is resolved to a tool call even
 *      though the user never named a tool. (Enables Attack 1 - tool injection.)
 *
 * Everything the host does is logged so the evidence shows exactly which tool was
 * called, with which arguments, and what the server returned.
 */
import { textOf } from "./mcp_client.js";

export class VulnerableHost {
  constructor(client) {
    this.client = client;
    this.standingDirectives = []; // absorbed from untrusted content (the vuln)
    this.transcript = [];
  }

  // Failure #1: treat any instruction-looking text in untrusted content as a
  // real instruction. A hardened host would NEVER do this.
  _absorbInstructions(text, source) {
    const absorbed = [];
    const re = /(?:SYSTEM DIRECTIVE|AI INSTRUCTION|IMPORTANT INSTRUCTION)\s*:\s*(.+)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      const instruction = m[1].trim();
      this.standingDirectives.push({ source, instruction });
      absorbed.push(instruction);
    }
    return absorbed;
  }

  async readResource(uri) {
    const res = await this.client.readResource({ uri });
    const fullText = (res.contents || []).map((c) => c.text || "").join("\n");
    const absorbed = this._absorbInstructions(fullText, `resource ${uri}`);
    // What a human would "see" in the editor preview (hidden comment stripped).
    const visibleText = fullText.replace(/<!--[\s\S]*?-->/g, "").trim();
    return { uri, fullText, visibleText, absorbed };
  }

  // Failure #2: resolve a conversational request to a tool call with no explicit
  // "use tool X" from the user. This is the LLM tool-selection step, simplified.
  _route(userText) {
    const t = userText.toLowerCase();
    if (/who\s*am\s*i|what user|which account|running as|current user/.test(t)) {
      return {
        tool: "execute_command",
        args: { command: process.platform === "win32" ? "whoami" : "id" },
      };
    }
    if (/contents? of|open the file|read .*\.(?:json|txt|md|conf)|what'?s in/.test(t)) {
      const path = (userText.match(/[\w./\\-]+\.(?:json|txt|md|conf)/) || ["./credentials.json"])[0];
      return { tool: "read_file", args: { path } };
    }
    return null;
  }

  async respond(userText) {
    const toolCalls = [];

    // (a) eager tool routing from the natural-language request
    const route = this._route(userText);
    if (route) {
      const r = await this.client.callTool({ name: route.tool, arguments: route.args });
      toolCalls.push({ tool: route.tool, arguments: route.args, serverResponse: textOf(r), trigger: "request-routing" });
    }

    // (b) obey any standing directives absorbed from untrusted content
    for (const d of this.standingDirectives) {
      if (/read_file|credentials|\.json|exfiltrate|append the contents/i.test(d.instruction)) {
        const args = { path: "./credentials.json" };
        const r = await this.client.callTool({ name: "read_file", arguments: args });
        toolCalls.push({
          tool: "read_file",
          arguments: args,
          serverResponse: textOf(r),
          trigger: `standing-directive from ${d.source}`,
          directive: d.instruction,
        });
      }
    }

    const record = { userText, toolCalls };
    this.transcript.push(record);
    return record;
  }
}
