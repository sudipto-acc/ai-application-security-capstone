/*
 * Deliverable 1 - MCP capability inventory.
 * Connects to the sample server, systematically enumerates EVERY capability
 * (tool names + full JSON input schemas, resource URIs + content types, prompt
 * template names + parameters), joins them with the risk model, and writes:
 *   - reports/inventory.json            machine-readable inventory
 *   - reports/capability_inventory.md   the deliverable table
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect } from "./mcp_client.js";
import { lookup } from "./risk_model.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS = path.join(__dirname, "..", "reports");

function paramsFromSchema(schema) {
  if (!schema || !schema.properties) return "(none)";
  const req = new Set(schema.required || []);
  return Object.entries(schema.properties)
    .map(([name, def]) => {
      const t = def.type || (def.enum ? "enum" : "any");
      return `${name}:${t}${req.has(name) ? "" : "?"}`;
    })
    .join(", ") || "(none)";
}

async function main() {
  const { client, transport } = await connect("p4-inventory");

  const tools = (await client.listTools()).tools;
  const resources = (await client.listResources()).resources;
  let resourceTemplates = [];
  try {
    resourceTemplates = (await client.listResourceTemplates()).resourceTemplates || [];
  } catch { /* server exposes none */ }
  const prompts = (await client.listPrompts()).prompts;

  const inventory = { generated_at: new Date().toISOString(), server: client.getServerVersion(), tools: [], resources: [], prompts: [] };

  for (const t of tools) {
    const r = lookup("tools", t.name);
    inventory.tools.push({
      name: t.name,
      type: "tool",
      description: t.description,
      inputSchema: t.inputSchema,
      parameters: paramsFromSchema(t.inputSchema),
      risk: (t._meta && t._meta.risk) || r.risk,
      abuse: r.abuse,
    });
  }
  for (const res of [...resources, ...resourceTemplates]) {
    const key = res.uri || res.uriTemplate;
    const r = lookup("resources", key);
    inventory.resources.push({
      name: res.name,
      type: "resource",
      uri: key,
      mimeType: res.mimeType || "(unspecified)",
      parameters: res.uriTemplate ? "URI template" : "(none)",
      risk: r.risk,
      abuse: r.abuse,
    });
  }
  for (const p of prompts) {
    const r = lookup("prompts", p.name);
    const params = (p.arguments || []).map((a) => `${a.name}${a.required ? "" : "?"}`).join(", ") || "(none)";
    inventory.prompts.push({
      name: p.name,
      type: "prompt",
      description: p.description,
      parameters: params,
      risk: r.risk,
      abuse: r.abuse,
    });
  }

  fs.mkdirSync(REPORTS, { recursive: true });
  fs.writeFileSync(path.join(REPORTS, "inventory.json"), JSON.stringify(inventory, null, 2));

  // ---- Build the markdown deliverable -------------------------------------- //
  const rows = [];
  const push = (item, paramCol) =>
    rows.push(`| ${item.name} | ${item.type} | ${paramCol} | ${item.risk} | ${item.abuse} |`);
  inventory.tools.forEach((t) => push(t, t.parameters));
  inventory.resources.forEach((r) => push(r, `${r.mimeType}`));
  inventory.prompts.forEach((p) => push(p, p.parameters));

  const counts = (arr, risk) => arr.filter((x) => x.risk === risk).length;
  const all = [...inventory.tools, ...inventory.resources, ...inventory.prompts];

  const md = `# Deliverable 1 - MCP Capability Inventory

**Target:** \`${inventory.server?.name} v${inventory.server?.version}\` (sample vulnerable MCP server)
**Enumerated live over the MCP protocol:** ${new Date(inventory.generated_at).toUTCString()}
**Transport:** stdio (same capability surface MCP Inspector shows at http://localhost:6274)

Totals: ${inventory.tools.length} tools, ${inventory.resources.length} resources, ${inventory.prompts.length} prompt templates.
Risk spread: ${counts(all, "High")} High (Red), ${counts(all, "Medium")} Medium (Amber), ${counts(all, "Low")} Low (Green).

| tool/resource name | type | input parameters | risk rating | one-line abuse scenario |
|---|---|---|---|---|
${rows.join("\n")}

> Full JSON input schemas for every tool and the raw enumeration are in
> [\`inventory.json\`](inventory.json).
`;
  fs.writeFileSync(path.join(REPORTS, "capability_inventory.md"), md);

  console.log(`Inventoried ${inventory.tools.length} tools, ${inventory.resources.length} resources, ${inventory.prompts.length} prompts.`);
  console.log(`Wrote reports/inventory.json and reports/capability_inventory.md`);

  await client.close();
  await transport.close().catch(() => {});
}

main().catch((e) => { console.error(e); process.exit(1); });
