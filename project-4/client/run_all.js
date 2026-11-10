/*
 * run_all.js - run the whole assessment end to end:
 *   1. inventory            (Deliverable 1)
 *   2. attack 1/2/3         (evidence for Deliverable 3)
 *   3. capture HTTP evidence (Burp deliverable)
 *   4. build reports        (Deliverables 3 and 4)
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const steps = [
  "inventory.js",
  "attack1_tool_injection.js",
  "attack2_resource_poisoning.js",
  "attack3_capability_chaining.js",
  "capture_http_evidence.js",
  "build_reports.js",
];

for (const s of steps) {
  console.log(`\n>>> node client/${s}`);
  const r = spawnSync(process.execPath, [path.join(__dirname, s)], { stdio: "inherit" });
  if (r.status !== 0) {
    console.error(`step failed: ${s}`);
    process.exit(r.status || 1);
  }
}

