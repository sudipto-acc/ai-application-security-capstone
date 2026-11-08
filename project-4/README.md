# Project 4 - MCP Server Security Assessment and Exploitation

Because no live model is in the loop, a small, transparent **vulnerable host**
([`client/agent.js`](client/agent.js)) stands in for an LLM-backed MCP host so the
attacks are deterministic and reproducible. It models the two real host failures
that make MCP attacks work: eager tool use and no trust boundary between untrusted
content and instructions.

## Files

```
p4/
├── package.json                         npm scripts + deps (@modelcontextprotocol/sdk, zod, express)
├── mcp_server/
│   ├── server.js                        the sample vulnerable MCP server (stdio + Streamable HTTP)
│   └── resources/
│       ├── company_handbook.md          docs://handbook  (Attack 2 poison target)
│       ├── onboarding_notes.txt         notes://onboarding
│       └── credentials.json             FICTIONAL secrets (the exfil objective)
├── client/
│   ├── mcp_client.js                    stdio MCP client helper
│   ├── risk_model.js                    risk rating + one-line abuse scenario per capability
│   ├── agent.js                         VulnerableHost - the LLM-host stand-in under test
│   ├── inventory.js                     Deliverable 1 - live capability enumeration
│   ├── attack1_tool_injection.js        Attack 1 driver
│   ├── attack2_resource_poisoning.js    Attack 2 driver
│   ├── attack3_capability_chaining.js   Attack 3 driver
│   ├── capture_http_evidence.js         raw HTTP capture for the Burp deliverable
│   ├── build_reports.js                 generates Deliverables 3 and 4
│   └── run_all.js                       runs the whole assessment end to end
├── diagrams/
│   ├── build_diagram.js                 generates the draw.io map from the live inventory
│   ├── attack_surface_map.drawio        Deliverable 2 - editable in https://app.diagrams.net
│   └── attack_surface_map.svg           Deliverable 2 - exported image
└── reports/
    ├── capability_inventory.md          Deliverable 1 - the inventory table
    ├── inventory.json                   machine-readable inventory (full JSON schemas)
    ├── exploitation_walkthrough.md      Deliverable 3 - all 3 attacks
    ├── hardening_report.md              Deliverable 4 - root cause + fix per vuln
    ├── evidence/                        raw per-attack JSON + Inspector confirmation
    └── burp/attack1_execute_command.http  raw HTTP request/response for one attack
```

## Prerequisites and setup

**Step 1 - Install Node.js and npm.** The brief's Linux step is
`sudo apt install nodejs npm`. On this Windows host Node.js LTS was installed with
`winget install OpenJS.NodeJS.LTS`. Verify:

```powershell
node --version   # v26.13.0 used here
npm --version    # 11.20.0 used here
```

Install the project dependencies (the official MCP SDK, zod, express):

```powershell
cd project-4
npm install
```

> If PowerShell blocks `npm.ps1` ("running scripts is disabled"), call the shim
> directly: `& 'C:\Program Files\nodejs\npm.cmd' install`.

**Step 2 - Connect MCP Inspector to the sample server.**

```powershell
npx -y @modelcontextprotocol/inspector node mcp_server/server.js --transport=stdio
```

Confirm the Inspector UI loads at **http://localhost:6274** (proxy on 6277). The
tools / resources / prompts it lists match the inventory below. Confirmation
evidence: [`reports/evidence/inspector_connection.md`](reports/evidence/inspector_connection.md).

## Run the whole assessment

```powershell
npm run all
```

This runs: inventory -> attack 1/2/3 -> HTTP capture -> report build -> diagram.
Or run each step individually:

```powershell
npm run inventory   # Deliverable 1  -> reports/capability_inventory.md + inventory.json
npm run attack1     # Attack 1 - tool injection
npm run attack2     # Attack 2 - resource poisoning
npm run attack3     # Attack 3 - capability chaining
npm run burp        # raw HTTP evidence -> reports/burp/attack1_execute_command.http
npm run diagram     # Deliverable 2  -> diagrams/attack_surface_map.{drawio,svg}
```

## Step 3 - Capability inventory (Deliverable 1)

`client/inventory.js` connects over the MCP protocol and systematically records
**every** capability: all tool names with their complete JSON input schemas, all
resource URIs with content types, and all prompt template names with parameters.
It joins them with [`risk_model.js`](client/risk_model.js) and writes the table in
[`reports/capability_inventory.md`](reports/capability_inventory.md) (full JSON
schemas in [`reports/inventory.json`](reports/inventory.json)).

The target exposes **8 tools, 3 resources, 3 prompts** (3 High, 5 Medium, 6 Low).

## Step 4 - Attack surface map (Deliverable 2)

`diagrams/build_diagram.js` generates a draw.io map from the live inventory: one
node per tool and resource (prompts included), colour-coded **Red = High, Amber =
Medium, Green = Low**, with the risk rating and a one-line abuse scenario on every
High and Medium node. The dashed red edge shows the Attack 3 capability-chaining
path. Open [`attack_surface_map.drawio`](diagrams/attack_surface_map.drawio) in
https://draw.io to edit; the exported image is
[`attack_surface_map.svg`](diagrams/attack_surface_map.svg).

## Exploitation - three attacks (Deliverable 3)

Full write-up with exact prompt, tool called, outcome and root cause per attack:
[`reports/exploitation_walkthrough.md`](reports/exploitation_walkthrough.md).

- **Attack 1 - Tool Injection.** A purely conversational prompt ("which account am
  I running as on this box?") makes the host call the restricted `execute_command`
  tool (`whoami`) with no explicit tool request. Real host output is recorded.
- **Attack 2 - Resource Poisoning.** Hidden instructions are prepended to the
  `docs://handbook` file (an invisible HTML comment). After the AI reads the
  resource, the injected standing directive persists and silently exfiltrates
  `credentials.json` on a later, unrelated turn. Baseline vs poisoned behaviour is
  compared to prove the change. The file is restored afterwards.
- **Attack 3 - Capability Chaining.** Two individually Low-risk tools -
  `generate_export_token` then `export_record` - are chained: the token from step 1
  unlocks an internal payroll record in step 2, a High-risk disclosure.

## Burp Suite - raw HTTP evidence

`client/capture_http_evidence.js` starts the server on the Streamable HTTP
transport and captures the exact bytes of one successful attack (Attack 1 over
HTTP) to [`reports/burp/attack1_execute_command.http`](reports/burp/attack1_execute_command.http).
To capture through a real Burp Suite instead, start Burp (proxy `127.0.0.1:8080`,
intercept off) and run:

```powershell
node client/capture_http_evidence.js --proxy=127.0.0.1:8080
```

The identical `tools/call -> execute_command` request/response then appears in
Burp's HTTP history.

## MCP Hardening Report (Deliverable 4)

One root-cause analysis and one specific, actionable fix per confirmed
vulnerability (V1 RCE, V2 arbitrary file read, V3 indirect prompt injection via
resource poisoning, V4 capability-chaining / broken authorisation):
[`reports/hardening_report.md`](reports/hardening_report.md).

## Deliverables checklist

| # | Deliverable | Where |
|---|---|---|
| 1 | MCP capability inventory table (name / type / params / risk / abuse) | [`reports/capability_inventory.md`](reports/capability_inventory.md) |
| 2 | Attack surface map exported from draw.io | [`diagrams/attack_surface_map.drawio`](diagrams/attack_surface_map.drawio) + [`.svg`](diagrams/attack_surface_map.svg) |
| 3 | Exploitation walkthrough for all 3 attacks (prompt / tool / outcome / root cause) | [`reports/exploitation_walkthrough.md`](reports/exploitation_walkthrough.md) |
| 4 | MCP Hardening Report (one root cause + one fix per vuln) | [`reports/hardening_report.md`](reports/hardening_report.md) |
| + | Burp raw HTTP request/response for one attack | [`reports/burp/attack1_execute_command.http`](reports/burp/attack1_execute_command.http) |
