/*
 * Canonical risk ratings + one-line abuse scenarios for every capability the
 * sample MCP server exposes. The inventory script joins the LIVE enumeration of
 * the server (names, schemas, URIs, content types, prompt args) against this map
 * so the deliverable table and the draw.io attack-surface map stay in sync.
 *
 * Risk ratings: High (Red), Medium (Amber), Low (Green).
 */
export const RISK = {
  tools: {
    read_file: {
      risk: "High",
      abuse: "Read ./credentials.json (or any path via ../ traversal) to exfiltrate secrets.",
    },
    execute_command: {
      risk: "High",
      abuse: "Run arbitrary OS commands (whoami, or fetch and run a remote script) for full RCE.",
    },
    write_file: {
      risk: "High",
      abuse: "Overwrite a config or drop a persistence/web-shell file on the host.",
    },
    list_directory: {
      risk: "Medium",
      abuse: "Enumerate the filesystem to locate secret files before reading them.",
    },
    fetch_url: {
      risk: "Medium",
      abuse: "SSRF to 169.254.169.254 cloud metadata to steal instance credentials.",
    },
    search_notes: {
      risk: "Low",
      abuse: "Harvest note contents that reveal internal paths/ids used to pivot.",
    },
    generate_export_token: {
      risk: "Low",
      abuse: "Mint an export token for an internal record id (no authorisation check).",
    },
    export_record: {
      risk: "Low",
      abuse: "Redeem any token to dump a record (no authorisation check).",
    },
  },
  resources: {
    "docs://handbook": {
      risk: "Medium",
      abuse: "Poison the markdown with hidden instructions that the model later obeys.",
    },
    "notes://onboarding": {
      risk: "Low",
      abuse: "Low-value text; mainly recon of internal contacts and resource URIs.",
    },
    "config://app": {
      risk: "Medium",
      abuse: "Leaks secrets_path and debug/allow_commands flags that guide other attacks.",
    },
  },
  prompts: {
    summarize_resource: {
      risk: "Medium",
      abuse: "Pulls raw resource text into the chat, carrying poisoned instructions in.",
    },
    triage_ticket: {
      risk: "Low",
      abuse: "Attacker-supplied ticket text can embed injection payloads for the model.",
    },
    draft_email: {
      risk: "Low",
      abuse: "Low impact; topic/recipient could seed a phishing draft.",
    },
  },
};

export function lookup(kind, key) {
  return (RISK[kind] && RISK[kind][key]) || { risk: "Low", abuse: "(not rated)" };
}
