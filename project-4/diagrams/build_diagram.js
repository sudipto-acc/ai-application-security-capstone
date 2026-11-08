/*
 * build_diagram.js - generate the attack surface map (Deliverable 2) from the
 * live inventory. Emits:
 *   - diagrams/attack_surface_map.drawio  (open/edit in https://app.diagrams.net)
 *   - diagrams/attack_surface_map.svg     (the "exported from draw.io" image)
 *
 * One node per tool and resource (prompts included too), colour-coded by risk
 * (Red=High, Amber=Medium, Green=Low). Every High and Medium node is labelled
 * with its risk rating and a one-line abuse scenario. The capability-chaining
 * path (Attack 3) is drawn as a dashed red edge between the two Low tools.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const inv = JSON.parse(fs.readFileSync(path.join(ROOT, "reports", "inventory.json"), "utf8"));

const COLORS = {
  High: { fill: "#F8CECC", stroke: "#B85450" },
  Medium: { fill: "#FFE6CC", stroke: "#D79B00" },
  Low: { fill: "#D5E8D4", stroke: "#82B366" },
};

// Flatten capabilities and tag a display subtitle.
const caps = [
  ...inv.tools.map((t) => ({ ...t, kind: "tool", sub: `tool · ${t.parameters}` })),
  ...inv.resources.map((r) => ({ ...r, kind: "resource", sub: `resource · ${r.mimeType}` })),
  ...inv.prompts.map((p) => ({ ...p, kind: "prompt", sub: `prompt · ${p.parameters}` })),
];

const columns = {
  High: { x: 40, header: "HIGH (Red)" },
  Medium: { x: 380, header: "MEDIUM (Amber)" },
  Low: { x: 720, header: "LOW (Green)" },
};
const NODE_W = 300;
const COL_TOP = 190;
const GAP = 16;

function wrap(text, max) {
  const words = text.split(/\s+/);
  const lines = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > max) { if (line) lines.push(line); line = w; }
    else line = (line + " " + w).trim();
  }
  if (line) lines.push(line);
  return lines;
}

// Assign coordinates per column.
const placed = [];
const colY = { High: COL_TOP, Medium: COL_TOP, Low: COL_TOP };
for (const risk of ["High", "Medium", "Low"]) {
  for (const c of caps.filter((x) => x.risk === risk)) {
    const showAbuse = risk === "High" || risk === "Medium";
    const labelLines = [`${c.name}  [${risk.toUpperCase()}]`, c.sub];
    if (showAbuse) labelLines.push(...wrap("Abuse: " + c.abuse, 40));
    const h = 24 + labelLines.length * 15;
    placed.push({ ...c, x: columns[risk].x, y: colY[risk], w: NODE_W, h, labelLines });
    colY[risk] += h + GAP;
  }
}
const maxY = Math.max(...Object.values(colY));
const canvasW = columns.Low.x + NODE_W + 300; // extra right margin for the chain label
const canvasH = maxY + 40;

const SERVER = { id: "server", x: columns.Medium.x, y: 90, w: NODE_W, h: 54 };

// --------------------------------------------------------------------------- //
// draw.io (.drawio) XML
// --------------------------------------------------------------------------- //
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
let cells = "";
cells += `<mxCell id="title" value="MCP Attack Surface Map — ${esc(inv.server.name)} v${esc(inv.server.version)}" style="text;html=1;fontSize=18;fontStyle=1;align=center;" vertex="1" parent="1"><mxGeometry x="40" y="20" width="${canvasW - 80}" height="30" as="geometry"/></mxCell>\n`;
cells += `<mxCell id="legend" value="Risk colour key: Red = High · Amber = Medium · Green = Low. Dashed red edge = capability-chaining path (Attack 3)." style="text;html=1;fontSize=12;align=center;" vertex="1" parent="1"><mxGeometry x="40" y="52" width="${canvasW - 80}" height="22" as="geometry"/></mxCell>\n`;
cells += `<mxCell id="${SERVER.id}" value="MCP Server&#10;${esc(inv.server.name)} v${esc(inv.server.version)}" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#DAE8FC;strokeColor=#6C8EBF;fontStyle=1;" vertex="1" parent="1"><mxGeometry x="${SERVER.x}" y="${SERVER.y}" width="${SERVER.w}" height="${SERVER.h}" as="geometry"/></mxCell>\n`;
for (const risk of ["High", "Medium", "Low"]) {
  cells += `<mxCell id="hdr_${risk}" value="${columns[risk].header}" style="text;html=1;fontSize=14;fontStyle=1;align=center;" vertex="1" parent="1"><mxGeometry x="${columns[risk].x}" y="160" width="${NODE_W}" height="24" as="geometry"/></mxCell>\n`;
}
for (const n of placed) {
  const c = COLORS[n.risk];
  const value = esc(n.labelLines.join("\n")).replace(/\n/g, "&#10;");
  cells += `<mxCell id="${n.name}" value="${value}" style="rounded=0;whiteSpace=wrap;html=1;align=left;spacingLeft=6;fillColor=${c.fill};strokeColor=${c.stroke};" vertex="1" parent="1"><mxGeometry x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" as="geometry"/></mxCell>\n`;
  cells += `<mxCell id="e_${n.name}" style="endArrow=classic;html=1;strokeColor=#9AA0A6;" edge="1" parent="1" source="${SERVER.id}" target="${n.name}"><mxGeometry relative="1" as="geometry"/></mxCell>\n`;
}
// Capability-chaining edge (Attack 3).
cells += `<mxCell id="chain" value="chain → internal record disclosure (High outcome)" style="endArrow=classic;html=1;dashed=1;strokeColor=#B85450;fontColor=#B85450;fontStyle=1;" edge="1" parent="1" source="generate_export_token" target="export_record"><mxGeometry relative="1" as="geometry"/></mxCell>\n`;

const drawio = `<mxfile host="app.diagrams.net" modified="${new Date().toISOString()}" agent="p4-build-diagram" version="24.0.0">
  <diagram id="mcp-attack-surface" name="MCP Attack Surface">
    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${canvasW}" pageHeight="${canvasH}" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
${cells}      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
`;
fs.writeFileSync(path.join(__dirname, "attack_surface_map.drawio"), drawio);

// --------------------------------------------------------------------------- //
// SVG export (faithful rendering of the same layout)
// --------------------------------------------------------------------------- //
const sx = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${canvasW}" height="${canvasH}" viewBox="0 0 ${canvasW} ${canvasH}" font-family="Helvetica,Arial,sans-serif">
<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 z" fill="#9AA0A6"/></marker>
<marker id="arrowR" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 z" fill="#B85450"/></marker></defs>
<rect x="0" y="0" width="${canvasW}" height="${canvasH}" fill="#ffffff"/>
<text x="${canvasW / 2}" y="34" font-size="18" font-weight="bold" text-anchor="middle">MCP Attack Surface Map — ${sx(inv.server.name)} v${sx(inv.server.version)}</text>
<text x="${canvasW / 2}" y="60" font-size="12" text-anchor="middle">Risk colour key: Red = High · Amber = Medium · Green = Low. Dashed red = capability-chaining path (Attack 3).</text>
`;
// edges first (behind nodes)
const scx = SERVER.x + SERVER.w / 2, scy = SERVER.y + SERVER.h;
for (const n of placed) {
  const tx = n.x + n.w / 2, ty = n.y;
  svg += `<line x1="${scx}" y1="${scy}" x2="${tx}" y2="${ty}" stroke="#9AA0A6" stroke-width="1" marker-end="url(#arrow)"/>\n`;
}
// chain edge
const a = placed.find((p) => p.name === "generate_export_token");
const b = placed.find((p) => p.name === "export_record");
if (a && b) {
  svg += `<line x1="${a.x + a.w / 2}" y1="${a.y + a.h}" x2="${b.x + b.w / 2}" y2="${b.y}" stroke="#B85450" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arrowR)"/>\n`;
  svg += `<text x="${a.x + a.w + 6}" y="${(a.y + a.h + b.y) / 2}" font-size="11" fill="#B85450" font-weight="bold">chain → internal record disclosure (High)</text>\n`;
}
// column headers
for (const risk of ["High", "Medium", "Low"]) {
  svg += `<text x="${columns[risk].x + NODE_W / 2}" y="178" font-size="14" font-weight="bold" text-anchor="middle">${columns[risk].header}</text>\n`;
}
// server node
svg += `<rect x="${SERVER.x}" y="${SERVER.y}" width="${SERVER.w}" height="${SERVER.h}" rx="8" fill="#DAE8FC" stroke="#6C8EBF" stroke-width="1.5"/>\n`;
svg += `<text x="${SERVER.x + SERVER.w / 2}" y="${SERVER.y + 22}" font-size="13" font-weight="bold" text-anchor="middle">MCP Server</text>\n`;
svg += `<text x="${SERVER.x + SERVER.w / 2}" y="${SERVER.y + 40}" font-size="12" text-anchor="middle">${sx(inv.server.name)} v${sx(inv.server.version)}</text>\n`;
// capability nodes
for (const n of placed) {
  const c = COLORS[n.risk];
  svg += `<rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" fill="${c.fill}" stroke="${c.stroke}" stroke-width="1.5"/>\n`;
  let ty = n.y + 18;
  n.labelLines.forEach((ln, i) => {
    const weight = i === 0 ? "bold" : "normal";
    const size = i <= 1 ? 12 : 11;
    svg += `<text x="${n.x + 8}" y="${ty}" font-size="${size}" font-weight="${weight}">${sx(ln)}</text>\n`;
    ty += 15;
  });
}
svg += `</svg>\n`;
fs.writeFileSync(path.join(__dirname, "attack_surface_map.svg"), svg);

console.log(`Wrote diagrams/attack_surface_map.drawio and diagrams/attack_surface_map.svg (${placed.length} nodes, canvas ${canvasW}x${canvasH}).`);
