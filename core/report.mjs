// Atlasxis — geração de relatório por sink (FASE 27).
// Formatos: json | markdown | sarif. Determinístico (sem timestamps/random).

import { readFileSync } from "node:fs";

const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

const CONF = {
  CONTROLLED: "PROVEN", VULNERABLE: "DEMONSTRATED", INSUFFICIENT_EVIDENCE: "UNPROVEN",
  NOT_ANALYZED: "UNMODELED", OUT_OF_SCOPE_PROVEN: "OUT_OF_SCOPE", OUT_OF_SCOPE_UNVERIFIED: "SUSPECTED_OOS",
};

// entra: [{path, handlers:[{method, client, decision, sinkDecisions}]}]
export function buildReport(files) {
  const findings = [];
  for (const f of files) for (const h of f.handlers) {
    const units = h.sinkDecisions.length ? h.sinkDecisions : [h.decision];
    for (const d of units) {
      findings.push({
        path: f.path, method: h.method, client: h.client,
        ...(d.sink?.file && d.sink.file !== f.path ? { sinkFile: d.sink.file } : {}),
        resource: d.sink?.table ?? d.proof?.sink?.table ?? null,
        operation: d.sink?.op ?? d.proof?.sink?.op ?? null,
        decision: d.status, confidence: CONF[d.status] || d.status,
        mechanism: d.proof?.mechanism ?? null, reasonCode: d.reasonCode,
        assumptions: (d.assumptions || []).map((a) => a.id),
        unknowns: d.unknowns || [],
        proof: d.proof ? proofSummary(d.proof) : null,
      });
    }
  }
  const counts = {};
  for (const x of findings) counts[x.decision] = (counts[x.decision] || 0) + 1;
  return { summary: counts, totalSinks: findings.length, findings };
}

function proofSummary(p) {
  return {
    source: p.source?.expr ?? p.source?.kind ?? null,
    resource: p.resource?.table ?? p.resource?.idExpr ?? null,
    authorization: p.authorization?.kind ?? null,
    guard: p.guard?.kind ?? null,
    identity: p.identity ? { same: p.identity.same, method: p.identity.method, witnesses: (p.identity.witness || []).length } : null,
    sink: p.sink ? `${p.sink.op} ${p.sink.table}` : null,
    steps: (p.steps || []).map((s) => s.kind),
  };
}

export function toJSON(report) { return JSON.stringify(report, null, 2); }

export function toMarkdown(report) {
  const L = [];
  L.push("# Atlasxis — Authorization Proof Report", "");
  L.push("> Certifica a presença de evidência de autorização para os caminhos prováveis. Não certifica ausência de vulnerabilidades.", "");
  L.push("## Resumo por sink", "");
  L.push("| Decisão | Sinks |", "|---|---|");
  for (const [k, v] of Object.entries(report.summary).sort()) L.push(`| ${k} | ${v} |`);
  L.push("", `Total de sinks: **${report.totalSinks}**`, "");
  const order = { VULNERABLE: 0, CONTROLLED: 1, INSUFFICIENT_EVIDENCE: 2, OUT_OF_SCOPE_UNVERIFIED: 3, OUT_OF_SCOPE_PROVEN: 4, NOT_ANALYZED: 5 };
  const sorted = [...report.findings].sort((a, b) => (order[a.decision] - order[b.decision]) || a.path.localeCompare(b.path));
  for (const x of sorted) {
    L.push("---", "", `### ${x.decision} — \`${x.method} ${x.path}\``, "");
    if (x.resource) L.push(`- **Sink**: ${x.operation} \`${x.resource}\``);
    L.push(`- **Confiança**: ${x.confidence}`, `- **Reason code**: \`${x.reasonCode}\``);
    if (x.mechanism) L.push(`- **Mecanismo**: ${x.mechanism}`);
    if (x.proof) {
      L.push("- **Cadeia de prova**:");
      L.push("  ```");
      L.push(`  SOURCE        ${x.proof.source}`);
      L.push(`  RESOURCE      ${x.proof.resource}`);
      L.push(`  AUTHORIZATION ${x.proof.authorization}`);
      L.push(`  GUARD         ${x.proof.guard}`);
      L.push(`  IDENTITY      same=${x.proof.identity?.same} (${x.proof.identity?.method}, ${x.proof.identity?.witnesses} witnesses)`);
      L.push(`  SINK          ${x.proof.sink}`);
      L.push("  ```");
    }
    if (x.assumptions.length) L.push(`- **Assumptions**: ${x.assumptions.join(", ")}`);
    if (x.unknowns.length) L.push(`- **Não provado**: ${x.unknowns.join("; ")}`);
    L.push("");
  }
  return L.join("\n");
}

// SARIF 2.1.0 — só VULNERABLE e INSUFFICIENT viram "results" (o resto é informativo)
export function toSARIF(report) {
  const rules = {}, results = [];
  const levelOf = (d) => d === "VULNERABLE" ? "error" : d === "INSUFFICIENT_EVIDENCE" ? "warning" : "note";
  for (const x of report.findings) {
    if (x.decision === "CONTROLLED" || x.decision === "OUT_OF_SCOPE_PROVEN" || x.decision === "NOT_ANALYZED") continue;
    rules[x.reasonCode] ??= { id: x.reasonCode, name: x.reasonCode, shortDescription: { text: x.reasonCode } };
    results.push({
      ruleId: x.reasonCode, level: levelOf(x.decision),
      message: { text: `${x.decision} (${x.confidence}) em ${x.method} ${x.operation || ""} ${x.resource || ""}: ${(x.unknowns[0] || x.reasonCode)}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: x.path } } }],
    });
  }
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "Atlasxis", informationUri: "https://github.com/atlasxis/atlasxis", version: VERSION, rules: Object.values(rules) } }, results }],
  }, null, 2);
}
