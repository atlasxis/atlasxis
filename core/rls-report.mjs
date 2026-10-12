// Atlasxis — relatórios da auditoria de RLS por tabela (json | markdown | sarif).
// Determinístico: sem timestamps nem aleatoriedade.

import { EXPLANATIONS } from "./explanations.mjs";

const OPS = ["select", "insert", "update", "delete"];

const CELL = {
  CONTROLLED_RLS_POLICY_OWNER: "ok:dono",
  CONTROLLED_RLS_DEFAULT_DENY: "ok:nega",
  CONTROLLED_PRIVILEGE_NOT_GRANTED: "ok:sem-priv",
  VULNERABLE_RLS_TABLE_EXPOSED: "VULNERÁVEL",
  VULNERABLE_RLS_POLICY_OPEN_WRITE: "VULNERÁVEL",
};
const cellOf = (d) => CELL[d.reasonCode] ?? (d.status === "INSUFFICIENT_EVIDENCE" ? "?" : d.status === "NOT_ANALYZED" ? "—" : d.status);

export function rlsToJSON(audit, meta) {
  return JSON.stringify({
    mode: audit.mode, meta, summary: audit.summary, tables: audit.tables, grantsSeen: audit.grantsSeen,
    findings: audit.findings.map((f) => ({
      table: f.table, schema: f.schema, role: f.role, op: f.op, file: f.file,
      decision: f.decision.status, reasonCode: f.decision.reasonCode,
      assumptions: f.decision.assumptions.map((a) => a.id),
      unknowns: f.decision.unknowns,
      proof: f.decision.proof ? { mechanism: f.decision.proof.mechanism, declared: f.decision.proof.authorization?.declared ?? null, steps: f.decision.proof.steps.map((s) => s.detail) } : null,
    })),
  }, null, 2);
}

export function rlsToMarkdown(audit, meta) {
  const L = [];
  L.push("# Atlasxis — Auditoria de RLS por tabela", "");
  L.push("> Afirma somente: (a) acessos com evidência suficiente de controle; (b) acessos com evidência suficiente de exposição; (c) o que não foi possível provar. Nunca afirma que o banco está seguro.", "");
  L.push(`Tabelas: ${audit.tables} · GRANT/REVOKE reconhecidos: ${audit.grantsSeen} · fonte: ${meta.source} · grants padrão do Supabase presumidos: ${meta.assumeDefaultGrants ? "SIM (declarado)" : "não"}`, "");
  L.push("## Resumo", "", "| Decisão | Células (tabela × papel × operação) |", "|---|---|");
  for (const [k, v] of Object.entries(audit.summary).sort()) L.push(`| ${k} | ${v} |`);
  if (!audit.findings.length) { L.push("", "_Nenhuma tabela encontrada no SQL._", ""); return L.join("\n"); }

  L.push("", "## Matriz", "", "Legenda: `ok:dono` policies restringem ao dono · `ok:nega` RLS ligado sem policy liberando · `ok:sem-priv` papel sem privilégio · `VULNERÁVEL` exposição com evidência positiva · `?` não foi possível provar (NÃO é seguro) · `—` fora do escopo", "");
  L.push("| Tabela | Papel | SELECT | INSERT | UPDATE | DELETE |", "|---|---|---|---|---|---|");
  const byKey = new Map(audit.findings.map((f) => [`${f.table}|${f.role}|${f.op}`, f]));
  const tables = [...new Set(audit.findings.map((f) => f.table))];
  for (const t of tables) {
    const na = byKey.get(`${t}|*|*`);
    if (na) { L.push(`| \`${t}\` | — | — | — | — | — |`); continue; }
    for (const role of ["anon", "authenticated"])
      L.push(`| \`${t}\` | ${role} | ${OPS.map((op) => cellOf(byKey.get(`${t}|${role}|${op}`).decision)).join(" | ")} |`);
  }

  const vulns = audit.findings.filter((f) => f.decision.status === "VULNERABLE");
  if (vulns.length) {
    L.push("", `## VULNERABLE (${vulns.length})`, "");
    const groups = new Map();
    for (const f of vulns) {
      const k = `${f.table}|${f.decision.reasonCode}`;
      if (!groups.has(k)) groups.set(k, { f, cells: [], assumptions: new Set() });
      const g = groups.get(k);
      g.cells.push(`${f.role} ${f.op.toUpperCase()}`);
      for (const a of f.decision.assumptions) g.assumptions.add(a.id);
    }
    for (const { f, cells, assumptions } of groups.values()) {
      L.push(`### \`${f.table}\` — \`${f.decision.reasonCode}\``, "");
      if (f.file) L.push(`- **Arquivo**: ${f.file}`);
      L.push(`- **Células**: ${cells.join(", ")}`);
      L.push(`- **Significado**: ${EXPLANATIONS[f.decision.reasonCode]?.meaning ?? ""}`);
      L.push(`- **Evidência positiva** (exemplo: ${f.role} ${f.op.toUpperCase()}; a mesma cadeia vale para as demais células):`);
      for (const st of f.decision.proof.steps) L.push(`  - ${st.detail}`);
      L.push(`- **Assumptions**: ${[...assumptions].join(", ")}`, "");
    }
  }

  const insuf = audit.findings.filter((f) => f.decision.status === "INSUFFICIENT_EVIDENCE");
  if (insuf.length) {
    L.push("", `## INSUFFICIENT_EVIDENCE (${insuf.length}) — não foi possível provar; NÃO significa seguro`, "");
    const groups = new Map();
    for (const f of insuf) {
      const k = `${f.table}|${f.decision.reasonCode}`;
      if (!groups.has(k)) groups.set(k, { f, cells: [], unknowns: new Set() });
      const g = groups.get(k);
      g.cells.push(`${f.role} ${f.op.toUpperCase()}`);
      for (const u of f.decision.unknowns) g.unknowns.add(u);
    }
    for (const { f, cells, unknowns } of groups.values()) {
      L.push(`### \`${f.table}\` — \`${f.decision.reasonCode}\``, "");
      L.push(`- **Células**: ${cells.join(", ")}`);
      L.push(`- **O que faltou provar**: ${EXPLANATIONS[f.decision.reasonCode]?.not_proven ?? ""}`);
      for (const u of unknowns) L.push(`- ${u}`);
      L.push("");
    }
  }
  return L.join("\n") + "\n";
}

export function rlsToSARIF(audit, meta) {
  const rules = {}, results = [];
  for (const f of audit.findings) {
    const d = f.decision;
    if (d.status !== "VULNERABLE" && d.status !== "INSUFFICIENT_EVIDENCE") continue;
    rules[d.reasonCode] ??= { id: d.reasonCode, name: d.reasonCode, shortDescription: { text: EXPLANATIONS[d.reasonCode]?.meaning ?? d.reasonCode } };
    results.push({
      ruleId: d.reasonCode, level: d.status === "VULNERABLE" ? "error" : "warning",
      message: { text: `${d.status}: ${f.role} ${f.op.toUpperCase()} em ${f.table} — ${d.unknowns[0] ?? EXPLANATIONS[d.reasonCode]?.meaning ?? ""}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file ?? "supabase" } } }],
    });
  }
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "Atlasxis", informationUri: "https://github.com/atlasxis/atlasxis", version: meta.version, rules: Object.values(rules) } }, results }],
  }, null, 2);
}
