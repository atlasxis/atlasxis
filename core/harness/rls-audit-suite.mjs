// Atlasxis — certificação da auditoria de RLS por tabela.
// Para cada caso (positivo, negativo, adversarial):
//   - a decisão de cada célula esperada bate com o gabarito (por construção);
//   - nenhuma célula proibida aparece (armadilhas de falso CONTROLLED);
//   - Proof Integrity = 0 em TODA decisão emitida;
//   - mutação causal: remover o elemento que sustenta cada CONTROLLED/VULNERABLE
//     esperado TEM que mudar a decisão (0 sobreviventes).
// Gates: fail = 0, false-control = 0, false-vuln = 0, integrity = 0, survivors = 0.

import { parseSqlCorpus } from "../rls.mjs";
import { auditTables } from "../rls-audit.mjs";
import { validateDecision } from "../ir.mjs";
import { RLS_AUDIT_CASES, RLS_MUTATORS } from "../fixtures/rls-audit.mjs";

const asFiles = (sql) => (typeof sql === "string" ? { "001.sql": sql } : sql);
const mapFiles = (sql, fn) => Object.fromEntries(Object.entries(asFiles(sql)).map(([k, v]) => [k, fn(v)]));

function run(sql, opts = {}) {
  const audit = auditTables(parseSqlCorpus(asFiles(sql)), opts);
  const cells = new Map(audit.findings.map((f) => [`${f.table}/${f.role}/${f.op}`, f.decision]));
  let integrity = 0;
  for (const f of audit.findings) { const v = validateDecision(f.decision); if (v.length) { integrity++; console.log(`    ✗ INTEGRIDADE ${f.table}/${f.role}/${f.op}: ${v.join("; ")}`); } }
  return { cells, integrity };
}

let fail = 0, falseControl = 0, falseVuln = 0, integrity = 0, mutations = 0, survivors = 0, nondeterministic = 0;
const byKind = {};
console.log("=== CERTIFICAÇÃO — auditoria de RLS por tabela ===");
for (const c of RLS_AUDIT_CASES) {
  const opts = c.opts || {};
  const r = run(c.sql, opts);
  integrity += r.integrity;
  // determinismo: a mesma entrada produz exatamente a mesma saída
  const again = run(c.sql, opts);
  const ser = (m) => JSON.stringify([...m.cells.entries()]);
  if (ser(r) !== ser(again)) { nondeterministic++; }
  let ok = true; const notes = [];
  for (const [cell, exp] of Object.entries(c.expect || {})) {
    const got = r.cells.get(cell);
    if (!got) { ok = false; notes.push(`${cell}: célula ausente`); continue; }
    if (got.reasonCode !== exp) {
      ok = false; notes.push(`${cell}: esperado ${exp}, obtido ${got.reasonCode}`);
      if (got.status === "CONTROLLED" && !exp.startsWith("CONTROLLED")) falseControl++;
      if (got.status === "VULNERABLE" && !exp.startsWith("VULNERABLE")) falseVuln++;
    }
  }
  for (const [cell, forbidden] of Object.entries(c.mustNot || {})) {
    const got = r.cells.get(cell);
    if (!got) { ok = false; notes.push(`${cell}: célula ausente`); continue; }
    if (got.status === forbidden) {
      ok = false; notes.push(`${cell}: ${forbidden} proibido (obtido ${got.reasonCode})`);
      if (forbidden === "CONTROLLED") falseControl++;
      if (forbidden === "VULNERABLE") falseVuln++;
    }
  }
  // mutação causal sobre cada CONTROLLED/VULNERABLE esperado
  let mut = 0, surv = 0;
  for (const [cell, exp] of Object.entries(c.expect || {})) {
    const claimed = exp.startsWith("CONTROLLED") ? "CONTROLLED" : exp.startsWith("VULNERABLE") ? "VULNERABLE" : null;
    if (!claimed) continue;
    for (const m of RLS_MUTATORS[exp] || []) {
      mut++; mutations++;
      const mutated = run(mapFiles(c.sql, m.apply), { ...opts, ...(m.opts || {}) });
      const after = mutated.cells.get(cell);
      // detectada = a PROVA citada deixou de valer (o reason code mudou). Se outra
      // prova independente e válida assumir (ex.: privilégio removido, mas RLS
      // ainda nega), a original era causal mesmo assim.
      if (after && after.reasonCode === exp) { surv++; survivors++; notes.push(`mutação "${m.name}" em ${cell} sobreviveu (${after.reasonCode})`); }
      else if (after && after.status === claimed) notes.push(`mutação "${m.name}" em ${cell}: prova original caiu; outra prova válida assumiu (${after.reasonCode})`);
    }
  }
  if (!ok || surv) fail++;
  byKind[c.kind] = byKind[c.kind] || { n: 0, ok: 0 }; byKind[c.kind].n++; if (ok && !surv) byKind[c.kind].ok++;
  console.log(`  ${ok && !surv ? "✓" : "✗"} ${c.id.padEnd(38)} [${c.kind}]${mut ? ` mutações ${mut - surv}/${mut}` : ""}`);
  for (const n of notes) console.log(`      ${n}`);
}
console.log(`\npor tipo: ${Object.entries(byKind).map(([k, v]) => `${k} ${v.ok}/${v.n}`).join(" · ")}`);
console.log(`mutações causais: ${mutations - survivors}/${mutations} detectadas`);
console.log(`determinismo: ${RLS_AUDIT_CASES.length - nondeterministic}/${RLS_AUDIT_CASES.length} casos idênticos em 2 execuções`);
console.log(`rls-audit: cases=${RLS_AUDIT_CASES.length} fail=${fail} false-control=${falseControl} false-vuln=${falseVuln} integrity=${integrity} survivors=${survivors}`);
process.exit(fail || falseControl || falseVuln || integrity || survivors || nondeterministic ? 1 : 0);
