// Validação humana cega — comparador (READ-ONLY).
// Compara: humano × Atlasxis × ground truth selado (por construção).
// NUNCA altera o ground truth nem o corpus. NUNCA preenche o formulário.
// Só roda quando auditor-form.json tiver ao menos uma classificação humana real.
//
// Ground truth (selado): SAFE | VULNERABLE | UNKNOWN (semântico, por construção).
// Atlasxis: CONTROLLED | VULNERABLE | INSUFFICIENT_EVIDENCE | NOT_ANALYZED | OUT_OF_SCOPE_*.
// Humano: CONTROLLED | VULNERABLE | INSUFFICIENT | NOT_ANALYZED.
//
// Regras de correção (CORRETUDE > COBERTURA):
//   - false-control  = Atlasxis CONTROLLED, mas gt = VULNERABLE   (erro grave)
//   - false-vuln     = Atlasxis VULNERABLE, mas gt ∈ {SAFE,UNKNOWN}
//   - control TP     = Atlasxis CONTROLLED e gt = SAFE
//   - vuln TP        = Atlasxis VULNERABLE e gt = VULNERABLE
//   - abstenção (INSUFFICIENT/NOT_ANALYZED/OOS) NUNCA é SAFE; abster num caso
//     realmente vulnerável é FN de COBERTURA (não é afirmação incorreta).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeFileIR } from "../core/engine.mjs";
import { parseSqlCorpus } from "../core/rls.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(here, "blind-corpus.json"), "utf8"));
const form = JSON.parse(readFileSync(join(here, "auditor-form.json"), "utf8"));
const sealed = JSON.parse(readFileSync(join(here, "SEALED-ground-truth.json"), "utf8"));

const filled = form.filter((f) => f.human_decision && String(f.human_decision).trim());
if (!filled.length) {
  console.log("HUMAN_VALIDATION = PENDING — auditor-form.json sem classificação humana.");
  console.log("Nenhuma comparação executada. O ground truth NÃO foi aberto para o motor.");
  console.log("Preencha auditor-form.json (human_decision por caso) e rode de novo.");
  process.exit(0);
}

// decisão do Atlasxis por caso (o motor roda sobre o mesmo material que o humano viu)
const engineDecision = {};
for (const c of corpus) {
  const rls = c.sql ? { model: parseSqlCorpus(c.sql), declared: {}, options: {} } : {};
  engineDecision[c.case_id] = analyzeFileIR(c.files, c.entry, rls)[0].decision.status;
}
const gt = Object.fromEntries(sealed.map((s) => [s.case_id, s.ground_truth]));

const norm = (s) => String(s || "").toUpperCase().replace("_EVIDENCE", "").replace(/^OUT_OF_SCOPE.*/, "OUT_OF_SCOPE");
const isAbstention = (d) => ["INSUFFICIENT", "NOT_ANALYZED", "OUT_OF_SCOPE"].includes(norm(d));

const M = {
  n: filled.length,
  controlTP: 0, controlFN: 0,      // gt SAFE
  vulnTP: 0, vulnFN: 0,            // gt VULNERABLE
  falseControl: 0, falseVuln: 0,  // erros de correção
  controlledOnUnknown: 0,         // Atlasxis CONTROLLED sobre gt UNKNOWN (erro: afirmou prova sem base)
  insufficient: 0, notAnalyzed: 0, outOfScope: 0,
  humanOracleAgree: 0, humanGtCorrect: 0,
};
const divergences = [];

console.log("caso                         humano        Atlasxis       gt");
console.log("─".repeat(74));
for (const f of filled) {
  const oc = norm(engineDecision[f.case_id]);
  const h = norm(f.human_decision);
  const g = String(gt[f.case_id] || "").toUpperCase();

  if (isAbstention(oc)) { if (norm(engineDecision[f.case_id]) === "INSUFFICIENT") M.insufficient++; else if (norm(engineDecision[f.case_id]) === "NOT_ANALYZED") M.notAnalyzed++; else M.outOfScope++; }
  if (oc === "CONTROLLED" && g === "VULNERABLE") M.falseControl++;
  if (oc === "CONTROLLED" && g === "UNKNOWN") M.controlledOnUnknown++;
  if (oc === "VULNERABLE" && (g === "SAFE" || g === "UNKNOWN")) M.falseVuln++;
  if (g === "SAFE") { if (oc === "CONTROLLED") M.controlTP++; else M.controlFN++; }
  if (g === "VULNERABLE") { if (oc === "VULNERABLE") M.vulnTP++; else M.vulnFN++; }

  // humano
  if (h === oc) M.humanOracleAgree++;
  const humanCorrect = (g === "SAFE" && h === "CONTROLLED") || (g === "VULNERABLE" && h === "VULNERABLE") || (g === "UNKNOWN" && isAbstention(h));
  if (humanCorrect) M.humanGtCorrect++;

  const flag = h === oc ? " " : "≠";
  if (h !== oc) divergences.push({ case_id: f.case_id, human: h, engine: oc, gt: g, reason: f.human_reason || "" });
  console.log(`${f.case_id.padEnd(28)} ${h.padEnd(13)} ${oc.padEnd(13)} ${g.padEnd(10)} ${flag}`);
}

console.log("\n===== MÉTRICAS (Atlasxis × ground truth selado) =====");
console.log(`casos avaliados: ${M.n}/42`);
console.log(`false-control (CONTROLLED sobre gt VULNERABLE): ${M.falseControl}  ${M.falseControl ? "✗ ERRO GRAVE" : "✓"}`);
console.log(`false-vuln (VULNERABLE sobre gt SAFE/UNKNOWN):   ${M.falseVuln}  ${M.falseVuln ? "✗" : "✓"}`);
console.log(`CONTROLLED sobre gt UNKNOWN (prova sem base):    ${M.controlledOnUnknown}  ${M.controlledOnUnknown ? "✗ REVISAR" : "✓"}`);
console.log(`control TP / (TP+FN):  ${M.controlTP}/${M.controlTP + M.controlFN}   (FN = abstenção sobre caso seguro; coverage, não erro)`);
console.log(`vuln TP / (TP+FN):     ${M.vulnTP}/${M.vulnTP + M.vulnFN}   (FN = abstenção sobre caso vulnerável; coverage, não erro)`);
console.log(`abstenções: INSUFFICIENT=${M.insufficient}  NOT_ANALYZED=${M.notAnalyzed}  OUT_OF_SCOPE=${M.outOfScope}`);
console.log("\n===== HUMANO =====");
console.log(`concordância humano × Atlasxis: ${M.humanOracleAgree}/${M.n}`);
console.log(`humano correto vs ground truth: ${M.humanGtCorrect}/${M.n}`);
console.log(`divergências humano × Atlasxis: ${divergences.length}`);
for (const d of divergences) console.log(`  ${d.case_id}: humano=${d.human} Atlasxis=${d.engine} gt=${d.gt}${d.reason ? ` — "${d.reason}"` : ""}`);

const criticalFail = M.falseControl > 0 || M.falseVuln > 0 || M.controlledOnUnknown > 0;
console.log(`\nVEREDITO: ${criticalFail ? "✗ há erro de correção — investigar (NUNCA ajustar fixture/engine para esconder)" : "✓ nenhum erro de correção detectado"}`);
console.log("Lembrete: FN de coverage NÃO é motivo para transformar abstenção em afirmação.");
process.exit(0);
