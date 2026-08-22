// ORÁCULO CORE — runner do benchmark (FASE 5).
// Mede correção contra ground truth POR CONSTRUÇÃO. Separa explicitamente:
//   - correctness: expectedDecision == actual (o que um certificador correto deve dar)
//   - false-control: groundTruth=VULNERABLE mas actual=CONTROLLED (o erro fatal)
//   - false-vuln: groundTruth=SAFE mas actual=VULNERABLE
//   - coverage: quantos SAFE realmente provados (CONTROLLED) — separado de correção

import { analyzeFileIR } from "../engine.mjs";
import { parseSqlCorpus } from "../rls.mjs";
import { validateDecision } from "../ir.mjs";
import { BENCHMARK } from "./generate.mjs";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "../harness/out");
mkdirSync(OUT, { recursive: true });

const rlsOf = (c) => c.sql ? { model: parseSqlCorpus(c.sql), declared: {}, options: {} } : (c.rls || {});

let mismatches = 0, falseControl = 0, falseVuln = 0, integrityFail = 0;
const byCat = {};
const rows = [];

for (const c of BENCHMARK) {
  const res = analyzeFileIR(c.files, c.entry, rlsOf(c));
  const d = res[0].decision;
  const actual = d.status, reason = d.reasonCode;
  // integridade de prova em toda decisão
  for (const sd of res[0].sinkDecisions) if (validateDecision(sd).length) integrityFail++;
  if (validateDecision(d).length) integrityFail++;

  const decisionOk = actual === c.expectedDecision;
  const reasonOk = !c.expectedReasonCodes || c.expectedReasonCodes.includes(reason) || actual !== c.expectedDecision;
  const sinkOk = c.expectedSinkCount == null || res[0].sinkDecisions.filter((s) => s.sink).length >= (c.expectedSinkCount ? 1 : 0);

  // erros fatais (independentes de "expected"): confronto com ground truth
  if (c.groundTruth === "VULNERABLE" && actual === "CONTROLLED") falseControl++;
  if (c.groundTruth === "SAFE" && actual === "VULNERABLE") falseVuln++;

  const ok = decisionOk && reasonOk;
  if (!ok) mismatches++;
  byCat[c.cat] ??= { n: 0, ok: 0 };
  byCat[c.cat].n++; if (ok) byCat[c.cat].ok++;
  rows.push({ id: c.id, cat: c.cat, groundTruth: c.groundTruth, expected: c.expectedDecision, actual, reason, ok, decisionOk, reasonOk });
}

// coverage separado de correção
const safe = BENCHMARK.filter((c) => c.groundTruth === "SAFE");
const safeProven = rows.filter((r, i) => BENCHMARK[i].groundTruth === "SAFE" && r.actual === "CONTROLLED").length;

console.log(`\n===== BENCHMARK: ${BENCHMARK.length} casos =====`);
console.log("por categoria (ok/total):");
for (const [k, v] of Object.entries(byCat).sort()) console.log(`  ${k.padEnd(26)} ${v.ok}/${v.n}${v.ok < v.n ? "  ⚠" : ""}`);
console.log("\nCORREÇÃO (expectedDecision == actual):", (BENCHMARK.length - mismatches) + "/" + BENCHMARK.length, `(${((1 - mismatches / BENCHMARK.length) * 100).toFixed(1)}%)`);
console.log("FALSE-CONTROL (VULNERABLE visto como CONTROLLED):", falseControl, falseControl === 0 ? "✓" : "✗ FATAL");
console.log("FALSE-VULN   (SAFE visto como VULNERABLE):", falseVuln, falseVuln === 0 ? "✓" : "✗");
console.log("PROOF INTEGRITY falhas:", integrityFail, integrityFail === 0 ? "✓" : "✗");
console.log("COVERAGE (SAFE provados CONTROLLED):", `${safeProven}/${safe.length} (${(safeProven / safe.length * 100).toFixed(1)}%) — separado de correção`);

writeFileSync(join(OUT, "benchmark-results.json"), JSON.stringify({ total: BENCHMARK.length, mismatches, falseControl, falseVuln, integrityFail, byCat, rows }, null, 1));

const fatal = falseControl > 0 || falseVuln > 0 || integrityFail > 0;
if (mismatches > 0) { console.log("\nMISMATCHES:"); rows.filter((r) => !r.ok).slice(0, 30).forEach((r) => console.log(`  ${r.id} [${r.cat}] gt=${r.groundTruth} esp=${r.expected} got=${r.actual} (${r.reason})`)); }
process.exit(fatal ? 1 : 0);
