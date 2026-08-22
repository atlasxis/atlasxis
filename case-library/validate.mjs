// Case Library — validador executável (sem dependências).
// Falha (exit 1) se qualquer caso violar o contrato:
//   - campos obrigatórios ausentes ou estado inválido;
//   - ground_truth.source fora de {human, construction} ('oracle' é circular e proibido);
//   - CERTIFIED sem os 10 requisitos todos true;
//   - CERTIFIED com referência de fixture inexistente;
//   - id do arquivo ≠ id do caso.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
// Diretório de casos: padrão `cases/`; a árvore pública usa `cases-public/`.
// Aceita override por argumento (nome relativo a case-library/ ou caminho).
const arg = process.argv[2];
const casesDir = arg ? (existsSync(arg) ? arg : join(here, arg)) : (existsSync(join(here, "cases")) ? join(here, "cases") : join(here, "cases-public"));

const STATES = ["OBSERVED", "REVIEWED", "VALIDATED", "CANDIDATE", "CERTIFIED", "REJECTED"];
const REQUIRED = ["id", "title", "status", "origin", "mechanism", "oracle_result", "ground_truth", "evidence"];
const CERT_KEYS = ["real_case", "ground_truth", "fixture_positive", "fixture_negative", "fixture_adversarial",
  "regression_pass", "mutation_pass", "benchmark_pass", "external_pass", "no_false_control_increase"];

let fail = 0;
const err = (id, msg) => { fail++; console.log(`  ✗ ${id}: ${msg}`); };

const files = readdirSync(casesDir).filter((f) => f.endsWith(".json")).sort();
console.log(`CASE LIBRARY — ${files.length} casos\n`);
const counts = {};
for (const f of files) {
  let c;
  try { c = JSON.parse(readFileSync(join(casesDir, f), "utf8")); }
  catch (e) { err(f, `JSON inválido: ${e.message}`); continue; }
  const id = c.id ?? f;
  for (const k of REQUIRED) if (!(k in c)) err(id, `campo obrigatório ausente: ${k}`);
  if (f !== `${c.id}.json`) err(id, `nome do arquivo (${f}) ≠ id (${c.id}.json)`);
  if (!STATES.includes(c.status)) err(id, `estado inválido: ${c.status}`);
  const src = c.ground_truth?.source;
  if (!["human", "construction"].includes(src)) err(id, `ground_truth.source proibido/inválido: ${src} (nunca 'oracle')`);
  if (c.status === "CERTIFIED") {
    const cert = c.certification || {};
    for (const k of CERT_KEYS) if (cert[k] !== true) err(id, `CERTIFIED exige certification.${k} === true`);
    const refs = [...(c.fixtures?.positive || []), ...(c.fixtures?.negative || []), ...(c.fixtures?.adversarial || [])];
    if (!refs.length) err(id, "CERTIFIED sem nenhuma fixture referenciada");
    for (const r of refs) if (!existsSync(join(root, r))) err(id, `fixture inexistente: ${r}`);
    if (!c.regression) err(id, "CERTIFIED sem harness de regressão");
  }
  if (c.code_ref && !existsSync(join(root, c.code_ref))) err(id, `code_ref inexistente: ${c.code_ref}`);
  counts[c.status] = (counts[c.status] || 0) + 1;
  if (!fail) console.log(`  ✓ ${id} [${c.status}]`);
}
console.log(`\nestados: ${Object.entries(counts).sort().map(([k, v]) => `${k}=${v}`).join(" ")}`);
console.log(fail ? `\nFALHAS: ${fail}` : "\ncase library íntegra");
process.exit(fail ? 1 : 0);
