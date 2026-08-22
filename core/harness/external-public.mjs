// ORÁCULO CORE — validação pública sobre corpus sintético (public-corpus/).
// Substitui a validação externa do mantenedor (13 repos reais, não
// redistribuíveis) por mini-projetos SINTÉTICOS, project-shaped, que exercitam
// os mecanismos que o ORÁCULO afirma entender. Cada caso declara o veredito
// esperado (ground truth por construção) e verificamos:
//   - a decisão do engine bate com o esperado;
//   - Proof Integrity = 0 em TODA decisão (invariante executável);
//   - nenhum false-control / false-vuln.
// NÃO é recall do mundo real: é demonstração reprodutível dos mecanismos.

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeFileIR } from "../engine.mjs";
import { parseSqlCorpus } from "../rls.mjs";
import { validateDecision } from "../ir.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(here, "../../public-corpus");

// ground truth por construção (mecanismo → veredito esperado do sink relevante)
const EXPECTED = {
  "self-scope": "CONTROLLED",
  "post-read-gate": "CONTROLLED",
  "helper-ownership": "CONTROLLED",
  "parent-child": "CONTROLLED",
  "rls-owner": "CONTROLLED",
  "service-role-vuln": "VULNERABLE",
  "admin-gate": "OUT_OF_SCOPE_PROVEN",
  "unsupported": "NOT_ANALYZED",
};

function walk(dir, test, out = [], depth = 0) {
  if (depth > 12) return out;
  let ents; try { ents = readdirSync(dir); } catch { return out; }
  for (const e of ents.sort()) {
    if (["node_modules", ".git"].includes(e)) continue;
    const p = join(dir, e); let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, test, out, depth + 1);
    else if (test(p)) out.push(p);
  }
  return out;
}

function loadProject(root) {
  const tsFiles = walk(root, (p) => /\.(ts|tsx)$/.test(p) && !/\.d\.ts$/.test(p));
  const files = {};
  for (const p of tsFiles) files[relative(root, p)] = readFileSync(p, "utf8");
  const routes = Object.keys(files).filter((p) => /(^|\/)src\/app\/api\/.*route\.(ts|tsx)$/.test(p) || /(^|\/)app\/api\/.*route\.(ts|tsx)$/.test(p));
  const sql = {};
  const sqlDir = join(root, "supabase");
  if (existsSync(sqlDir)) for (const p of walk(sqlDir, (x) => x.endsWith(".sql"))) sql[relative(root, p)] = readFileSync(p, "utf8");
  const rls = Object.keys(sql).length ? { model: parseSqlCorpus(sql), declared: {}, options: {} } : {};
  return { files, routes, rls };
}

let fail = 0, integrity = 0, falseControl = 0, falseVuln = 0;
const dist = {};
console.log("=== VALIDAÇÃO PÚBLICA (corpus sintético) ===");
for (const name of Object.keys(EXPECTED).sort()) {
  const root = join(CORPUS, name);
  const { files, routes, rls } = loadProject(root);
  const statuses = [];
  for (const rp of routes.sort()) {
    const hs = analyzeFileIR(files, rp, rls);
    for (const h of hs) {
      const units = h.sinkDecisions.length ? h.sinkDecisions : [h.decision];
      for (const d of units) {
        statuses.push(d.status);
        dist[d.status] = (dist[d.status] || 0) + 1;
        if (validateDecision(d).length) integrity++;
      }
    }
  }
  const exp = EXPECTED[name];
  const got = statuses.includes(exp) ? exp : (statuses[0] || "NENHUM");
  const ok = statuses.includes(exp);
  // erros fatais: esperado VULNERABLE mas veio CONTROLLED, ou vice-versa
  if (exp === "VULNERABLE" && statuses.includes("CONTROLLED")) falseControl++;
  if (exp === "CONTROLLED" && statuses.includes("VULNERABLE")) falseVuln++;
  if (!ok) fail++;
  console.log(`  ${ok ? "✓" : "✗"} ${name.padEnd(20)} esperado=${exp.padEnd(20)} → ${statuses.join(",")}`);
}
console.log(`\ndistribuição: ${Object.entries(dist).sort().map(([k, v]) => `${k}=${v}`).join(" ")}`);
console.log(`fail=${fail} false-control=${falseControl} false-vuln=${falseVuln} integrity=${integrity}`);
process.exit(fail || falseControl || falseVuln || integrity ? 1 : 0);
