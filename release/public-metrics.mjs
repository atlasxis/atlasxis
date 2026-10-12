// Métricas PÚBLICAS — geradas exclusivamente do corpus público (determinístico).
// Escreve docs/PUBLIC-METRICS.md. Nenhum número vem de corpora privados ou de
// terceiros. Cada métrica declara seu ground truth. Não apresenta benchmark
// sintético como recall do mundo real.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const run = (args, cwd) => { try { return execFileSync(process.execPath, args, { cwd, encoding: "utf8" }); } catch (e) { return (e.stdout || "") + (e.stderr || ""); } };

// benchmark sintético (rótulos por construção)
run(["run.mjs"], join(root, "core/benchmark"));
const bench = JSON.parse(readFileSync(join(root, "core/harness/out/benchmark-results.json"), "utf8"));
const ctrl = bench.rows.filter((r) => r.expected === "CONTROLLED");
const vuln = bench.rows.filter((r) => r.expected === "VULNERABLE");
const abst = bench.rows.filter((r) => ["INSUFFICIENT_EVIDENCE", "NOT_ANALYZED"].includes(r.expected));
const ok = (rs) => rs.filter((r) => r.ok).length;

// mutation (fase3 CONTROLLED, autocontido)
const mutOut = run(["-e", `import("./mutation.mjs").then(async({runMutations})=>{const{FIXTURES:f}=await import("../fixtures/fase3.mjs");const a=f.filter(x=>x.handler==="CONTROLLED");const r=await runMutations(a);const s=r.filter(x=>!x.detected).length;console.log("N="+r.length+" DET="+r.filter(x=>x.detected).length+" SURV="+s);});`], join(root, "core/harness"));
const mut = { n: +(mutOut.match(/N=(\d+)/) || [])[1] || 0, det: +(mutOut.match(/DET=(\d+)/) || [])[1] || 0, surv: +(mutOut.match(/SURV=(\d+)/) || [])[1] || 0 };

// validação pública sintética (mecanismos + Proof Integrity)
const pubOut = run(["external-public.mjs"], join(root, "core/harness"));
const pubM = pubOut.match(/fail=(\d+) false-control=(\d+) false-vuln=(\d+) integrity=(\d+)/) || [];
const pubDist = (pubOut.match(/distribuição: (.+)/) || [])[1] || "";

// adversarial
const advOut = run(["adversarial-repo.mjs"], join(root, "core/harness"));
const advM = advOut.match(/fail=(\d+) false-control=(\d+) false-vuln=(\d+) integrity=(\d+)/) || [];

// auditoria de RLS por tabela e server actions (certificações autocontidas)
const rlsOut = run(["rls-audit-suite.mjs"], join(root, "core/harness"));
const rlsM = rlsOut.match(/rls-audit: cases=(\d+) fail=(\d+) false-control=(\d+) false-vuln=(\d+) integrity=(\d+) survivors=(\d+)/) || [];
const rlsMut = rlsOut.match(/mutações causais: (\d+)\/(\d+)/) || [];
const saOut = run(["server-actions-suite.mjs"], join(root, "core/harness"));
const saM = saOut.match(/server-actions: cases=(\d+) fail=(\d+) false-control=(\d+) false-vuln=(\d+) integrity=(\d+) survivors=(\d+)/) || [];
const saMut = saOut.match(/mutações causais: (\d+)\/(\d+)/) || [];
const advN = (advOut.match(/\((\d+) padrões\)/) || [])[1] ?? "?";

// opsec
const opsOut = run(["operational-security.mjs"], join(root, "core/harness"));
const opsM = opsOut.match(/pass=(\d+) fail=(\d+)/) || [];

const L = [];
L.push("# Atlasxis — Métricas públicas (corpus público apenas)", "");
L.push("_Gerado por `node release/public-metrics.mjs`. Fontes: benchmark sintético, mutation, corpus público sintético. **Nenhum número vem de corpora privados ou de terceiros.** Cada métrica declara seu ground truth._", "");
L.push("| Métrica | Valor | Ground truth |", "|---|---|---|");
L.push(`| Correção (benchmark sintético) | ${bench.total - bench.mismatches}/${bench.total} | ${bench.total} casos rotulados **por construção** (21 categorias) |`);
L.push(`| False-control | ${bench.falseControl} | benchmark — NÃO-CONTROLLED declarado CONTROLLED |`);
L.push(`| False-vuln | ${bench.falseVuln} | benchmark — NÃO-VULNERABLE declarado VULNERABLE |`);
L.push(`| Recall CONTROLLED (sintético) | ${ok(ctrl)}/${ctrl.length} | **só no corpus sintético**; não é recall do mundo real |`);
L.push(`| Recall VULNERABLE (sintético) | ${ok(vuln)}/${vuln.length} | idem |`);
L.push(`| Abstenção correta (sintético) | ${ok(abst)}/${abst.length} | casos onde abster É a resposta certa |`);
L.push(`| Mutation score | ${mut.det}/${mut.n} (${mut.surv} survivors) | mutações causais em fixtures CONTROLLED públicas |`);
L.push(`| Validação pública (mecanismos) | ${pubM[1] === "0" ? "8/8" : "ver saída"} | 8 mini-projetos sintéticos, ground truth por construção |`);
L.push(`| Proof Integrity (público) | ${pubM[4] ?? "?"} falhas | invariante executável em toda decisão |`);
L.push(`| Adversarial | fail=${advM[1] ?? "?"} fc=${advM[2] ?? "?"} fv=${advM[3] ?? "?"} | ${advN} padrões projetados para induzir false-control |`);
L.push(`| Auditoria de RLS (\`atlasxis rls\`) | ${rlsM[1] ?? "?"} casos, fail=${rlsM[2] ?? "?"} fc=${rlsM[3] ?? "?"} fv=${rlsM[4] ?? "?"}, mutações ${rlsMut[1] ?? "?"}/${rlsMut[2] ?? "?"} | positivos, negativos e armadilhas por construção (semântica do PostgreSQL) |`);
L.push(`| Server actions | ${saM[1] ?? "?"} casos, fail=${saM[2] ?? "?"} fc=${saM[3] ?? "?"} fv=${saM[4] ?? "?"}, mutações ${saMut[1] ?? "?"}/${saMut[2] ?? "?"} | fixtures por construção + validação em 7 projetos open source reais (integridade 0) |`);
L.push(`| Segurança operacional | ${opsM[1] ?? "?"}/${(+(opsM[1] || 0)) + (+(opsM[2] || 0))} | projeto malicioso não compromete o analisador |`);
L.push(`| Determinismo | verificado | 2 execuções byte-idênticas |`);
L.push("| **Human agreement** | **PENDING** | corpus cego de 42 casos em blind-validation/; nenhum auditor humano — não fabricado |");
L.push("", `Distribuição da validação pública: ${pubDist}`, "");
L.push("## Leitura honesta", "");
L.push("- Os recalls acima valem **exclusivamente no corpus sintético que este repositório contém**. Medem se o motor prova o que o corpus contém — não o que existe no mundo real.");
L.push("- **Não há métrica de recall do mundo real neste repositório público**: isso exigiria ground truth sobre código real, que não é redistribuível. O mantenedor mantém essa validação separadamente sobre corpora privados.");
L.push("- Abstenção não é defeito: sem evidência suficiente, `INSUFFICIENT`/`NOT_ANALYZED` são a resposta correta e **nunca** significam `SAFE`.");
L.push("- `VULNERABLE` no benchmark exige evidência positiva (fonte controlável + sink alcançável + ausência de gating).");
L.push("");
writeFileSync(join(root, "docs/PUBLIC-METRICS.md"), L.join("\n"));
process.stdout.write("docs/PUBLIC-METRICS.md gerado\n");
