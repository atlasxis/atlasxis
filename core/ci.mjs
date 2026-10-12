// Atlasxis — CI gate. Roda os gates técnicos e sai != 0 se QUALQUER gate
// que EFETIVAMENTE RODOU falhar. INSUFFICIENT/NOT_ANALYZED nunca falham CI.
//
// Dois tipos de gate:
//   - reprodutíveis: usam apenas arquivos do repositório + core/ + typescript.
//     Rodam em qualquer máquina (inclusive clone limpo público de terceiros).
//   - só-do-mantenedor: comparam contra o baseline congelado e leem corpora
//     privados/terceiros não redistribuíveis. Ficam em core/harness/
//     maintainer-gates.mjs, que é EXCLUÍDO da árvore pública. Ausentes → SKIPPED
//     (nunca falsamente "passado"). `--public` força pulá-los.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const PUBLIC = process.argv.includes("--public");

const run = (cmd, args, cwd) => {
  try { return { ok: true, out: execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }; }
  catch (e) { return { ok: false, out: (e.stdout || "") + (e.stderr || "") }; }
};

// A árvore pública de distribuição NÃO contém rescue/ (baseline congelado +
// fixtures derivadas de código privado e de repos de terceiros). Os gates que
// dependem desse material degradam para SKIPPED nessa árvore.
const hasRescue = existsSync(join(root, "rescue"));

const gates = [];
const add = (name, pass, detail) => { gates.push({ name, status: pass ? "PASS" : "FAIL", detail }); console.log(`${pass ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`); };
const skip = (name, why) => { gates.push({ name, status: "SKIP", detail: why }); console.log(`○ ${name} — SKIPPED (${why})`); };

// ---------------- gates reprodutíveis (sempre rodam) ----------------

// baseline preservado (só hash; não executa os arquivos congelados). Ausente na
// árvore pública, onde o baseline congelado (rescue/) não é distribuído.
if (!hasRescue) skip("baseline checksums", "rescue/ ausente (árvore pública de distribuição)");
else {
  const ck = run("shasum", ["-a", "256", "-c", "SHA256SUMS.baseline"], root);
  add("baseline checksums", ck.ok && !/FAILED/.test(ck.out), ck.ok ? "6/6 OK" : "checksum divergente");
}

// benchmark: 0 false-control / 0 false-vuln / 0 integrity
const b = run("node", ["run.mjs"], join(root, "core/benchmark"));
const bFatal = /FALSE-CONTROL[^\n]*: 0 ✓/.test(b.out) && /FALSE-VULN[^\n]*: 0 ✓/.test(b.out) && /INTEGRITY falhas: 0 ✓/.test(b.out);
const bCorr = b.out.match(/CORREÇÃO[^:]*: (\d+)\/(\d+)/);
add("benchmark (0 false-control, 0 false-vuln, integridade)", bFatal, bCorr ? `${bCorr[1]}/${bCorr[2]} correção` : "");

// mutation: 0 survivors. Com rescue/ presente, usa legacy(68) + fase3; na árvore
// pública (sem rescue/legacy-fixtures) usa as fixtures fase3 CONTROLLED, que são
// autocontidas. Em ambos os casos: quebrar o guard causal deve ser detectado.
const mutScript = hasRescue
  ? `import("./mutation.mjs").then(async({runMutations})=>{const{FIXTURES:f}=await import("../fixtures/fase3.mjs");const{loadLegacyFixtures}=await import("./legacy-fixtures.mjs");const l=await loadLegacyFixtures();const a=[...l.filter(x=>x.exp==="CONTROLLED"),...f.filter(x=>x.handler==="CONTROLLED")];const r=await runMutations(a);const s=r.filter(x=>!x.detected).length;console.log("SURV="+s+" RATE="+(r.filter(x=>x.detected).length/r.length*100).toFixed(0)+" N="+r.length);process.exit(s?1:0);});`
  : `import("./mutation.mjs").then(async({runMutations})=>{const{FIXTURES:f}=await import("../fixtures/fase3.mjs");const a=f.filter(x=>x.handler==="CONTROLLED");const r=await runMutations(a);const s=r.filter(x=>!x.detected).length;console.log("SURV="+s+" RATE="+(r.filter(x=>x.detected).length/r.length*100).toFixed(0)+" N="+r.length);process.exit(s?1:0);});`;
const m = run("node", ["-e", mutScript], join(root, "core/harness"));
const mN = (m.out.match(/N=(\d+)/) || [])[1];
add("mutation testing (sensibilidade causal)", m.ok, (m.out.match(/RATE=(\d+)/) || [])[1] ? `${m.out.match(/RATE=(\d+)/)[1]}% detecção, 0 survivors${mN ? ` (${mN} mutações)` : ""}` : "");

// determinismo do benchmark
const d1 = run("node", ["run.mjs"], join(root, "core/benchmark"));
const d2 = run("node", ["run.mjs"], join(root, "core/benchmark"));
add("determinismo (2 execuções idênticas)", d1.out.replace(/\s+/g, "") === d2.out.replace(/\s+/g, ""));

// repositório adversarial: 17 padrões, abstém quando não pode provar
const adv = run("node", ["adversarial-repo.mjs"], join(root, "core/harness"));
add("repositório adversarial (17 padrões, abstenção correta)", adv.ok, (adv.out.match(/fail=(\d+) false-control=(\d+)/) || []).slice(1).join("/") ? "fail/fc " + adv.out.match(/fail=(\d+) false-control=(\d+)/).slice(1, 3).join("/") : "");

// validação pública: corpus SINTÉTICO autocontido (public-corpus/). Demonstra
// os mecanismos + Proof Integrity = 0. Reprodutível por qualquer terceiro.
const exp = run("node", ["external-public.mjs"], join(root, "core/harness"));
const expM = exp.out.match(/fail=(\d+) false-control=(\d+) false-vuln=(\d+) integrity=(\d+)/);
add("validação pública (corpus sintético, Proof Integrity)", exp.ok && expM && expM.slice(1).every((x) => x === "0"), expM ? "8 mecanismos, integridade 0" : "ver saída");

// segurança operacional: projeto malicioso não compromete o analisador
const ops = run("node", ["operational-security.mjs"], join(root, "core/harness"));
const opsM = ops.out.match(/opsec: pass=(\d+) fail=(\d+)/);
add("segurança operacional (symlink, lifecycle, secrets, limites)", ops.ok && opsM && opsM[2] === "0", opsM ? `pass=${opsM[1]} fail=${opsM[2]}` : "ver saída");

// scanner de publicação: sempre roda o self-test (prova que detecta vazamentos);
// varre a árvore só quando ela é pública (sem rescue/), onde nada privado pode
// existir. Na árvore do mantenedor (com rescue/ e docs privados) a varredura é
// feita por publish/build-public.mjs sobre a árvore GERADA, não sobre esta.
const pubSelf = run("node", ["publication-scan.mjs", "--self-test"], join(root, "core/harness"));
let pubOk = pubSelf.ok && /todas as categorias detectadas/.test(pubSelf.out);
let pubDetail = "self-test 13/13";
if (!hasRescue) {
  const pubTree = run("node", ["publication-scan.mjs", root], join(root, "core/harness"));
  pubOk = pubOk && pubTree.ok && /limpo:/.test(pubTree.out);
  pubDetail += pubTree.ok ? " + árvore limpa" : " + ÁRVORE COM VAZAMENTO";
}
add("scanner de publicação (anti-vazamento)", pubOk, pubDetail);

// case library: processo de certificação íntegro (auto-detecta cases/ ou cases-public/)
const cl = run("node", ["validate.mjs"], join(root, "case-library"));
add("case library (certificação íntegra)", cl.ok && /case library íntegra/.test(cl.out), (cl.out.match(/estados: (.+)/) || [])[1] || "ver saída");

// ---------------- gates só-do-mantenedor ----------------
// Delegados a core/harness/maintainer-gates.mjs, ausente na árvore pública.
const mgPath = join(root, "core/harness/maintainer-gates.mjs");
if (PUBLIC || !existsSync(mgPath)) {
  skip("gates do mantenedor (baseline congelado + corpora reais)", PUBLIC ? "--public" : "módulo do mantenedor ausente (árvore pública)");
} else {
  const { runMaintainerGates } = await import(mgPath);
  for (const g of runMaintainerGates(root, run)) {
    if (g.status === "SKIP") skip(g.name, g.detail);
    else add(g.name, g.status === "PASS", g.detail);
  }
}

// ---------------- veredito ----------------
const ran = gates.filter((g) => g.status !== "SKIP");
const failed = ran.filter((g) => g.status === "FAIL");
const skipped = gates.filter((g) => g.status === "SKIP");
console.log(`\n===== CI: ${ran.length - failed.length}/${ran.length} gates${skipped.length ? ` (+${skipped.length} SKIPPED, só-do-mantenedor)` : ""} =====`);
if (skipped.length) console.log("SKIPPED:", skipped.map((g) => g.name).join(", "));
if (failed.length) { console.log("GATES FALHOS:", failed.map((g) => g.name).join(", ")); process.exit(1); }
console.log(PUBLIC ? "TODOS OS GATES PÚBLICOS PASSARAM" : "TODOS OS GATES PASSARAM");
process.exit(0);
