// Atlasxis — certificação de server actions.
// Gates: fail = 0, false-control = 0, false-vuln = 0, integrity = 0,
// survivors = 0 (mutação causal), determinismo 100%.

import { analyzeFileIR } from "../engine.mjs";
import { isServerActionFile } from "../extract.mjs";
import { validateDecision } from "../ir.mjs";
import { SERVER_ACTION_CASES, ACTION_MUTATORS } from "../fixtures/server-actions.mjs";

function run(c, code = c.code) {
  if (!isServerActionFile(code)) return { isAction: false, byAction: new Map(), integrity: 0, ser: "not-action" };
  const files = { "app/actions.ts": code, ...(c.extra || {}) };
  const res = analyzeFileIR(files, "app/actions.ts", {}, { kind: "action" });
  const byAction = new Map(); let integrity = 0;
  for (const h of res) {
    const name = h.method.replace(/^ACTION /, "");
    const d = h.sinkDecisions.length ? h.sinkDecisions[0] : h.decision;
    byAction.set(name, d);
    for (const x of [h.decision, ...h.sinkDecisions]) {
      const v = validateDecision(x);
      if (v.length) { integrity++; console.log(`    ✗ INTEGRIDADE ${name}: ${v.join("; ")}`); }
      if (!x.assumptions.some((a) => a.id === "SERVER_ACTION_IS_PUBLIC_ENDPOINT")) { integrity++; console.log(`    ✗ ${name}: decisão sem a assumption SERVER_ACTION_IS_PUBLIC_ENDPOINT`); }
    }
  }
  return { isAction: true, byAction, integrity, ser: JSON.stringify(res.map((h) => [h.method, h.decision.reasonCode, h.sinkDecisions.map((d) => d.reasonCode)])) };
}

let fail = 0, falseControl = 0, falseVuln = 0, integrity = 0, mutations = 0, survivors = 0, nondet = 0;
const byKind = {};
console.log("=== CERTIFICAÇÃO — server actions ===");
for (const c of SERVER_ACTION_CASES) {
  const r = run(c);
  integrity += r.integrity;
  if (run(c).ser !== r.ser) nondet++;
  let ok = true; const notes = [];
  if (c.notAction) { if (r.isAction) { ok = false; notes.push("arquivo tratado como server actions, mas não é"); } }
  else if (!r.isAction) { ok = false; notes.push("arquivo de server actions não foi reconhecido"); }
  for (const [a, exp] of Object.entries(c.expect || {})) {
    const d = r.byAction.get(a);
    if (!d) { ok = false; notes.push(`${a}: ausente`); continue; }
    if (d.reasonCode !== exp) {
      ok = false; notes.push(`${a}: esperado ${exp}, obtido ${d.reasonCode}`);
      if (d.status === "CONTROLLED" && !exp.startsWith("CONTROLLED")) falseControl++;
      if (d.status === "VULNERABLE" && !exp.startsWith("VULNERABLE")) falseVuln++;
    }
  }
  for (const [a, forbidden] of Object.entries(c.mustNot || {})) {
    const d = r.byAction.get(a);
    if (d && d.status === forbidden) { ok = false; notes.push(`${a}: ${forbidden} proibido (${d.reasonCode})`); if (forbidden === "CONTROLLED") falseControl++; if (forbidden === "VULNERABLE") falseVuln++; }
  }
  if (c.onlyActions) {
    const got = [...r.byAction.keys()].sort().join(",");
    if (got !== [...c.onlyActions].sort().join(",")) { ok = false; notes.push(`actions descobertas: ${got}; esperado só ${c.onlyActions.join(",")}`); }
  }
  let mut = 0, surv = 0;
  for (const [a, exp] of Object.entries(c.expect || {})) {
    const ms = ACTION_MUTATORS[exp] || [];
    // pelo menos UMA mutação causal tem que se aplicar a cada decisão provada
    if (ms.length && !ms.some((m) => m.apply(c.code) !== c.code)) { notes.push(`nenhuma mutação se aplicou a ${a} (${exp})`); ok = false; }
    for (const m of ms) {
      const mutated = m.apply(c.code);
      if (mutated === c.code) continue;
      mut++; mutations++;
      const after = run(c, mutated).byAction.get(a);
      if (after && after.reasonCode === exp) { surv++; survivors++; notes.push(`mutação "${m.name}" em ${a} sobreviveu`); }
    }
  }
  if (!ok || surv) fail++;
  byKind[c.kind] = byKind[c.kind] || { n: 0, ok: 0 }; byKind[c.kind].n++; if (ok && !surv) byKind[c.kind].ok++;
  console.log(`  ${ok && !surv ? "✓" : "✗"} ${c.id.padEnd(30)} [${c.kind}]${mut ? ` mutações ${mut - surv}/${mut}` : ""}`);
  for (const n of notes) console.log(`      ${n}`);
}
console.log(`\npor tipo: ${Object.entries(byKind).map(([k, v]) => `${k} ${v.ok}/${v.n}`).join(" · ")}`);
console.log(`mutações causais: ${mutations - survivors}/${mutations} detectadas`);
console.log(`determinismo: ${SERVER_ACTION_CASES.length - nondet}/${SERVER_ACTION_CASES.length} casos idênticos em 2 execuções`);
console.log(`server-actions: cases=${SERVER_ACTION_CASES.length} fail=${fail} false-control=${falseControl} false-vuln=${falseVuln} integrity=${integrity} survivors=${survivors}`);
process.exit(fail || falseControl || falseVuln || integrity || survivors || nondet ? 1 : 0);
