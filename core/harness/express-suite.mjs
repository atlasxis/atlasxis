// Atlasxis — certificação Express + Prisma (docs/EXPRESS-PRISMA.md).
// Gates: fail = 0, false-control = 0, false-vuln = 0, integrity = 0, survivors = 0, determinismo.

import { analyzeExpressProject } from "../express.mjs";
import { validateDecision } from "../ir.mjs";
import { EXPRESS_CASES, SCHEMAS } from "../fixtures/express-prisma.mjs";
import { EXPRESS_ADVERSARIAL_CASES } from "../fixtures/express-adversarial.mjs";

const CASES = [...EXPRESS_CASES.map((c) => ({ kind: c.kind, ...c })), ...EXPRESS_ADVERSARIAL_CASES.map((c) => ({ kind: "attack", ...c }))];

function run(files, schemas = SCHEMAS) {
  let out;
  try { out = analyzeExpressProject(files, schemas); }
  catch (e) { return { sinks: new Map(), handlers: new Map(), integrity: 0, ser: "crash", crash: String(e.message).slice(0, 120) }; }
  const sinks = new Map(), handlers = new Map();
  let integrity = 0;
  for (const f of out) for (const h of f.handlers) {
    handlers.set(h.method, h.decision);
    for (const d of [h.decision, ...h.sinkDecisions]) {
      const v = validateDecision(d);
      if (v.length) { integrity++; console.log(`    ✗ INTEGRIDADE ${h.method}: ${v.join("; ")}`); }
    }
    for (const d of h.sinkDecisions) {
      const key = `${h.method} ${d.sink?.table}.${d.sink?.op}`;
      if (!sinks.has(key)) sinks.set(key, d);
    }
  }
  return { sinks, handlers, integrity, ser: JSON.stringify([...sinks.entries()].map(([k, d]) => [k, d.reasonCode])) };
}

let fail = 0, falseControl = 0, falseVuln = 0, integrity = 0, mutations = 0, survivors = 0, nondet = 0;
const byKind = {};
console.log("=== CERTIFICAÇÃO — Express + Prisma ===");
for (const c of CASES) {
  const r = run(c.files, c.schemas);
  integrity += r.integrity;
  if (run(c.files, c.schemas).ser !== r.ser) nondet++;
  let ok = true; const notes = [];
  if (r.crash) { ok = false; notes.push(`queda: ${r.crash}`); }
  for (const [key, statuses] of Object.entries(c.mustNotStatus || {})) {
    const d = r.sinks.get(key);
    if (d && statuses.includes(d.status)) { ok = false; notes.push(`${key}: ${d.status} proibido (${d.reasonCode})`); if (d.status !== "VULNERABLE") falseControl++; else falseVuln++; }
  }
  for (const [key, exp] of Object.entries(c.expect || {})) {
    const d = r.sinks.get(key);
    if (!d) { ok = false; notes.push(`${key}: acesso ausente (tem: ${[...r.sinks.keys()].join(" | ") || "nenhum"})`); continue; }
    if (d.reasonCode !== exp) {
      ok = false; notes.push(`${key}: esperado ${exp}, obtido ${d.reasonCode} ${JSON.stringify(d.unknowns || [])}`);
      if (d.status === "CONTROLLED" && !exp.startsWith("CONTROLLED")) falseControl++;
      if (d.status === "VULNERABLE" && !exp.startsWith("VULNERABLE")) falseVuln++;
    }
  }
  for (const [key, forbidden] of Object.entries(c.mustNot || {})) {
    const d = r.sinks.get(key);
    if (d && d.status === forbidden) { ok = false; notes.push(`${key}: ${forbidden} proibido (${d.reasonCode})`); if (forbidden === "CONTROLLED") falseControl++; if (forbidden === "VULNERABLE") falseVuln++; }
  }
  for (const [label, statuses] of Object.entries(c.handlerMustNot || {})) {
    const d = r.handlers.get(label);
    if (d && statuses.includes(d.status)) { ok = false; notes.push(`handler ${label}: ${d.status} proibido (${d.reasonCode})`); falseControl++; }
  }
  for (const [label, status] of Object.entries(c.handlerExpect || {})) {
    const d = r.handlers.get(label);
    if (!d || d.status !== status) { ok = false; notes.push(`handler ${label}: esperado ${status}, obtido ${d?.status ?? "ausente"}`); }
  }
  let mut = 0, surv = 0;
  for (const m of c.mutate || []) {
    const mutated = Object.fromEntries(Object.entries(c.files).map(([p, content]) => [p, content.split(m.from).join(m.to)]));
    if (JSON.stringify(mutated) === JSON.stringify(c.files)) { ok = false; notes.push(`mutação "${m.name}" não se aplicou`); continue; }
    mut++; mutations++;
    const after = run(mutated, c.schemas);
    for (const [key, exp] of Object.entries(c.expect || {})) {
      if (!/^(CONTROLLED|VULNERABLE)/.test(exp)) continue;
      if (m.keys && !m.keys.includes(key)) continue;
      const d = after.sinks.get(key);
      if (d && d.reasonCode === exp) { surv++; survivors++; notes.push(`mutação "${m.name}" em ${key} sobreviveu`); }
    }
  }
  if (!ok || surv) fail++;
  byKind[c.kind] = byKind[c.kind] || { n: 0, ok: 0 }; byKind[c.kind].n++; if (ok && !surv) byKind[c.kind].ok++;
  console.log(`  ${ok && !surv ? "✓" : "✗"} ${c.id.padEnd(38)} [${c.kind}]${mut ? ` mutações ${mut - surv}/${mut}` : ""}`);
  for (const n of notes) console.log(`      ${n}`);
}
console.log(`\npor tipo: ${Object.entries(byKind).map(([k, v]) => `${k} ${v.ok}/${v.n}`).join(" · ")}`);
console.log(`mutações causais: ${mutations - survivors}/${mutations} detectadas`);
console.log(`determinismo: ${CASES.length - nondet}/${CASES.length} casos idênticos em 2 execuções`);
console.log(`express: cases=${CASES.length} fail=${fail} false-control=${falseControl} false-vuln=${falseVuln} integrity=${integrity} survivors=${survivors}`);
process.exit(fail || falseControl || falseVuln || integrity || survivors || nondet ? 1 : 0);
