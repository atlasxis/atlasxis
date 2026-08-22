// ORÁCULO CORE — Security IR (FASE 3).
//
// Representação intermediária formal do caminho
//   SOURCE → RESOURCE → AUTHORIZATION → GUARD → IDENTITY → SINK
// Toda decisão é um objeto estruturado e serializável; strings aparecem
// apenas em campos `text`/`explanation` (explicativos, nunca decisórios).
//
// Invariante central (Proof Integrity, REQUISITO 2/10):
//   CONTROLLED exige ProofChain completa com IdentityProof same === true
//   e zero componentes essenciais UNKNOWN. validateDecision() é executável
//   e roda no harness sobre TODA decisão emitida.

import { STATUS, REASON_STATUS } from "./reason-codes.mjs";

// mecanismo exigido por reason code CONTROLLED (integridade mecanismo↔código)
const MECHANISM_FOR_REASON = {
  CONTROLLED_SELF_SCOPE: ["self-scope"],
  CONTROLLED_OWNERSHIP_HELPER: ["helper-ownership"],
  CONTROLLED_OWNERSHIP_INLINE: ["inline-ownership", "inline-participation"],
  CONTROLLED_POST_READ_GATE: ["post-read-gate"],
  CONTROLLED_TRANSITIVE_OWNERSHIP: ["transitive-ownership"],
  CONTROLLED_RLS_DECLARED_OWNER: ["rls-declared-owner"],
  CONTROLLED_RLS_POLICY_OWNER: ["rls-policy-owner"],
};
// assumptions que NUNCA podem sustentar um CONTROLLED
const FORBIDDEN_IN_CONTROLLED = new Set(["SUPABASE_DEFAULT_GRANTS"]);

// ---------- nós do IR ----------

/** Origem de um identificador controlável pelo cliente. */
export const Source = (kind, expr, pos = -1) => ({ ir: "Source", kind, expr, pos });
// kind: "route-param" | "route-param-member" | "body" | "search-param" | "server-identity"

/** Leitura de recurso (query cujo resultado entra na prova). */
export const ResourceRead = ({ binding, table, idFilter, filters, pos }) => ({
  ir: "ResourceRead", binding, table: table ?? null, idFilter: idFilter ?? null,
  filters: filters ?? [], pos,
});

/** Guard estrutural: ponto do código que rejeita o caminho não autorizado. */
export const Guard = ({ kind, pos, rejects, conditionIR = null, helper = null, text = "" }) => ({
  ir: "Guard", kind, pos, rejects, conditionIR, helper, text,
});
// kind: "if-reject" | "helper-throw" | "sink-filter" | "db-policy-declared"

/** Prova de identidade: o recurso verificado É o recurso do sink. */
export const IdentityProof = ({ verified, sinkBound, same, method, witness = [] }) => ({
  ir: "IdentityProof", verified, sinkBound, same: !!same, method, witness,
});
// method: "same-identifier" | "sink-binds-owner" | "declared-policy" | "role-gate-dominates"

/** Sink normalizado: operação sobre uma tabela (o verbo é detalhe; o recurso é o centro). */
export const Sink = ({ table, op, pos, filters = [], fields = [], returned = false }) => ({
  ir: "Sink", table, op, pos, filters, fields, returned,
});

/** Autorização demonstrada (expressão AuthzExpr normalizada ou política declarada). */
export const Authorization = ({ kind, expr = null, declared = null }) => ({
  ir: "Authorization", kind, expr, declared,
});
// kind: "authz-expr" | "helper-predicate" | "membership-chain" | "owner-filter" | "declared-rls" | "role-gate" | "shared-secret"

/** Cadeia de prova completa. */
export const ProofChain = ({ mechanism, source, resource, authorization, guard, identity, sink, steps = [], unknowns = [] }) => ({
  ir: "ProofChain", mechanism, source, resource, authorization, guard, identity, sink, steps, unknowns,
});

/** Decisão por sink (unit="sink") ou agregada (unit="handler"). */
export const Decision = ({ unit, method, path, status, reasonCode, proof = null, assumptions = [], unknowns = [], sink = null, explanation = "" }) => ({
  ir: "Decision", unit, method, path, status, reasonCode, proof, assumptions, unknowns, sink, explanation,
});

// ---------- Proof Integrity (invariante executável) ----------

const ESSENTIAL = ["source", "resource", "authorization", "guard", "identity", "sink"];

/**
 * Valida uma decisão. Retorna lista de violações (vazia = íntegra).
 * UNKNOWN → SAFE é impossível: qualquer componente essencial ausente ou
 * unknown em uma decisão CONTROLLED é violação dura.
 */
export function validateDecision(d) {
  const v = [];
  if (!d || d.ir !== "Decision") return ["não é Decision"];
  const allowed = REASON_STATUS[d.reasonCode];
  if (!allowed) v.push(`reasonCode desconhecido: ${d.reasonCode}`);
  else if (allowed !== d.status) v.push(`reasonCode ${d.reasonCode} não sustenta status ${d.status}`);

  if (d.status === STATUS.CONTROLLED || d.status === STATUS.OOS_PROVEN) {
    if (!d.proof || d.proof.ir !== "ProofChain") { v.push(`${d.status} sem ProofChain`); return v; }
    for (const c of ESSENTIAL) if (!d.proof[c]) v.push(`${d.status} sem componente essencial: ${c}`);
    if (d.proof.unknowns.length) v.push(`${d.status} com unknowns essenciais: ${d.proof.unknowns.join(",")}`);
    // guard precisa REJEITAR e DOMINAR o sink (prova viva no fluxo)
    const g = d.proof.guard, s = d.proof.sink;
    if (g && g.rejects !== true) v.push(`${d.status} com guard que não rejeita`);
    if (g && s && g.kind === "if-reject" && Number.isFinite(g.pos) && Number.isFinite(s.pos) && g.pos >= 0 && s.pos >= 0 && g.pos >= s.pos)
      v.push(`${d.status} com guard (pos ${g.pos}) que não domina o sink (pos ${s.pos})`);
    // autorização precisa ter conteúdo estrutural (expr ou declared)
    const az = d.proof.authorization;
    if (az && az.expr == null && az.declared == null) v.push(`${d.status} com authorization vazia`);
    if (d.status === STATUS.CONTROLLED) {
      if (!d.proof.identity || d.proof.identity.same !== true)
        v.push("CONTROLLED sem IdentityProof.same === true");
      if (!d.proof.identity?.witness?.length) v.push("CONTROLLED sem witnesses na IdentityProof");
      const allowed = MECHANISM_FOR_REASON[d.reasonCode];
      if (allowed && !allowed.includes(d.proof.mechanism))
        v.push(`mecanismo ${d.proof.mechanism} não sustenta ${d.reasonCode}`);
      for (const a of d.assumptions || [])
        if (FORBIDDEN_IN_CONTROLLED.has(a.id)) v.push(`assumption proibida em CONTROLLED: ${a.id}`);
    }
  }
  if (d.status === STATUS.VULNERABLE) {
    if (!Array.isArray(d.proof?.steps) || !d.proof.steps.length)
      v.push("VULNERABLE sem evidence trace (steps)");
  }
  return v;
}

/** Serialização estável (para diffs determinísticos no harness). */
export function serializeDecision(d) {
  return JSON.stringify(d, (k, val) => (k === "node" || k === "tsNode" ? undefined : val));
}
