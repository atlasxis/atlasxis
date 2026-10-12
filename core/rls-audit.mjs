// Atlasxis — auditoria de RLS por tabela (modo `atlasxis rls`).
//
// Responde, para cada tabela × papel (anon, authenticated) × operação
// (select, insert, update, delete), se há evidência de que o acesso pela API de
// dados do Supabase está controlado — sem depender de rotas de API. Cobre apps
// que chamam o Supabase direto do navegador.
//
// Regras (CORRETUDE > COBERTURA):
//   - CONTROLLED só com prova: policies que restringem ao dono, RLS ligado sem
//     policy permissiva (nega tudo), ou papel sem privilégio na tabela.
//   - VULNERABLE só com evidência POSITIVA de que o papel alcança a tabela
//     (GRANT explícito, dump completo, ou --assume-default-grants declarado) E
//     de que a proteção falta (RLS comprovadamente desligado, ou policy
//     `using (true)` para UPDATE/DELETE) numa tabela com dono por linha.
//   - Ausência de ENABLE nas migrações NÃO é prova de RLS desligado: pode ter
//     sido ligado pelo dashboard. Só um dump completo (--schema-dump) prova.
//   - O padrão de grants do Supabase mudou em 2026; ele nunca é presumido.
//
// Este módulo só INTERPRETA fatos que core/rls.mjs extraiu do SQL. Não decide
// nada sobre rotas e não altera o engine de sinks.

import { ProofChain, Source, Authorization, Guard, IdentityProof, Sink, Decision } from "./ir.mjs";
import { STATUS, REASON } from "./reason-codes.mjs";
import { assumptionRefs, A } from "./assumptions.mjs";
import { OWNER } from "./extract.mjs";

export const AUDIT_ROLES = ["anon", "authenticated"];
export const AUDIT_OPS = ["select", "insert", "update", "delete"];
const DATA_API_SCHEMAS = new Set(["public"]);

const isLiteralTrue = (raw) => raw != null &&
  raw.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/[()\s]/g, "").toLowerCase() === "true";

// ---------- estado de RLS da tabela ----------
function rlsState(t, dump) {
  const log = t.rlsLog || [];
  if (log.some((e) => e.conditional)) return "uncertain";
  const toggles = log.filter((e) => e.action === "enable" || e.action === "disable");
  const last = toggles.length ? toggles[toggles.length - 1].action : null;
  // o registro permissivo é superconjunto do parser estrito (aceita IF EXISTS);
  // se o estrito vê "ligado" e o registro não, algo divergiu → incerto
  if (last !== "enable" && t.rlsEnabled) return "uncertain";
  if (last === "enable") return "enabled";
  if (last === "disable") return "disabled";
  return dump ? "disabled" : "never";
}

// ---------- privilégio do papel na operação ----------
// → { state: "granted"|"revoked"|"partial"|"unknown"|"uncertain", via }
function privilege(model, t, role, op, opts) {
  if (t.privUncertain) return { state: "uncertain", via: "conditional" };
  const own = t.priv?.[role]?.[op], pub = t.priv?.public?.[op];
  if (own === "granted" || pub === "granted") return { state: "granted", via: "explicit" };
  if (own === "partial" || pub === "partial") return { state: "partial", via: "explicit" };
  if (own === "revoked") return { state: "revoked", via: "explicit" };
  if (opts.schemaDump) {
    // um dump com privilégios lista todo GRANT; sem nenhum GRANT o dump veio sem ACLs
    return model.grantsSeen > 0 ? { state: "revoked", via: "dump" } : { state: "unknown", via: "dump-sem-acl" };
  }
  if (model.defaultPrivUncertain) return { state: "uncertain", via: "default-privileges" };
  const dp = t.defaultPrivAtCreate?.[role]?.[op] ?? t.defaultPrivAtCreate?.public?.[op];
  if (dp === "granted") return { state: "granted", via: "default-privileges" };
  if (dp === "partial") return { state: "partial", via: "default-privileges" };
  if (dp === "revoked") return { state: "revoked", via: "default-privileges" };
  if (opts.assumeDefaultGrants) return { state: "granted", via: "assumed" };
  return { state: "unknown", via: "none" };
}

// ---------- policies ----------
const appliesTo = (p, role, op) =>
  (!p.roles.length || p.roles.includes("public") || p.roles.includes(role)) && (p.cmd === "all" || p.cmd === op);

// classes relevantes da policy para a operação (semântica do PostgreSQL)
function relevantClasses(p, op) {
  const using = p.usingRaw != null ? p.usingClass : { kind: "unproven", why: "sem USING" };
  const check = p.checkRaw != null ? p.checkClass : using;
  if (op === "select" || op === "delete") return [using];
  if (op === "insert") return [p.checkRaw != null ? p.checkClass : (p.usingRaw != null ? p.usingClass : { kind: "unproven", why: "sem WITH CHECK" })];
  return [using, check]; // update
}
const ownerOK = (p, op) => relevantClasses(p, op).every((c) => c?.kind === "authz");

function ownerColumns(t) {
  const cols = new Set();
  for (const c of t.columns || []) if (OWNER.has(c)) cols.add(c);
  for (const fk of t.fks || []) if (fk.refTable === "users") cols.add(fk.column);
  for (const p of t.policies || []) for (const c of [p.usingClass, p.checkClass]) for (const o of c?.owners || []) cols.add(o);
  return [...cols].sort();
}

// ---------- montagem de decisões ----------
function finding(t, role, op, status, reasonCode, { proof = null, assumptions = [], unknowns = [], explanation = "" } = {}) {
  return {
    table: t.name, schema: t.schema ?? null, role, op, file: t.file ?? null,
    decision: Decision({
      unit: "table", method: op.toUpperCase(), path: t.name, status, reasonCode, proof,
      assumptions: assumptionRefs(assumptions), unknowns, explanation,
      sink: Sink({ table: t.name, op, pos: -1 }),
    }),
  };
}

const corpusAssumption = (opts) => (opts.schemaDump ? A.SCHEMA_DUMP_IS_PRODUCTION : A.RLS_CORPUS_COMPLETE);
const privAssumptions = (priv, opts) => [corpusAssumption(opts), ...(priv.via === "assumed" ? [A.SUPABASE_DEFAULT_GRANTS] : [])];

function controlledChain({ mechanism, t, role, op, declared, guardText, witness }) {
  return ProofChain({
    mechanism,
    source: Source("server-identity", role === "anon" ? "anon (sem identidade)" : "auth.uid()"),
    resource: { table: t.name, idExpr: ownerColumns(t).join(",") || "(linhas da tabela)" },
    authorization: Authorization({ kind: "declared-rls", declared }),
    guard: Guard({ kind: "db-policy-declared", pos: -1, rejects: true, text: guardText }),
    identity: IdentityProof({ verified: { idExpr: "auth.uid()" }, sinkBound: { idExpr: t.name }, same: true, method: "declared-policy", witness }),
    sink: Sink({ table: t.name, op, pos: -1 }),
    steps: [{ kind: "table-audit", detail: `${role} ${op.toUpperCase()} ${t.name}` }],
  });
}

function decide(model, t, role, op, opts) {
  if (model.ambiguousTables.has(t.name))
    return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_AMBIGUOUS, { unknowns: ["policies da tabela recriadas com definições conflitantes"] });

  const rls = rlsState(t, opts.schemaDump);
  if (rls === "uncertain")
    return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_STATE_UNCERTAIN, { unknowns: ["RLS alterado em bloco condicional ou em forma divergente"] });

  const priv = privilege(model, t, role, op, opts);
  if (priv.state === "uncertain")
    return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_STATE_UNCERTAIN, { unknowns: ["privilégios alterados em bloco condicional"] });

  if (priv.state === "revoked") {
    const proof = controlledChain({
      mechanism: "privilege-not-granted", t, role, op,
      declared: { table: t.name, role, op, privilege: "not-granted", via: priv.via },
      guardText: `${role} sem privilégio ${op.toUpperCase()} (${priv.via === "dump" ? "nenhum GRANT no dump" : "REVOKE explícito"})`,
      witness: [`privilégio ${op} de ${role}: não concedido (${priv.via})`],
    });
    return finding(t, role, op, STATUS.CONTROLLED, REASON.CONTROLLED_PRIVILEGE_NOT_GRANTED, { proof, assumptions: [corpusAssumption(opts)] });
  }

  const owners = ownerColumns(t);
  const reachable = priv.state === "granted";

  if (rls === "enabled") {
    const applicable = (t.policies || []).filter((p) => appliesTo(p, role, op));
    const perm = applicable.filter((p) => p.permissive), restr = applicable.filter((p) => !p.permissive);
    if (!perm.length) {
      const proof = controlledChain({
        mechanism: "rls-default-deny", t, role, op,
        declared: { table: t.name, rlsEnabled: true, permissivePolicies: 0, role, op },
        guardText: `RLS ligado e nenhuma policy libera ${op.toUpperCase()} para ${role}`,
        witness: ["RLS habilitado", `0 policies permissivas para ${role}/${op}`],
      });
      return finding(t, role, op, STATUS.CONTROLLED, REASON.CONTROLLED_RLS_DEFAULT_DENY, { proof, assumptions: [corpusAssumption(opts)] });
    }
    const allPermOwner = perm.every((p) => ownerOK(p, op));
    const restrOwner = restr.filter((p) => ownerOK(p, op));
    if (allPermOwner || restrOwner.length) {
      const used = allPermOwner ? perm : restrOwner;
      const admin = used.some((p) => relevantClasses(p, op).some((c) => c?.adminFns?.length));
      const proof = controlledChain({
        mechanism: "rls-policy-owner", t, role, op,
        declared: { table: t.name, rlsEnabled: true, role, op, policies: used.map((p) => ({ name: p.name, cmd: p.cmd, permissive: p.permissive, using: (p.usingRaw || "").slice(0, 120), check: (p.checkRaw || "").slice(0, 120), file: p.sourceFile })) },
        guardText: `policies ${used.map((p) => p.name).join(", ")} restringem ao dono`,
        witness: used.map((p) => `${p.name}: ${(p.usingRaw || p.checkRaw || "").slice(0, 80)}`),
      });
      return finding(t, role, op, STATUS.CONTROLLED, REASON.CONTROLLED_RLS_POLICY_OWNER, {
        proof, assumptions: [A.SUPABASE_AUTH_UID_SEMANTICS, corpusAssumption(opts), ...(admin ? [A.ADMIN_ROLE_GRANTS_ACCESS] : [])],
      });
    }
    const openWrite = (op === "update" || op === "delete") ? perm.filter((p) => isLiteralTrue(p.usingRaw)) : [];
    if (openWrite.length && !restr.length && owners.length) {
      if (!reachable)
        return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_GRANTS_UNKNOWN, {
          unknowns: [`policy ${openWrite[0].name} libera ${op.toUpperCase()} de qualquer linha, mas não há prova de que ${role} tem privilégio na tabela (${priv.state})`],
        });
      const proof = ProofChain({
        mechanism: "rls-policy-open-write",
        source: Source("client", `${role} via API de dados`),
        resource: { table: t.name, idExpr: owners.join(",") },
        authorization: Authorization({ kind: "declared-rls", declared: { table: t.name, rlsEnabled: true, openPolicies: openWrite.map((p) => p.name) } }),
        guard: Guard({ kind: "db-policy-declared", pos: -1, rejects: false, text: `${openWrite.map((p) => p.name).join(", ")}: using (true)` }),
        identity: IdentityProof({ verified: { idExpr: "(nenhum)" }, sinkBound: { idExpr: owners.join(",") }, same: false, method: "declared-policy", witness: [] }),
        sink: Sink({ table: t.name, op, pos: -1 }),
        steps: [
          { kind: "privilege", detail: `${role} tem ${op.toUpperCase()} (${priv.via})` },
          { kind: "rls", detail: "RLS ligado" },
          { kind: "open-policy", detail: `${openWrite.map((p) => p.name).join(", ")} usa USING (true) para ${op.toUpperCase()}` },
          { kind: "no-restrictive", detail: "nenhuma policy restritiva aplicável" },
          { kind: "owner-rows", detail: `linhas têm dono (${owners.join(", ")}): um usuário altera/apaga linhas de outros` },
        ],
      });
      return finding(t, role, op, STATUS.VULNERABLE, REASON.VULNERABLE_RLS_POLICY_OPEN_WRITE, {
        proof, assumptions: [A.OWNER_COLUMN_CONVENTION, ...privAssumptions(priv, opts)],
      });
    }
    const unproven = perm.filter((p) => !ownerOK(p, op)).map((p) => `${p.name}: ${(relevantClasses(p, op).find((c) => c?.kind !== "authz")?.why || "não provada").slice(0, 90)}`);
    return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_POLICY_UNPROVEN, { unknowns: unproven });
  }

  if (rls === "disabled") {
    if (!reachable)
      return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_GRANTS_UNKNOWN, {
        unknowns: [`RLS desligado; o acesso de ${role} depende do privilégio na tabela, que o SQL não comprova (${priv.state})`],
      });
    if (!owners.length)
      return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_OFF_UNOWNED, {
        unknowns: [`${role} acessa todas as linhas, mas a tabela não tem coluna de dono — não dá para provar que os dados são privados`],
      });
    const proof = ProofChain({
      mechanism: "rls-table-exposed",
      source: Source("client", `${role} via API de dados`),
      resource: { table: t.name, idExpr: owners.join(",") },
      authorization: Authorization({ kind: "declared-rls", declared: { table: t.name, rlsEnabled: false } }),
      guard: Guard({ kind: "db-policy-declared", pos: -1, rejects: false, text: "(RLS desligado — nenhuma proteção por linha)" }),
      identity: IdentityProof({ verified: { idExpr: "(nenhum)" }, sinkBound: { idExpr: owners.join(",") }, same: false, method: "declared-policy", witness: [] }),
      sink: Sink({ table: t.name, op, pos: -1 }),
      steps: [
        { kind: "privilege", detail: `${role} tem ${op.toUpperCase()} (${priv.via})` },
        { kind: "rls", detail: opts.schemaDump ? "RLS desligado (dump sem ENABLE)" : "RLS desligado (DISABLE explícito)" },
        { kind: "owner-rows", detail: `linhas têm dono (${owners.join(", ")}): ${role} ${op === "insert" ? "cria linhas em nome de qualquer dono" : op === "select" ? "lê as linhas de todos" : op === "update" ? "altera as linhas de todos" : "apaga as linhas de todos"}` },
      ],
    });
    return finding(t, role, op, STATUS.VULNERABLE, REASON.VULNERABLE_RLS_TABLE_EXPOSED, {
      proof, assumptions: [A.OWNER_COLUMN_CONVENTION, ...privAssumptions(priv, opts)],
    });
  }

  // rls === "never": migrações nunca ligam o RLS (não é prova de desligado)
  const hint = reachable && owners.length
    ? `${role} tem ${op.toUpperCase()} (${priv.via}) e a tabela tem dono (${owners.join(", ")}): se o RLS não foi ligado fora das migrações, as linhas de todos estão expostas`
    : "o RLS pode ter sido ligado fora das migrações (dashboard); use --schema-dump para ter prova";
  return finding(t, role, op, STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_NOT_ENABLED_IN_CORPUS, { unknowns: [hint] });
}

// ---------- API ----------
// opts: { schemaDump: bool, assumeDefaultGrants: bool }
export function auditTables(model, opts = {}) {
  const findings = [];
  for (const name of Object.keys(model.tables).sort()) {
    const t = model.tables[name];
    if (t.schema && !DATA_API_SCHEMAS.has(t.schema)) {
      findings.push(finding(t, "*", "*", STATUS.NOT_ANALYZED, REASON.NOT_ANALYZED_NON_PUBLIC_SCHEMA, { unknowns: [`schema ${t.schema}`] }));
      continue;
    }
    for (const role of AUDIT_ROLES) for (const op of AUDIT_OPS) findings.push(decide(model, t, role, op, opts));
  }
  const summary = {};
  for (const f of findings) summary[f.decision.status] = (summary[f.decision.status] || 0) + 1;
  return {
    mode: "rls-audit",
    tables: Object.keys(model.tables).length,
    grantsSeen: model.grantsSeen || 0,
    dumpHeader: !!model.dumpHeader,
    summary, findings,
  };
}
