// Atlasxis — mecanismos de prova (porta estrutural do analyzer6 sobre o IR,
// com a lógica de gates reescrita em Authorization IR em vez de texto).
// Cada prova retorna { proven, ...componentes IR } — nunca uma frase.

import {
  ts, findAll, isDead, callee, paramNames, resolveFn, queryInfo, collectReads,
  findAllSinks, parse as parseFile, dominatesSink, OWNER, T, canonText,
} from "./extract.mjs";
import { fromTsExpression, not, verifiedDNF, classifyLiteral } from "./authz.mjs";
import { Guard, IdentityProof, Authorization, ResourceRead } from "./ir.mjs";
import { A } from "./assumptions.mjs";

// um statement de rejeição: throw, ou return com status 40x
const isReject = (n, sf) =>
  ts.isThrowStatement(n) || (ts.isReturnStatement(n) && /40[13]|status/.test(T(n, sf)));

const rejectingIfs = (fn, sf, beforePos) =>
  findAll(fn, ts.isIfStatement).filter(
    (iff) => iff.pos < beforePos && !isDead(iff) && findAll(iff, (n) => isReject(n, sf)).length > 0
      && dominatesSink(iff, fn, beforePos) // o gate precisa dominar o sink
  );

// expansor de variáveis booleanas (const isOwner = post.author_id === user.id)
export function makeResolveIdent(fn, sf) {
  const decls = new Map();
  findAll(fn, (n) => ts.isVariableDeclaration(n) && n.initializer && ts.isIdentifier(n.name) && !isDead(n))
    .forEach((d) => { if (!decls.has(d.name.text)) decls.set(d.name.text, d.initializer); });
  const resolve = (name, depth) => {
    const init = decls.get(name);
    if (!init) return null;
    const t = T(init, sf);
    if (!/(===|!==|&&|\|\||^\s*!)/.test(t)) return null;
    return fromTsExpression(init, sf, resolve, depth + 1);
  };
  return resolve;
}

// Analisa um gate `if (C) reject` como autorização do read R (binding).
// ALLOW = ¬C, normalizado por De Morgan e VERIFICADO por truth table.
// Prova exige: todo disjunto de DNF(ALLOW) contém literal autorizador
// (ownership de um binding CONFIÁVEL — R ou derivado de R por filtro
// explícito no código — ou admin); e ≥1 disjunto tem esse ownership.
// trustedCols: Map binding -> Set(colunas selecionadas por aquele read).
// Um literal de ownership só conta se o campo comparado a user.id FOI realmente
// lido do recurso (não basta o nome casar a convenção *_id) — fecha M06.
function gateAuthorizes(iff, sf, resolveIdent, trustedBindings, trustedCols) {
  const cond = fromTsExpression(iff.expression, sf, resolveIdent);
  const dnf = verifiedDNF(not(cond));
  if (!dnf) return null; // transformação não verificável semanticamente → não prova
  let ownershipOfTrusted = false;
  const okAll = dnf.every((conj) =>
    conj.some((lit) => {
      const c = classifyLiteral(lit);
      if (!c) return false;
      if (c.type === "admin") return true;
      if (c.type === "ownership" && trustedBindings.has(c.obj)) {
        const cols = trustedCols?.get(c.obj);
        // se conhecemos as colunas lidas, o campo owner precisa estar entre elas
        if (cols && !cols.has(c.field.toLowerCase())) return false;
        ownershipOfTrusted = true; return true;
      }
      return false;
    })
  );
  if (!okAll || !ownershipOfTrusted) return null;
  return { conditionIR: cond, allowDNF: dnf };
}

// fecho confiável a partir de R: reads filtrados por campos de reads já
// confiáveis (a relação vem do código — .eq("id", R.<fk>) — nunca inventada)
// Retorna { trusted:Set(nomes), cols:Map(nome->Set(colunas lidas)) }.
function trustedClosure(allReads, rootBindings) {
  const trusted = new Set(rootBindings);
  const cols = new Map();
  const noteCols = (rd) => {
    if (!rd.q.selectCols) return;
    for (const n of [rd.bindings.dataBinding || rd.bindings[0], ...rd.bindings].filter(Boolean))
      cols.set(n, new Set(rd.q.selectCols));
  };
  allReads.forEach((rd) => { const names = [rd.bindings.dataBinding || rd.bindings[0], ...rd.bindings].filter(Boolean); if (names.some((n) => rootBindings.includes(n))) noteCols(rd); });
  let changed = true;
  while (changed) {
    changed = false;
    for (const rd of allReads) {
      const names = [rd.bindings.dataBinding || rd.bindings[0], ...rd.bindings].filter(Boolean);
      if (names.some((n) => trusted.has(n))) continue;
      const derived = (rd.q.filters || []).some((f) => [...trusted].some((t) => new RegExp("^" + t + "\\.\\w").test(f.val)));
      if (derived) { names.forEach((n) => trusted.add(n)); noteCols(rd); changed = true; }
    }
  }
  return { trusted, cols };
}

// ---------- C. post-read ownership gate ----------
// sinkTable (quando fornecida): o recurso VERIFICADO precisa ser lido da MESMA
// tabela que o sink escreve — fecha M12 (check tabela A / sink tabela B).
export function provePostReadGate(fn, sf, rid, sinkPos, resolveIdent, sinkTable = null) {
  const allReads = collectReads(fn, sf, sinkPos);
  const reads = allReads.filter((r) => (r.q.filters || []).some((f) => f.val === rid)
    && (sinkTable == null || r.q.table == null || r.q.table === sinkTable));
  for (const r of reads) {
    for (const binding of r.bindings) {
      const { trusted, cols } = trustedClosure(allReads, [binding]);
      for (const iff of rejectingIfs(fn, sf, sinkPos)) {
        const g = gateAuthorizes(iff, sf, resolveIdent, trusted, cols);
        if (!g) continue;
        return {
          proven: true,
          mechanism: "post-read-gate",
          resource: ResourceRead({ binding, table: r.q.table, idFilter: rid, filters: r.q.filters, pos: r.pos }),
          authorization: Authorization({ kind: "authz-expr", expr: g.allowDNF }),
          guard: Guard({ kind: "if-reject", pos: iff.pos, rejects: true, conditionIR: g.conditionIR, text: T(iff.expression, sf).slice(0, 80) }),
          identity: IdentityProof({
            verified: { table: r.q.table, idExpr: rid }, sinkBound: { idExpr: rid },
            same: true, method: "same-identifier",
            witness: [{ kind: "read", pos: r.pos }, { kind: "gate", pos: iff.pos }, { kind: "sink", pos: sinkPos }],
          }),
          assumptions: [A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS, A.ADMIN_ROLE_GRANTS_ACCESS, A.OWNER_COLUMN_CONVENTION],
          steps: [
            { kind: "read-by-id", table: r.q.table, binding, rid, pos: r.pos },
            { kind: "authz-gate", pos: iff.pos, disjuncts: g.allowDNF.length },
            { kind: "sink-same-id", rid, pos: sinkPos },
          ],
        };
      }
    }
  }
  return { proven: false };
}

// ---------- A/B. ownership via helper (call guard) ----------
function resolveResourceGuard(name, files, callerSf = null, depth = 0) {
  if (depth > 3) return null;
  const rf = resolveFn(name, files, callerSf);
  if (!rf) return null;
  const { node, sf } = rf;
  const params = paramNames(node, sf);
  const steps = [{ kind: "helper", name, params, path: rf.path }];
  let resourceParam = null;
  findAll(node, (n) => ts.isCallExpression(n) && callee(n) === "eq").forEach((eq) => {
    if (ts.isStringLiteral(eq.arguments[0]) && eq.arguments[0].text === "id" && eq.arguments[1]) {
      const v = canonText(eq.arguments[1], sf);
      if (params.includes(v)) resourceParam = v;
    }
  });
  if (!resourceParam) {
    for (const c of findAll(node, (n) => ts.isCallExpression(n))) {
      const sub = resolveFn(callee(c), files, sf);
      if (!sub) continue;
      const sp = paramNames(sub.node, sub.sf);
      const subq = findAll(sub.node, (n) => ts.isCallExpression(n) && callee(n) === "eq")
        .find((eq) => ts.isStringLiteral(eq.arguments[0]) && eq.arguments[0].text === "id");
      if (!subq) continue;
      const idParamName = canonText(subq.arguments[1], sub.sf);
      const idx = sp.indexOf(idParamName);
      if (idx >= 0 && c.arguments[idx]) {
        const v = canonText(c.arguments[idx], sf);
        if (params.includes(v)) { resourceParam = v; steps.push({ kind: "helper-read", name: callee(c), idParam: idParamName }); }
      }
    }
  }
  if (!resourceParam) return null;
  let field = null, userParam = null, throws = false, guardPos = -1;
  findAll(node, ts.isIfStatement).forEach((iff) => {
    if (findAll(iff, (n) => ts.isThrowStatement(n)).length === 0) return;
    const cond = T(iff.expression, sf);
    for (const pnm of params) {
      // <objeto>.<campo> [!=]== <param-usuário> — campo owner por convenção
      // declarada (não restrito a *_id); o helper leu o recurso por id logo acima.
      if (new RegExp("\\.(\\w+)\\s*[!=]==?\\s*" + pnm + "\\b").test(cond) ||
          new RegExp(pnm + "\\b\\s*[!=]==?\\s*\\w+\\.\\w+").test(cond)) {
        field = "ownerfield"; userParam = pnm; throws = true; guardPos = iff.pos;
      }
    }
    findAll(iff.expression, (n) => ts.isCallExpression(n)).forEach((c) => {
      const pf = resolveFn(callee(c), files, sf);
      if (!pf) return;
      const bins = findAll(pf.node, ts.isBinaryExpression);
      const referencesOwnerCol = bins.some((x) => {
        const t = T(x, pf.sf);
        return /===|!==/.test(t) && [...OWNER, "participant", "owner"].some((col) => t.includes(col));
      });
      if (referencesOwnerCol) {
        const ua = c.arguments.map((a) => canonText(a, sf));
        const up = ua.find((a) => params.includes(a));
        if (up) { userParam = up; field = "participant"; throws = true; guardPos = iff.pos; steps.push({ kind: "predicate", name: callee(c) }); }
      }
    });
  });
  if (!field || !throws) return null;
  return { resourceParamIdx: params.indexOf(resourceParam), userParamIdx: params.indexOf(userParam), field, steps, guardPos, helperName: name, helperPath: rf.path };
}

export function proveOwnershipViaHelper(fn, sf, files, rid, sinkPos) {
  for (const gc of findAll(fn, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression)).filter((c) => c.pos < sinkPos && !isDead(c) && dominatesSink(c, fn, sinkPos))) {
    const rg = resolveResourceGuard(callee(gc), files, sf);
    if (!rg) continue;
    const resArg = gc.arguments[rg.resourceParamIdx] ? canonText(gc.arguments[rg.resourceParamIdx], sf) : null;
    const userArg = gc.arguments[rg.userParamIdx] ? canonText(gc.arguments[rg.userParamIdx], sf) : null;
    if (resArg === rid && /user\.id/.test(userArg || "")) {
      return {
        proven: true,
        mechanism: "helper-ownership",
        resource: ResourceRead({ binding: null, table: null, idFilter: rid, filters: [], pos: gc.pos }),
        authorization: Authorization({ kind: "helper-predicate", declared: { helper: rg.helperName, path: rg.helperPath, field: rg.field } }),
        guard: Guard({ kind: "helper-throw", pos: gc.pos, rejects: true, helper: rg.helperName }),
        identity: IdentityProof({
          verified: { idExpr: rid }, sinkBound: { idExpr: rid }, same: true, method: "same-identifier",
          witness: [{ kind: "helper-call", pos: gc.pos }, { kind: "sink", pos: sinkPos }],
        }),
        assumptions: [A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS, A.OWNER_COLUMN_CONVENTION],
        steps: [...rg.steps, { kind: "call-site", pos: gc.pos, resArg, userArg }, { kind: "sink-same-id", rid, pos: sinkPos }],
      };
    }
  }
  return { proven: false };
}

// ---------- B-inline. read via helper + gate inline no handler ----------
export function proveOwnershipInline(fn, sf, files, rid, sinkPos, resolveIdent) {
  for (const d of findAll(fn, (n) => ts.isVariableDeclaration(n)).filter((x) => !isDead(x) && x.pos < sinkPos)) {
    if (!d.initializer) continue;
    let init = d.initializer;
    if (ts.isAwaitExpression(init)) init = init.expression;
    if (!ts.isCallExpression(init)) continue;
    const rf = resolveFn(callee(init), files, sf);
    if (!rf) continue;
    const sp = paramNames(rf.node, rf.sf);
    const subq = findAll(rf.node, (n) => ts.isCallExpression(n) && callee(n) === "eq")
      .find((eq) => ts.isStringLiteral(eq.arguments[0]) && eq.arguments[0].text === "id");
    if (!subq) continue;
    const idParam = canonText(subq.arguments[1], rf.sf);
    const idx = sp.indexOf(idParam);
    if (idx < 0 || !init.arguments[idx]) continue;
    if (canonText(init.arguments[idx], sf) !== rid) continue;
    const V = ts.isIdentifier(d.name) ? d.name.text : null;
    if (!V) continue;
    for (const iff of rejectingIfs(fn, sf, sinkPos)) {
      // (a) gate direto sobre V via Authorization IR
      const g = gateAuthorizes(iff, sf, resolveIdent, new Set([V]));
      if (g) {
        return {
          proven: true, mechanism: "inline-ownership",
          resource: ResourceRead({ binding: V, table: null, idFilter: rid, filters: [], pos: d.pos }),
          authorization: Authorization({ kind: "authz-expr", expr: g.allowDNF }),
          guard: Guard({ kind: "if-reject", pos: iff.pos, rejects: true, conditionIR: g.conditionIR }),
          identity: IdentityProof({ verified: { idExpr: rid }, sinkBound: { idExpr: rid }, same: true, method: "same-identifier",
            witness: [{ kind: "helper-read", pos: d.pos }, { kind: "gate", pos: iff.pos }, { kind: "sink", pos: sinkPos }] }),
          assumptions: [A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS, A.OWNER_COLUMN_CONVENTION],
          steps: [{ kind: "helper-read", helper: callee(init), rid, pos: d.pos }, { kind: "authz-gate", pos: iff.pos }, { kind: "sink-same-id", rid, pos: sinkPos }],
        };
      }
      // (b) predicado: if(!isParticipant(user.id, V)) reject
      const pc = findAll(iff.expression, (n) => ts.isCallExpression(n))
        .find((c) => c.arguments.some((a) => canonText(a, sf) === V) && c.arguments.some((a) => /user\.id/.test(T(a, sf))));
      if (pc) {
        const pf = resolveFn(callee(pc), files, sf);
        if (pf) {
          const bins = findAll(pf.node, ts.isBinaryExpression);
          const owns = bins.some((x) => {
            const t = T(x, pf.sf);
            return /===|!==/.test(t) && [...OWNER, "participant", "owner"].some((col) => t.includes(col));
          });
          if (owns) {
            return {
              proven: true, mechanism: "inline-participation",
              resource: ResourceRead({ binding: V, table: null, idFilter: rid, filters: [], pos: d.pos }),
              authorization: Authorization({ kind: "helper-predicate", declared: { helper: callee(pc), path: pf.path } }),
              guard: Guard({ kind: "if-reject", pos: iff.pos, rejects: true, helper: callee(pc) }),
              identity: IdentityProof({ verified: { idExpr: rid }, sinkBound: { idExpr: rid }, same: true, method: "same-identifier",
                witness: [{ kind: "helper-read", pos: d.pos }, { kind: "gate", pos: iff.pos }, { kind: "sink", pos: sinkPos }] }),
              assumptions: [A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS, A.OWNER_COLUMN_CONVENTION],
              steps: [{ kind: "helper-read", helper: callee(init), rid, pos: d.pos }, { kind: "predicate-gate", name: callee(pc), pos: iff.pos }, { kind: "sink-same-id", rid, pos: sinkPos }],
            };
          }
        }
      }
    }
  }
  return { proven: false };
}

// ---------- E. ownership transitivo (M2) ----------
export function proveTransitiveOwnership(fn, sf, rid, sinkPos, sinkTable = null) {
  const readDecls = [];
  collectReads(fn, sf, sinkPos).forEach((r) => {
    const name = r.bindings.dataBinding || r.bindings[0];
    if (name) readDecls.push({ name, q: r.q, pos: r.pos });
  });
  const Aread = readDecls.find((rd) => (rd.q.filters || []).some((f) => f.val === rid)
    && (sinkTable == null || rd.q.table == null || rd.q.table === sinkTable));
  if (!Aread) return { proven: false };
  const trusted = new Set([Aread.name]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const rd of readDecls) {
      if (trusted.has(rd.name)) continue;
      if ((rd.q.filters || []).some((f) => [...trusted].some((t) => new RegExp("^" + t + "\\.\\w").test(f.val)))) {
        trusted.add(rd.name); changed = true;
      }
    }
  }
  const membership = readDecls.find((rd) =>
    rd.name !== Aread.name && trusted.has(rd.name)
    && (rd.q.filters || []).some((f) => OWNER.has(f.col) && /\buser\.id\b|\bsession\.user\b/.test(f.val))
    && (rd.q.filters || []).some((f) => !OWNER.has(f.col) && [...trusted].some((t) => new RegExp("^" + t + "\\.\\w").test(f.val)))
  );
  if (!membership) return { proven: false };
  const gate = findAll(fn, ts.isIfStatement).find((iff) =>
    iff.pos < sinkPos && !isDead(iff)
    && findAll(iff, (n) => isReject(n, sf)).length > 0
    && dominatesSink(iff, fn, sinkPos)
    && new RegExp("(^|[^\\w.])!\\s*" + membership.name + "\\b").test(T(iff.expression, sf))
  );
  if (!gate) return { proven: false };
  return {
    proven: true, mechanism: "transitive-ownership",
    resource: ResourceRead({ binding: Aread.name, table: Aread.q.table, idFilter: rid, filters: Aread.q.filters, pos: Aread.pos }),
    authorization: Authorization({ kind: "membership-chain", declared: { via: membership.q.table, memberBinding: membership.name } }),
    guard: Guard({ kind: "if-reject", pos: gate.pos, rejects: true, text: T(gate.expression, sf).slice(0, 60) }),
    identity: IdentityProof({ verified: { table: Aread.q.table, idExpr: rid }, sinkBound: { idExpr: rid }, same: true, method: "same-identifier",
      witness: [{ kind: "read", pos: Aread.pos }, { kind: "membership", pos: membership.pos }, { kind: "gate", pos: gate.pos }, { kind: "sink", pos: sinkPos }] }),
    assumptions: [A.SERVER_IDENTITY, A.MEMBERSHIP_GRANTS_ACCESS, A.OWNER_COLUMN_CONVENTION],
    steps: [
      { kind: "read-by-id", table: Aread.q.table, binding: Aread.name, rid, pos: Aread.pos },
      { kind: "membership-read", table: membership.q.table, binding: membership.name, pos: membership.pos },
      { kind: "falsy-gate", binding: membership.name, pos: gate.pos },
      { kind: "sink-same-id", rid, pos: sinkPos },
    ],
  };
}

// ---------- admin: helper estrutural ----------
export function proveAdminHelper(fn, sf, files, minSinkPos = Infinity) {
  const calls = findAll(fn, (n) => ts.isCallExpression(n) && /requireAdmin/i.test(callee(n)) && !isDead(n));
  if (!calls.length) return { present: false };
  const dominated = calls.filter((c) => dominatesSink(c, fn, minSinkPos));
  if (!dominated.length) return { present: true, proven: false, pos: calls[0].pos };
  const rf = resolveFn(callee(dominated[0]), files, sf);
  if (!rf) return { present: true, proven: false, pos: dominated[0].pos };
  const queriesRole = /role/.test(rf.code);
  const throwsOnNonAdmin = findAll(rf.node, ts.isIfStatement).some(
    (iff) => /role\s*!==?\s*["']admin["']|!==\s*["']admin["']/.test(T(iff.expression, rf.sf)) && findAll(iff, (n) => ts.isThrowStatement(n)).length > 0
  );
  return {
    present: true, proven: queriesRole && throwsOnNonAdmin, pos: dominated[0].pos,
    helper: callee(dominated[0]), helperPath: rf.path,
  };
}

// ---------- admin: role-gate inline (novo, genérico) ----------
// read de role filtrado por user.id + gate que só deixa passar admin, antes dos sinks.
export function proveInlineRoleGate(fn, sf, minSinkPos, resolveIdent) {
  const roleReads = collectReads(fn, sf, minSinkPos).filter((r) =>
    (r.q.filters || []).some((f) => /\buser\.id\b|\bsession\.user\.id\b/.test(f.val))
  );
  for (const r of roleReads) {
    for (const binding of r.bindings) {
      for (const iff of rejectingIfs(fn, sf, minSinkPos)) {
        const cond = fromTsExpression(iff.expression, sf, resolveIdent);
        const dnf = verifiedDNF(not(cond));
        if (!dnf) continue;
        const allAdmin = dnf.length > 0 && dnf.every((conj) =>
          conj.some((lit) => {
            const c = classifyLiteral(lit);
            if (!c || c.type !== "admin") return false;
            // o literal admin precisa vir do read de role (V.role === "admin") ou de expansão dele
            const at = lit.atom;
            const refsBinding = (t) => t && t.member && t.member.obj === binding;
            if (at.k === "cmp") return refsBinding(at.left) || refsBinding(at.right) || at.left.text === "role" || at.right.text === "role";
            return refsBinding(at.term);
          })
        );
        if (allAdmin) {
          return {
            proven: true, mechanism: "admin-role-gate",
            resource: ResourceRead({ binding, table: r.q.table, idFilter: "user.id", filters: r.q.filters, pos: r.pos }),
            authorization: Authorization({ kind: "role-gate", expr: dnf }),
            guard: Guard({ kind: "if-reject", pos: iff.pos, rejects: true, conditionIR: cond, text: T(iff.expression, sf).slice(0, 80) }),
            identity: IdentityProof({ verified: { table: r.q.table, idExpr: "user.id" }, sinkBound: { idExpr: "(todas)" }, same: true, method: "role-gate-dominates",
              witness: [{ kind: "role-read", pos: r.pos }, { kind: "gate", pos: iff.pos }] }),
            assumptions: [A.SERVER_IDENTITY, A.ADMIN_ROLE_GRANTS_ACCESS],
            steps: [{ kind: "role-read", table: r.q.table, binding, pos: r.pos }, { kind: "admin-gate", pos: iff.pos }],
          };
        }
      }
    }
  }
  return { proven: false };
}

// ---------- webhook: shared secret estrutural (genérico, sem tokens de projeto) ----------
// Um termo é "segredo" se deriva de process.env diretamente, ou via helper
// resolvido cross-file (até 2 saltos) cujo corpo lê process.env.
function helperReturnsEnv(text, files, callerSf = null, depth = 0) {
  if (depth > 2) return false;
  const m = text.match(/^([A-Za-z_$][\w$]*)\(\)$/);
  if (!m) return false;
  const rf = resolveFn(m[1], files, callerSf);
  if (!rf || !rf.node.body) return false;
  const body = rf.node.body.getText(rf.sf);
  if (/process\.env/.test(body)) return true;
  for (const c of findAll(rf.node, (n) => ts.isCallExpression(n))) {
    const sub = resolveFn(callee(c), files, rf.sf);
    if (sub && sub.node.body && /process\.env/.test(sub.node.body.getText(sub.sf))) return true;
  }
  return false;
}

export function proveWebhookSecret(fn, sf, minSinkPos, code, files = {}, depth = 0) {
  // (a) comparação de header contra process.env com rejeição
  for (const iff of rejectingIfs(fn, sf, minSinkPos)) {
    const bins = findAll(iff.expression, (n) => ts.isBinaryExpression(n) &&
      (n.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken || n.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken));
    for (const b of bins) {
      const l = canonText(b.left, sf), r = canonText(b.right, sf);
      const isHeader = (t) => /^(req|request)\.headers\.get\(/.test(t) || /headers\.get\(/.test(t);
      const isSecret = (t) => /^process\.env\./.test(t) || helperReturnsEnv(t, files, sf);
      // resolve identificadores 1 nível (const secret = process.env.X / const token = request.headers.get(...))
      const resolveTxt = (t) => {
        if (!/^[A-Za-z_$][\w$]*$/.test(t)) return t;
        const d = findAll(fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === t && n.initializer)[0];
        return d ? canonText(d.initializer, sf) : t;
      };
      const L = resolveTxt(l), R = resolveTxt(r);
      if ((isHeader(L) && isSecret(R)) || (isSecret(L) && isHeader(R))) {
        return {
          proven: true, mechanism: "webhook-shared-secret",
          resource: { kind: "caller-identity" },
          authorization: Authorization({ kind: "shared-secret", declared: { header: isHeader(L) ? L : R, secret: isSecret(L) ? L : R } }),
          guard: Guard({ kind: "if-reject", pos: iff.pos, rejects: true, text: T(iff.expression, sf).slice(0, 80) }),
          identity: IdentityProof({ verified: { idExpr: "caller" }, sinkBound: { idExpr: "(todas)" }, same: true, method: "role-gate-dominates",
            witness: [{ kind: "secret-check", pos: iff.pos }] }),
          assumptions: [A.SHARED_SECRET_VERIFIES_CALLER],
          steps: [{ kind: "secret-compare", pos: iff.pos }],
        };
      }
    }
  }
  // (b) HMAC/verificação criptográfica ligada a uma rejeição
  if (/createHmac|timingSafeEqual/.test(code)) {
    const hv = findAll(fn, (n) => ts.isVariableDeclaration(n) && n.initializer && /createHmac|timingSafeEqual/.test(T(n.initializer, sf)) && ts.isIdentifier(n.name) && !isDead(n));
    for (const d of hv) {
      const V = d.name.text;
      const gate = rejectingIfs(fn, sf, minSinkPos).find((iff) => new RegExp("\\b" + V + "\\b").test(T(iff.expression, sf)));
      if (gate) {
        return {
          proven: true, mechanism: "webhook-hmac",
          resource: { kind: "caller-identity" },
          authorization: Authorization({ kind: "shared-secret", declared: { hmacBinding: V } }),
          guard: Guard({ kind: "if-reject", pos: gate.pos, rejects: true, text: T(gate.expression, sf).slice(0, 80) }),
          identity: IdentityProof({ verified: { idExpr: "caller" }, sinkBound: { idExpr: "(todas)" }, same: true, method: "role-gate-dominates",
            witness: [{ kind: "hmac", pos: d.pos }, { kind: "gate", pos: gate.pos }] }),
          assumptions: [A.SHARED_SECRET_VERIFIES_CALLER],
          steps: [{ kind: "hmac-verify", pos: d.pos }, { kind: "gate", pos: gate.pos }],
        };
      }
    }
  }
  // (c) delegação pura: `return F(request)` onde F é import-alias de um handler
  // de outro arquivo do conjunto — a prova é a do handler delegado (1 salto).
  if (depth < 1) {
    const body = fn.body;
    const stmts = body && ts.isBlock(body) ? body.statements.filter((s) => !ts.isEmptyStatement(s)) : [];
    const ret = stmts.length === 1 && ts.isReturnStatement(stmts[0]) ? stmts[0] : null;
    if (ret && ret.expression && ts.isCallExpression(ret.expression) && ts.isIdentifier(ret.expression.expression)) {
      const localName = ret.expression.expression.text;
      const rootSf = sf;
      for (const imp of findAll(rootSf, ts.isImportDeclaration)) {
        const spec = ts.isStringLiteral(imp.moduleSpecifier) ? imp.moduleSpecifier.text : "";
        const named = imp.importClause?.namedBindings;
        if (!named || !ts.isNamedImports(named)) continue;
        for (const el of named.elements) {
          if (el.name.text !== localName) continue;
          const exportedName = (el.propertyName || el.name).text;
          const suffix = spec.replace(/^@\//, "").replace(/^\.\//, "");
          const targetPath = Object.keys(files).find((p) => p.endsWith(suffix + ".ts") || p.endsWith(suffix + ".tsx") || p.endsWith(suffix));
          if (!targetPath) continue;
          const tSf = parseFile(files[targetPath]);
          const tFn = findAll(tSf, (n) => ts.isFunctionDeclaration(n) && n.name?.text === exportedName && n.body)[0];
          if (!tFn) continue;
          // horizonte do arquivo delegado: o gate precisa dominar os sinks DELE
          const tSinks = findAllSinks(tFn, tSf);
          const tMin = tSinks.length ? Math.min(...tSinks.map((s) => s.pos)) : Infinity;
          const sub = proveWebhookSecret(tFn, tSf, tMin, files[targetPath], files, depth + 1);
          if (sub.proven) {
            return {
              ...sub,
              mechanism: "webhook-delegated:" + sub.mechanism,
              steps: [{ kind: "delegation", local: localName, exported: exportedName, target: targetPath }, ...sub.steps],
            };
          }
        }
      }
    }
  }
  return { proven: false };
}
