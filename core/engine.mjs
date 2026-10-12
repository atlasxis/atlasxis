// Atlasxis — decision engine (FASE 3).
// Unidade de decisão: a cadeia SOURCE → AUTHORIZATION → SINK. Cada sink recebe
// sua própria Decision com ProofChain; o veredito do handler é DERIVADO dos
// sinks (REQUISITO 1), nunca o contrário.

import {
  ts, parse, findAll, isDead, callee, T, canonText,
  discoverHandlers, collectSources, clientKind, findAllSinks, resolveFn, identityFromClient,
  discoverServerActions, collectActionSources, sinkClientKind, collectReads,
  isImportedUnresolved, queryInfo as queryInfoLocal, OWNER, CONTAINER,
} from "./extract.mjs";
import {
  provePostReadGate, proveOwnershipViaHelper, proveOwnershipInline,
  proveTransitiveOwnership, proveAdminHelper, proveInlineRoleGate,
  proveWebhookSecret, makeResolveIdent,
} from "./proofs.mjs";
import { Decision, ProofChain, Source, Guard, IdentityProof, Authorization, validateDecision } from "./ir.mjs";
import { STATUS, REASON } from "./reason-codes.mjs";
import { A, assumptionRefs } from "./assumptions.mjs";
import { normalizeRlsInput, evaluateAccess } from "./rls.mjs";

const MECH_REASON = {
  "helper-ownership": REASON.CONTROLLED_OWNERSHIP_HELPER,
  "inline-ownership": REASON.CONTROLLED_OWNERSHIP_INLINE,
  "inline-participation": REASON.CONTROLLED_OWNERSHIP_INLINE,
  "post-read-gate": REASON.CONTROLLED_POST_READ_GATE,
  "transitive-ownership": REASON.CONTROLLED_TRANSITIVE_OWNERSHIP,
};

function explain(d) {
  const p = d.proof;
  if (d.status === STATUS.CONTROLLED && p)
    return `${d.reasonCode}: ${p.mechanism} — recurso ${p.identity?.verified?.idExpr ?? "?"} verificado e usado no mesmo sink (${p.sink?.table}/${p.sink?.op})`;
  return d.reasonCode + (d.sink ? ` [${d.sink.table}/${d.sink.op}]` : "");
}

function mkDecision(base) {
  const d = Decision(base);
  d.explanation = explain(d);
  const viol = validateDecision(d);
  if (viol.length) throw new Error("Proof Integrity violada: " + viol.join(" | ") + " em " + base.reasonCode);
  return d;
}

function sourceFor(rid, sources) {
  const det = sources.detail.find((s) => s.expr === rid);
  return Source(det ? det.kind : "unknown-client-expr", rid);
}

export function analyzeHandlerIR(fn, sf, code, path, files, rls, opts = {}) {
  const rlsN = normalizeRlsInput(rls);
  const method = fn.name?.text || fn.__name || "?";
  const sources = opts.kind === "action" ? collectActionSources(fn, sf) : collectSources(fn, sf);
  const fileClient = clientKind(code);
  const client = fileClient;
  const resolveIdent = makeResolveIdent(fn, sf);
  const sinks = findAllSinks(fn, sf);
  const minPos = sinks.length ? Math.min(...sinks.map((s) => s.pos)) : Infinity;

  const handlerLevel = (status, reasonCode, proof = null, assumptions = [], unknowns = []) => ({
    method, client,
    decision: mkDecision({ unit: "handler", method, path, status, reasonCode, proof, assumptions: assumptionRefs(assumptions), unknowns }),
    sinkDecisions: [],
  });

  // ---- identidade vinda do cliente: nenhuma prova baseada em user.id vale ----
  const tainted = identityFromClient(fn, sf, sources.exprs);
  if (tainted.length)
    return handlerLevel(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_IDENTITY_FROM_CLIENT, null, [], tainted);

  // ---- OOS: admin (helper estrutural, path, ou role-gate inline provado) ----
  const ag = proveAdminHelper(fn, sf, files, minPos);
  if (/(^|\/)admin\//.test(path) || ag.present) {
    if (ag.proven && ag.pos < minPos) {
      const proof = ProofChain({
        mechanism: "admin-helper",
        source: Source("server-identity", "user.id"),
        resource: { kind: "role-of-user" },
        authorization: Authorization({ kind: "role-gate", declared: { helper: ag.helper, path: ag.helperPath } }),
        guard: Guard({ kind: "helper-throw", pos: ag.pos, rejects: true, helper: ag.helper }),
        identity: IdentityProof({ verified: { idExpr: "user.id" }, sinkBound: { idExpr: "(todas)" }, same: true, method: "role-gate-dominates", witness: [{ kind: "helper-call", pos: ag.pos }] }),
        sink: { table: "(todos)", op: "(todas)", pos: minPos },
        steps: [{ kind: "admin-helper", helper: ag.helper, pos: ag.pos }],
      });
      return handlerLevel(STATUS.OOS_PROVEN, REASON.OOS_PROVEN_ADMIN_HELPER, proof, [A.SERVER_IDENTITY, A.ADMIN_ROLE_GRANTS_ACCESS, A.ADMIN_HELPER_NAME_CONVENTION]);
    }
    if (ag.present)
      return handlerLevel(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_ADMIN_GUARD_UNPROVEN, null, [A.ADMIN_HELPER_NAME_CONVENTION], ["admin guard não provado efetivo-antes-do-sink"]);
    const inlineAdmin = sinks.length ? proveInlineRoleGate(fn, sf, minPos, resolveIdent) : { proven: false };
    if (inlineAdmin.proven) {
      const proof = ProofChain({ mechanism: inlineAdmin.mechanism, source: Source("server-identity", "user.id"), resource: inlineAdmin.resource, authorization: inlineAdmin.authorization, guard: inlineAdmin.guard, identity: inlineAdmin.identity, sink: { table: "(todos)", op: "(todas)", pos: minPos }, steps: inlineAdmin.steps });
      return handlerLevel(STATUS.OOS_PROVEN, REASON.OOS_PROVEN_ADMIN_INLINE_ROLE_GATE, proof, inlineAdmin.assumptions);
    }
    return handlerLevel(STATUS.OOS_UNVERIFIED, REASON.OOS_UNVERIFIED_ADMIN, null, [], ["rota /admin/ sem guard estrutural provado"]);
  }
  // role-gate inline fora de /admin/: só quando domina todos os sinks
  if (sinks.length) {
    const inlineAdmin = proveInlineRoleGate(fn, sf, minPos, resolveIdent);
    if (inlineAdmin.proven) {
      const proof = ProofChain({ mechanism: inlineAdmin.mechanism, source: Source("server-identity", "user.id"), resource: inlineAdmin.resource, authorization: inlineAdmin.authorization, guard: inlineAdmin.guard, identity: inlineAdmin.identity, sink: { table: "(todos)", op: "(todas)", pos: minPos }, steps: inlineAdmin.steps });
      return handlerLevel(STATUS.OOS_PROVEN, REASON.OOS_PROVEN_ADMIN_INLINE_ROLE_GATE, proof, inlineAdmin.assumptions);
    }
  }

  // ---- OOS: webhook (prova estrutural genérica; nenhum token de projeto) ----
  if (/webhook/i.test(path)) {
    const wh = proveWebhookSecret(fn, sf, minPos, code, files);
    if (wh.proven) {
      const proof = ProofChain({ mechanism: wh.mechanism, source: Source("server-identity", "shared-secret"), resource: wh.resource, authorization: wh.authorization, guard: wh.guard, identity: wh.identity, sink: { table: "(todos)", op: "(todas)", pos: minPos }, steps: wh.steps });
      return handlerLevel(STATUS.OOS_PROVEN, REASON.OOS_PROVEN_WEBHOOK_SIGNATURE, proof, wh.assumptions);
    }
    return handlerLevel(STATUS.OOS_UNVERIFIED, REASON.OOS_UNVERIFIED_WEBHOOK, null, [], ["webhook sem verificação estrutural de assinatura/segredo"]);
  }

  if (!sinks.length) return handlerLevel(STATUS.NOT_ANALYZED, REASON.NOT_ANALYZED_NO_SINK);

  // ---- decisão POR SINK ----
  const clientRids = (sink) => {
    const out = [];
    (sink.filters || []).forEach((f) => { if (f.col && !OWNER.has(f.col) && sources.exprs.has(f.val)) out.push(f.val); });
    if (/insert|upsert/.test(sink.op)) (sink.fields || []).forEach((f) => { if (CONTAINER.has(f.key) && sources.exprs.has(f.val)) out.push(f.val); });
    return [...new Set(out)];
  };
  const selfOwned = (sink) =>
    (sink.filters || []).some((f) => /\buser\.id\b/.test(f.val)) ||
    (/insert|upsert|update/.test(sink.op) && (sink.fields || []).some((f) => OWNER.has(f.key) && /\buser\.id\b/.test(f.val)));

  // requireSameTable: quando o rid alcança o sink pela PK "id", o recurso
  // verificado precisa ser a MESMA tabela (mesma entidade). Se alcança por
  // coluna-container (post_id, conversation_id...), é padrão pai-filho e a
  // tabela lida (o pai) naturalmente difere da tabela do sink.
  const proveRid = (rid, sinkPos, sinkTable = null, requireSameTable = false) => {
    const st = requireSameTable ? sinkTable : null;
    let p = proveOwnershipViaHelper(fn, sf, files, rid, sinkPos);
    if (!p.proven) p = proveOwnershipInline(fn, sf, files, rid, sinkPos, resolveIdent);
    if (!p.proven) p = provePostReadGate(fn, sf, rid, sinkPos, resolveIdent, st);
    if (!p.proven) p = proveTransitiveOwnership(fn, sf, rid, sinkPos, st);
    return p;
  };

  const decideSink = (sink) => {
    // tipo de cliente do PRÓPRIO sink (não do arquivo inteiro)
    const client = sinkClientKind(sink, fn, sf, fileClient);
    const rids = clientRids(sink);
    const sinkInfo = { table: sink.table, op: sink.op, pos: sink.pos };
    const D = (status, reasonCode, proof, assumptions, unknowns = [], applicable = true) => ({
      applicable,
      decision: mkDecision({ unit: "sink", method, path, status, reasonCode, proof, assumptions: assumptionRefs(assumptions), unknowns, sink: sinkInfo }),
    });

    if (rids.length) {
      // ---- FASE 4: evidência de RLS PARSEADA (precede a declarada) ----
      // aplica-se só a client authenticated; insert/upsert com container rid
      // NUNCA são provados por policy de coluna owner (fail-closed).
      let rlsEv = null;
      if (client === "authenticated" && rlsN.model) {
        if (/insert|upsert/.test(sink.op)) rlsEv = { insertContainer: true };
        else {
          rlsEv = evaluateAccess(rlsN.model, sink.table, sink.op === "read" ? "select" : sink.op);
          if (rlsEv.provable) {
            const pol = rlsEv.policies;
            const adminInvolved = pol.some((p) => p.class.adminFns?.length);
            const proof = ProofChain({
              mechanism: "rls-policy-owner",
              source: sourceFor(rids[0], sources),
              resource: { table: sink.table, idExpr: rids.join(",") },
              authorization: Authorization({ kind: "declared-rls", declared: { table: sink.table, policies: pol } }),
              guard: Guard({ kind: "db-policy-declared", pos: sink.pos, rejects: true, text: pol.map((p) => p.name).join(",") }),
              identity: IdentityProof({
                verified: { table: sink.table, idExpr: "linha ligada a auth.uid() por policy" },
                sinkBound: { idExpr: rids.join(",") }, same: true, method: "declared-policy",
                witness: pol.map((p) => ({ kind: "rls-policy", name: p.name, file: p.file })),
              }),
              sink: sinkInfo,
              steps: [
                { kind: "rls-enabled", table: sink.table },
                ...pol.map((p) => ({ kind: "rls-policy", name: p.name, cmd: p.cmd, permissive: p.permissive, owners: p.class.owners, adminFns: p.class.adminFns, file: p.file })),
              ],
            });
            const asm = [A.SUPABASE_AUTH_UID_SEMANTICS, A.CLIENT_KIND_BY_API_NAME, A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS];
            if (adminInvolved) asm.push(A.ADMIN_ROLE_GRANTS_ACCESS);
            return D(STATUS.CONTROLLED, REASON.CONTROLLED_RLS_POLICY_OWNER, proof, asm);
          }
        }
      }
      if (client === "authenticated" && rlsN.declared[sink.table] === "owner") {
        const proof = ProofChain({
          mechanism: "rls-declared-owner",
          source: sourceFor(rids[0], sources),
          resource: { table: sink.table, idExpr: rids.join(",") },
          authorization: Authorization({ kind: "declared-rls", declared: { table: sink.table, mode: "owner" } }),
          guard: Guard({ kind: "db-policy-declared", pos: sink.pos, rejects: true }),
          identity: IdentityProof({ verified: { table: sink.table, idExpr: "auth.uid()-bound (declarado)" }, sinkBound: { idExpr: rids.join(",") }, same: true, method: "declared-policy", witness: [{ kind: "declared-rls", table: sink.table }] }),
          sink: sinkInfo,
          steps: [{ kind: "declared-rls", table: sink.table, mode: "owner" }],
        });
        return D(STATUS.CONTROLLED, REASON.CONTROLLED_RLS_DECLARED_OWNER, proof, [A.RLS_DECLARED_BY_CONFIG, A.CLIENT_KIND_BY_API_NAME, A.SERVER_IDENTITY]);
      }
      if (client === "authenticated" && rlsN.declared[sink.table] === "complex")
        return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_DECLARED_COMPLEX, null, [A.RLS_DECLARED_BY_CONFIG, A.CLIENT_KIND_BY_API_NAME], [`política RLS de ${sink.table} declarada complexa — não provada`]);

      const ridViaPk = (rid) => (sink.filters || []).some((f) => f.col === "id" && f.val === rid);
      const proofs = rids.map((rid) => ({ rid, p: proveRid(rid, sink.pos, sink.table, ridViaPk(rid)) }));
      if (proofs.every((x) => x.p.proven)) {
        const first = proofs[0].p;
        const proof = ProofChain({
          mechanism: first.mechanism,
          source: sourceFor(proofs[0].rid, sources),
          resource: first.resource,
          authorization: first.authorization,
          guard: first.guard,
          identity: { ...first.identity, sinkBound: { idExpr: proofs.map((x) => x.rid).join(",") } },
          sink: sinkInfo,
          steps: proofs.flatMap((x) => x.p.steps),
        });
        return D(STATUS.CONTROLLED, MECH_REASON[first.mechanism], proof, proofs.flatMap((x) => x.p.assumptions));
      }

      // alias: rid é identificador declarado como cópia de outro identificador —
      // sem dataflow completo a identidade não é provada (nunca CONTROLLED via alias)
      const aliasRid = rids.find((rid) => /^[A-Za-z_$][\w$]*$/.test(rid) &&
        findAll(fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === rid && n.initializer && ts.isIdentifier(n.initializer)).length > 0);
      if (aliasRid)
        return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_ALIAS_RESOLUTION, null, [], [`${aliasRid} é alias não resolvido — identidade recurso→sink não provada`]);
      // identidade cruzada (check A / sink B): NUNCA muda status — apenas refina
      // o reason code quando o veredito já é INSUFFICIENT. Uma prova sobre outro
      // rid não protege este sink (TR-05/06: tratá-la como gating engoliria um
      // verdadeiro-positivo VULNERABLE).
      let _cross = null;
      const crossProven = () => {
        if (_cross === null) _cross = [...sources.exprs].filter((e) => !rids.includes(e)).some((rid2) => proveRid(rid2, sink.pos).proven);
        return _cross;
      };

      // guard por call não resolvida / não provada
      const g = findAll(fn, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression))
        .filter((c) => c.pos < sink.pos && !isDead(c) && c.arguments.some((a) => /\buser\.id\b/.test(T(a, sf))));
      for (const c of g) {
        const rf = resolveFn(callee(c), files);
        if (!rf) {
          const code_ = isImportedUnresolved(callee(c), sf) ? REASON.INSUFFICIENT_CROSS_FILE_EVIDENCE : REASON.INSUFFICIENT_GUARD_UNRESOLVED;
          return D(STATUS.INSUFFICIENT, code_, null, [], [`helper ${callee(c)} recebe user.id mas não é resolvível no conjunto de arquivos analisado`]);
        }
        if (findAll(rf.node, ts.isThrowStatement).length > 0)
          return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RESOURCE_IDENTITY, null, [], [`guard ${callee(c)} lança, mas identidade recurso→sink não provada`]);
      }
      // if inline com user.id (não-vácuo) antes do sink
      const nonVacIf = findAll(fn, ts.isIfStatement).some((iff) => {
        if (iff.pos >= sink.pos || isDead(iff)) return false;
        if (!/user\.id/.test(T(iff.expression, sf))) return false;
        if (findAll(iff, (n) => ts.isThrowStatement(n) || ts.isReturnStatement(n)).length === 0) return false;
        const calls = findAll(iff.expression, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression));
        if (calls.length) {
          const allVac = calls.every((c) => {
            const rf = resolveFn(callee(c), files);
            if (!rf) return false;
            const rets = findAll(rf.node, ts.isReturnStatement);
            return rets.length === 1 && rets[0].expression && rets[0].expression.kind === ts.SyntaxKind.TrueKeyword;
          });
          if (allVac) return false;
        }
        return true;
      });
      if (nonVacIf) {
        const code = crossProven() ? REASON.INSUFFICIENT_CROSS_RESOURCE : REASON.INSUFFICIENT_RESOURCE_IDENTITY;
        return D(STATUS.INSUFFICIENT, code, null, [], [
          crossProven() ? `autorização provada para outro recurso, não para ${rids.join(",")}` : "guard inline com user.id presente, mas identidade recurso→sink não provada",
        ]);
      }

      // trava anti-FP: VULNERABLE exige ausência de QUALQUER gating vivo.
      // Inclui um gate que LÊ o próprio recurso do sink (mesmo rid) e rejeita:
      // esse gate pode codificar autorização que não sabemos classificar (ex.:
      // `if(doc.locked) throw`), então abstemos em vez de afirmar VULNERABLE.
      const resourceGate = (() => {
        const readsOfRid = findAll(fn, (n) => ts.isVariableDeclaration(n) && !isDead(n) && n.pos < sink.pos && n.initializer)
          .map((dcl) => { let init = dcl.initializer; if (ts.isAwaitExpression(init)) init = init.expression; const q = queryInfoLocal(init, sf); return { dcl, q }; })
          .filter((x) => x.q && (x.q.filters || []).some((f) => rids.includes(f.val)));
        const bindings = new Set();
        for (const r of readsOfRid) { if (ts.isIdentifier(r.dcl.name)) bindings.add(r.dcl.name.text); if (ts.isObjectBindingPattern(r.dcl.name)) r.dcl.name.elements.forEach((e) => bindings.add(e.name.getText(sf))); }
        if (!bindings.size) return false;
        // só conta como possível controle um gate que acessa um CAMPO do
        // recurso (ex.: `if(doc.locked)`); um mero teste de existência
        // (`if(!lineup) throw 404`) não é controle de autorização.
        return findAll(fn, ts.isIfStatement).some((iff) => iff.pos < sink.pos && !isDead(iff)
          && findAll(iff, (n) => ts.isThrowStatement(n) || (ts.isReturnStatement(n) && /40[13]|status/.test(T(n, sf)))).length > 0
          && findAll(iff.expression, (n) => ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && bindings.has(n.expression.text)).length > 0);
      })();
      const liveCmp = resourceGate || findAll(fn, (n) => ts.isBinaryExpression(n) && !isDead(n) &&
        (n.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken || n.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) &&
        /\buser\.id\b/.test(T(n, sf))).length > 0;
      const pubFilter = findAll(fn, (n) => ts.isCallExpression(n) && callee(n) === "eq" && ts.isStringLiteral(n.arguments[0]) &&
        n.arguments[0].text === "status" && n.arguments[1] && /published|public/.test(T(n.arguments[1], sf))).length > 0;
      const roleChk = /role\s*[=!]==?\s*["']admin["']|is_admin/.test(code);
      // guard-ish: um if de rejeição antes do sink cuja condição chama uma
      // função referenciando user. Se a função for PROVAVELMENTE VÁCUA (só
      // `return true`), o guard é oco → deixa seguir para VULNERABLE. Caso
      // contrário (não resolvível, ou resolvível mas não provado vácuo), é um
      // controle compensatório que não conseguimos analisar → abster.
      const provablyVacuous = (name) => {
        const rf = resolveFn(name, files, sf);
        if (!rf) return false;
        const rets = findAll(rf.node, ts.isReturnStatement);
        const throws = findAll(rf.node, ts.isThrowStatement);
        return throws.length === 0 && rets.length === 1 && rets[0].expression && rets[0].expression.kind === ts.SyntaxKind.TrueKeyword;
      };
      let guardishCall = null;
      for (const iff of findAll(fn, ts.isIfStatement)) {
        if (iff.pos >= sink.pos || isDead(iff)) continue;
        if (findAll(iff, (n) => ts.isThrowStatement(n) || ts.isReturnStatement(n)).length === 0) continue;
        const c = findAll(iff.expression, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression))
          .find((cc) => /\buser\b/.test(T(cc, sf)) && !provablyVacuous(callee(cc)));
        if (c) { guardishCall = c; break; }
      }
      if (guardishCall) {
        const code_ = isImportedUnresolved(callee(guardishCall), sf) ? REASON.INSUFFICIENT_CROSS_FILE_EVIDENCE
          : !resolveFn(callee(guardishCall), files, sf) ? REASON.INSUFFICIENT_GUARD_UNRESOLVED : REASON.INSUFFICIENT_RESOURCE_IDENTITY;
        return D(STATUS.INSUFFICIENT, code_, null, [], [`guard chama ${callee(guardishCall)}(...) referenciando user, não provado vácuo nem autorizador — controle compensatório não analisável`]);
      }
      if (liveCmp || pubFilter || roleChk) {
        const code = crossProven() ? REASON.INSUFFICIENT_CROSS_RESOURCE : REASON.INSUFFICIENT_UNRESOLVED_GATING;
        return D(STATUS.INSUFFICIENT, code, null, [], [
          `gating vivo não resolvido (user.id-cmp:${liveCmp}, status-público:${pubFilter}, role:${roleChk}) — caminho desprotegido não provado`,
        ]);
      }
      if (client === "service_role") {
        const proof = ProofChain({
          mechanism: "absence-of-gating",
          source: sourceFor(rids[0], sources),
          resource: { table: sink.table, idExpr: rids.join(",") },
          authorization: Authorization({ kind: "authz-expr", expr: null }),
          guard: Guard({ kind: "if-reject", pos: -1, rejects: false, text: "(nenhum guard vivo encontrado)" }),
          identity: IdentityProof({ verified: { idExpr: "(nenhum)" }, sinkBound: { idExpr: rids.join(",") }, same: false, method: "same-identifier", witness: [] }),
          sink: sinkInfo,
          steps: [
            { kind: "client-kind", value: "service_role" },
            { kind: "client-rid", rids },
            { kind: "absence", checks: ["no-live-user-id-comparison", "no-public-status-filter", "no-role-check", "no-resolvable-guard"] },
            { kind: "sink", ...sinkInfo },
          ],
        });
        return D(STATUS.VULNERABLE, REASON.VULNERABLE_NO_GATING_SERVICE_ROLE, proof, [A.CLIENT_KIND_BY_API_NAME, A.SERVICE_ROLE_BYPASSES_RLS]);
      }
      // ---- FASE 4: refinamento do INSUFFICIENT quando há evidência parseada ----
      if (client === "authenticated" && rlsEv) {
        if (rlsEv.ambiguous)
          return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_AMBIGUOUS, null, [A.SUPABASE_AUTH_UID_SEMANTICS], [`policies de ${sink.table} recriadas com definições conflitantes — ordem de migração incerta`]);
        if (rlsEv.disabled) {
          if (rlsN.options.defaultGrants) {
            const proof = ProofChain({
              mechanism: "rls-disabled-default-grants",
              source: sourceFor(rids[0], sources),
              resource: { table: sink.table, idExpr: rids.join(",") },
              authorization: Authorization({ kind: "declared-rls", declared: { table: sink.table, rlsEnabled: false } }),
              guard: Guard({ kind: "db-policy-declared", pos: -1, rejects: false, text: "(RLS desabilitada — nenhuma proteção de linha)" }),
              identity: IdentityProof({ verified: { idExpr: "(nenhum)" }, sinkBound: { idExpr: rids.join(",") }, same: false, method: "declared-policy", witness: [] }),
              sink: sinkInfo,
              steps: [
                { kind: "client-kind", value: "authenticated" },
                { kind: "rls-disabled-proven", table: sink.table },
                { kind: "client-rid", rids },
                { kind: "absence", checks: ["no-app-level-proof", "no-live-gating"] },
              ],
            });
            return D(STATUS.VULNERABLE, REASON.VULNERABLE_RLS_DISABLED_DEFAULT_GRANTS, proof, [A.CLIENT_KIND_BY_API_NAME, A.SUPABASE_DEFAULT_GRANTS]);
          }
          return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_ABSENT, null, [A.CLIENT_KIND_BY_API_NAME], [`RLS desabilitada em ${sink.table} (provado no schema); grants de tabela não analisados — sem prova de proteção`]);
        }
        if (rlsEv.insertContainer)
          return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_POLICY_UNPROVEN, null, [A.SUPABASE_AUTH_UID_SEMANTICS], [`policy de coluna owner não autoriza o container de um ${sink.op} — participação exigiria subquery (não provável nesta fase)`]);
        if (!rlsEv.unknownTable)
          return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_POLICY_UNPROVEN, null, [A.SUPABASE_AUTH_UID_SEMANTICS], [`RLS habilitada em ${sink.table} mas nenhuma policy aplicável é provável (${(rlsEv.applicable || []).length} aplicáveis)`]);
      }
      return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RLS_UNKNOWN, null, [A.CLIENT_KIND_BY_API_NAME], [`client=${client}: RLS pode proteger, schema/policies indisponíveis (FASE 4)`]);
    }

    // sem rid do cliente
    // Spread no objeto gravado ({ user_id: user.id, ...dados }): colunas
    // desconhecidas entram na escrita e podem SOBRESCREVER o dono ou apontar para
    // recursos de outros. O vínculo de dono deixa de ser prova — nunca CONTROLLED.
    if (selfOwned(sink) && /insert|upsert|update/.test(sink.op) && (sink.spreads || []).length)
      return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_OWNER_OVERRIDABLE, null, [],
        sink.spreads.map((x) => `...${x} grava colunas desconhecidas junto com o dono; elas podem sobrescrever o dono ou referenciar recursos de outros`));

    // Referência escolhida pelo cliente gravada junto com o dono: o registro do
    // usuário aponta para um recurso de OUTRO (ex.: campaign_id vindo do
    // argumento, ou de uma linha lida com filtro do cliente). O self-scope prova
    // só a posse da linha, não a do recurso referenciado — nunca CONTROLLED.
    // Também nunca VULNERABLE: a referência pode ser a uma tabela pública.
    if (selfOwned(sink) && /insert|upsert|update/.test(sink.op)) {
      const taintedRows = new Set();
      for (const r of collectReads(fn, sf, sink.pos))
        if ((r.q.filters || []).some((f) => sources.exprs.has(f.val))) r.bindings.forEach((b) => taintedRows.add(b));
      const clientRefs = (sink.fields || []).filter((f) => /(^id$|_id$)/.test(f.key) && !OWNER.has(f.key) && f.val &&
        (sources.exprs.has(f.val) || [...taintedRows].some((b) => f.val === b || f.val.startsWith(b + "."))));
      if (clientRefs.length)
        return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_CROSS_RESOURCE, null, [],
          clientRefs.map((f) => `${f.key} = ${f.val}: o registro do usuário referencia um recurso escolhido pelo cliente; a autorização sobre esse recurso não foi provada`));
    }
    if (selfOwned(sink)) {
      const proof = ProofChain({
        mechanism: "self-scope",
        source: Source("server-identity", "user.id"),
        resource: { table: sink.table, idExpr: "user.id" },
        authorization: Authorization({ kind: "owner-filter", declared: { table: sink.table } }),
        guard: Guard({ kind: "sink-filter", pos: sink.pos, rejects: true }),
        identity: IdentityProof({ verified: { table: sink.table, idExpr: "user.id" }, sinkBound: { idExpr: "user.id" }, same: true, method: "sink-binds-owner", witness: [{ kind: "sink-filter", pos: sink.pos }] }),
        sink: sinkInfo,
        steps: [{ kind: "owner-bound-sink", ...sinkInfo }],
      });
      return D(STATUS.CONTROLLED, REASON.CONTROLLED_SELF_SCOPE, proof, [A.SERVER_IDENTITY, A.OWNER_COLUMN_CONVENTION, A.OWNERSHIP_GRANTS_ACCESS]);
    }
    return D(STATUS.NOT_ANALYZED, REASON.NOT_ANALYZED_NO_CLIENT_RESOURCE_ID, null, [], [], false);
  };

  const evals = sinks.map(decideSink);
  const sinkDecisions = evals.map((e) => e.decision);
  const appl = evals.filter((e) => e.applicable);

  // ---- agregação DERIVADA dos sinks ----
  const pick = (status) => appl.find((e) => e.decision.status === status);
  let agg;
  const vuln = pick(STATUS.VULNERABLE);
  if (vuln) agg = vuln.decision;
  else if (appl.length && appl.every((e) => e.decision.status === STATUS.CONTROLLED)) agg = appl[0].decision;
  else if (pick(STATUS.INSUFFICIENT)) agg = pick(STATUS.INSUFFICIENT).decision;
  else agg = mkDecision({ unit: "handler", method, path, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_NO_CLIENT_RESOURCE_ID });

  return {
    method, client,
    decision: mkDecision({ unit: "handler", method, path, status: agg.status, reasonCode: agg.reasonCode, proof: agg.proof, assumptions: agg.assumptions, unknowns: agg.unknowns, sink: agg.sink }),
    sinkDecisions,
  };
}

export function analyzeFileIR(files, entry, rls = {}, opts = {}) {
  if (opts.kind === "action") return analyzeActionFile(files, entry, rls);
  const code = files[entry];
  const sf = parse(code);
  const hs = discoverHandlers(sf);
  if (!hs.length) {
    return [{ method: "?", client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: "?", path: entry, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_NO_HANDLER }) }];
  }
  return hs.map((h) => {
    if (!h.supported) {
      return { method: h.name, client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: h.name, path: entry, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_UNSUPPORTED_SYNTAX, unknowns: ["handler exportado em forma não analisável — nunca tratar como seguro"] }) };
    }
    try {
      h.fn.__name = h.name;
      return analyzeHandlerIR(h.fn, sf, code, entry, files, rls);
    } catch (e) {
      return { method: h.name, client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: h.name, path: entry, status: STATUS.INSUFFICIENT, reasonCode: REASON.INSUFFICIENT_ANALYSIS_ERROR, unknowns: [String(e.message).slice(0, 120)] }) };
    }
  });
}

// visão compatível com o formato do analyzer6 (para o harness diferencial)
export function legacyView(results) {
  return results.map((r) => ({ method: r.method, verdict: r.decision.status, reason: r.decision.reasonCode, client: r.client }));
}

// ---------- server actions ----------
// Mesmo motor de provas das rotas; muda só a descoberta (funções exportadas de um
// arquivo "use server") e as fontes (argumentos = cliente). Toda decisão carrega
// a assumption SERVER_ACTION_IS_PUBLIC_ENDPOINT.
function analyzeActionFile(files, entry, rls) {
  const code = files[entry];
  const sf = parse(code);
  const hs = discoverServerActions(sf);
  const tag = (res, name) => {
    const label = `ACTION ${name}`;
    const extra = assumptionRefs([A.SERVER_ACTION_IS_PUBLIC_ENDPOINT]);
    for (const d of [res.decision, ...res.sinkDecisions]) {
      d.method = label;
      if (!d.assumptions.some((a) => a.id === A.SERVER_ACTION_IS_PUBLIC_ENDPOINT)) d.assumptions = [...d.assumptions, ...extra];
    }
    return { ...res, method: label };
  };
  if (!hs.length)
    return [tag({ method: "?", client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: "?", path: entry, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_NO_HANDLER, unknowns: ["arquivo \"use server\" sem função async exportada"] }) }, "?")];
  return hs.map((h) => {
    if (!h.supported)
      return tag({ method: h.name, client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: h.name, path: entry, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_UNSUPPORTED_SYNTAX, unknowns: ["server action exportada em forma não analisável (ex.: wrapper) — nunca tratar como segura"] }) }, h.name);
    try {
      h.fn.__name = h.name;
      return tag(analyzeHandlerIR(h.fn, sf, code, entry, files, rls, { kind: "action" }), h.name);
    } catch (e) {
      return tag({ method: h.name, client: "unknown", sinkDecisions: [], decision: mkDecision({ unit: "handler", method: h.name, path: entry, status: STATUS.INSUFFICIENT, reasonCode: REASON.INSUFFICIENT_ANALYSIS_ERROR, unknowns: [String(e.message).slice(0, 120)] }) }, h.name);
    }
  });
}
