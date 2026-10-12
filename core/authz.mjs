// Atlasxis — Authorization IR (REQUISITO 3).
//
// Condições de autorização viram AST booleana estruturada — nunca string.
// Normalização lógica (NNF via De Morgan + eliminação de dupla negação +
// negação de comparações) com verificação semântica por truth table:
// normalize(e) só é usada se equivalent(e, normalize(e)) === true.

import ts from "typescript";

// ---------- termos ----------
// term = { text, member: {obj, field} | null, isString, strVal }
const canon = (t) => t.replace(/\?\./g, ".").replace(/\s+/g, "").trim();

function term(node, sf) {
  const text = canon(node.getText(sf));
  const out = { text, member: null, isString: false, strVal: null };
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    out.isString = true; out.strVal = node.text;
  }
  const m = text.match(/^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.([A-Za-z_$][\w$]*)$/);
  if (m) out.member = { obj: m[1], field: m[2] };
  return out;
}

// ---------- construção da AST ----------
// nós: {k:"and"|"or", args} | {k:"not", arg} | {k:"cmp", op:"eq"|"ne", left, right} | {k:"truthy", term}

export function fromTsExpression(node, sf, resolveIdent = null, depth = 0) {
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken)
      return { k: "and", args: [fromTsExpression(node.left, sf, resolveIdent, depth), fromTsExpression(node.right, sf, resolveIdent, depth)] };
    if (op === ts.SyntaxKind.BarBarToken)
      return { k: "or", args: [fromTsExpression(node.left, sf, resolveIdent, depth), fromTsExpression(node.right, sf, resolveIdent, depth)] };
    if (op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken)
      return { k: "cmp", op: "eq", left: term(node.left, sf), right: term(node.right, sf) };
    if (op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken)
      return { k: "cmp", op: "ne", left: term(node.left, sf), right: term(node.right, sf) };
    return { k: "truthy", term: term(node, sf) };
  }
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken)
    return { k: "not", arg: fromTsExpression(node.operand, sf, resolveIdent, depth) };
  if (ts.isIdentifier(node) && resolveIdent && depth < 4) {
    const sub = resolveIdent(node.text, depth);
    if (sub) return sub; // expansão de variável booleana (const isOwner = ...)
  }
  return { k: "truthy", term: term(node, sf) };
}

export const not = (e) => ({ k: "not", arg: e });

// ---------- normalização (De Morgan como conceito interno) ----------

export function toNNF(e) {
  if (e.k === "not") {
    const a = e.arg;
    if (a.k === "not") return toNNF(a.arg);                         // ¬¬X ⇒ X
    if (a.k === "and") return { k: "or", args: a.args.map((x) => toNNF(not(x))) };  // ¬(A∧B) ⇒ ¬A∨¬B
    if (a.k === "or") return { k: "and", args: a.args.map((x) => toNNF(not(x))) }; // ¬(A∨B) ⇒ ¬A∧¬B
    if (a.k === "cmp") return { ...a, op: a.op === "eq" ? "ne" : "eq" };            // ¬(a===b) ⇒ a!==b
    return { k: "not", arg: a }; // ¬truthy fica como literal negativo
  }
  if (e.k === "and" || e.k === "or") return { k: e.k, args: e.args.map(toNNF) };
  return e;
}

// DNF: lista de disjuntos; cada disjunto = lista de literais {atom, neg}
const CAP = 64;
export function toDNF(e) {
  const n = toNNF(e);
  function go(x) {
    if (x.k === "or") return x.args.flatMap(go);
    if (x.k === "and") {
      const parts = x.args.map(go); // cada parte: lista de disjuntos
      let acc = [[]];
      for (const p of parts) {
        const next = [];
        for (const a of acc) for (const d of p) { next.push([...a, ...d]); if (next.length > CAP) throw new Error("DNF cap"); }
        acc = next;
      }
      return acc;
    }
    if (x.k === "not") return [[{ atom: x.arg, neg: true }]];
    return [[{ atom: x, neg: false }]];
  }
  return go(n);
}

// ---------- verificação semântica (truth table) ----------

function atomKey(a) {
  if (a.k === "cmp") return "C:" + [a.left.text, a.right.text].sort().join("≡");
  if (a.k === "truthy") return "T:" + a.term.text;
  return "X:" + JSON.stringify(a);
}
function collectAtoms(e, set) {
  if (e.k === "and" || e.k === "or") e.args.forEach((x) => collectAtoms(x, set));
  else if (e.k === "not") collectAtoms(e.arg, set);
  else set.add(atomKey(e));
}
function evalExpr(e, assign) {
  if (e.k === "and") return e.args.every((x) => evalExpr(x, assign));
  if (e.k === "or") return e.args.some((x) => evalExpr(x, assign));
  if (e.k === "not") return !evalExpr(e.arg, assign);
  if (e.k === "cmp") { const base = assign[atomKey(e)]; return e.op === "eq" ? base : !base; }
  return assign[atomKey(e)];
}
export function equivalent(e1, e2) {
  const atoms = new Set(); collectAtoms(e1, atoms); collectAtoms(e2, atoms);
  const keys = [...atoms];
  if (keys.length > 14) return null; // não verificável por truth table — chamador deve tratar como não provado
  for (let mask = 0; mask < 1 << keys.length; mask++) {
    const assign = {}; keys.forEach((k, i) => (assign[k] = !!(mask & (1 << i))));
    if (evalExpr(e1, assign) !== evalExpr(e2, assign)) return false;
  }
  return true;
}

/** DNF verificada: só retorna se a transformação preservar semântica. */
export function verifiedDNF(e) {
  let d;
  try { d = toDNF(e); } catch { return null; }
  const back = { k: "or", args: d.map((conj) => ({ k: "and", args: conj.map((l) => (l.neg ? { k: "not", arg: l.atom } : l.atom)) })) };
  return equivalent(e, back) === true ? d : null;
}

// ---------- classificação de literais autorizadores ----------

const ID_FIELD = /^(?:\w*id|\w*_id)$/i;
const isUserIdent = (t) => /^(?:user\.id|session\.user\.id|authUser\.id)$/.test(t.text);

/**
 * Um literal POSITIVO é autorizador quando é:
 *  - ownership: R.<campo id-ish> === user.id  → {type:"ownership", obj, field}
 *  - admin:     <...>.role === "admin" | role === "admin" | is_admin truthy → {type:"admin"}
 * Literais negativos nunca autorizam (só restringem).
 */
export function classifyLiteral(lit) {
  if (lit.neg) return null;
  const a = lit.atom;
  if (a.k === "cmp" && a.op === "eq") {
    const sides = [[a.left, a.right], [a.right, a.left]];
    for (const [x, y] of sides) {
      // ownership = <objeto lido>.<campo> === <identidade autenticada>.
      // O nome do campo NÃO é a prova (aceitamos user_id, created_by, owner_id…);
      // a prova vem de o campo ter sido REALMENTE lido do recurso (constraint M06
      // em proofs.mjs) e de a tabela verificada == tabela do sink. A convenção
      // OWNER_COLUMN_CONVENTION é declarada como assumption.
      if (isUserIdent(y) && x.member)
        return { type: "ownership", obj: x.member.obj, field: x.member.field };
      if (isUserIdent(y) && !x.member && !x.isString && /^[A-Za-z_$][\w$]*$/.test(x.text))
        return { type: "identity-eq", ident: x.text }; // fraco: precisa de vínculo com read p/ virar ownership
      if (y.isString && y.strVal === "admin" && (x.text === "role" || (x.member && x.member.field === "role")))
        return { type: "admin" };
    }
  }
  // apenas o campo is_admin (dado lido), nunca variável camelCase não expandida:
  // convenção de nome não vira fato (REQUISITO 6)
  if (a.k === "truthy" && /(^|\.)is_admin$/.test(a.term.text)) return { type: "admin" };
  return null;
}
