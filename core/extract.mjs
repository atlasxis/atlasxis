// Atlasxis — discovery, sources e sinks (REQUISITO 9 + porta estrutural
// do findAllSinks do analyzer6, preservando a correção M1: chaves de
// PropertyAssignment e nomes de membro nunca contam como dado retornado).

import ts from "typescript";
import { Sink } from "./ir.mjs";

export const HTTP = /^(GET|POST|PUT|PATCH|DELETE)$/;
export const OWNER = new Set(["user_id","owner_id","created_by","sender_id","profile_id","author_id","requester_id","reporter_id","blocker_id"]);
export const CONTAINER = new Set(["conversation_id","post_id","comment_id","id"]);

export const parse = (c) => ts.createSourceFile("t.ts", c, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
export function walk(n, fn) { fn(n); n.forEachChild((c) => walk(c, fn)); }
export function findAll(n, p) { const o = []; walk(n, (x) => { if (p(x)) o.push(x); }); return o; }
export const T = (n, sf) => n.getText(sf);
export const canonText = (n, sf) => T(n, sf).replace(/\?\./g, ".").replace(/\s+/g, "").trim();
export function isDead(n) {
  let p = n.parent;
  while (p) {
    if (ts.isIfStatement(p) && p.expression.kind === ts.SyntaxKind.FalseKeyword && p.thenStatement && n.pos >= p.thenStatement.pos && n.end <= p.thenStatement.end) return true;
    p = p.parent;
  }
  return false;
}
export function callee(c) {
  return ts.isIdentifier(c.expression) ? c.expression.text
    : ts.isPropertyAccessExpression(c.expression) ? c.expression.name.text : "";
}
export function paramNames(fn, sf) { return fn.parameters.map((pp) => pp.name.getText(sf)); }

// ---------- DISCOVERY (REQUISITO 9) ----------
// Reconhece:  export async function GET(...)   e   export const GET = async (...) => {...}
// Formas exportadas com nome HTTP que não são função analisável viram
// NOT_ANALYZED_UNSUPPORTED_SYNTAX (nunca silêncio pelo motivo errado).
export function discoverHandlers(sf) {
  const found = [];
  findAll(sf, (n) => ts.isFunctionDeclaration(n) && HTTP.test(n.name?.text || "")).forEach((n) => {
    if (n.body) found.push({ name: n.name.text, fn: n, supported: true });
    else found.push({ name: n.name.text, fn: null, supported: false });
  });
  findAll(sf, ts.isVariableStatement).forEach((st) => {
    st.declarationList.declarations.forEach((d) => {
      if (!ts.isIdentifier(d.name) || !HTTP.test(d.name.text)) return;
      let init = d.initializer;
      if (!init) return;
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
        if (init.body) found.push({ name: d.name.text, fn: init, supported: !!(ts.isBlock(init.body) || init.body) });
      } else {
        // export const GET = wrapper(handler) etc. — não suportado, mas visível
        found.push({ name: d.name.text, fn: null, supported: false });
      }
    });
  });
  return found;
}

// ---------- SOURCES ----------
// Identificadores/expressões controláveis pelo cliente. Além dos nomes
// destructurados (analyzer6), rastreia acesso inline `params.id` (REQUISITO 9).
export function collectSources(fn, sf) {
  const s = new Set();
  const add = (kind, expr) => s.add(JSON.stringify({ kind, expr }));
  findAll(fn, (n) => ts.isVariableDeclaration(n) && n.initializer).forEach((d) => {
    const init = T(d.initializer, sf);
    if (/\b(params|searchParams)\b|request\.json\(\)|await\s+req\.json|await\s+request\.json/.test(init)) {
      if (ts.isIdentifier(d.name)) add("client-binding", d.name.text);
      if (ts.isObjectBindingPattern(d.name)) d.name.elements.forEach((e) => add("route-param", e.name.getText(sf)));
    }
  });
  findAll(fn, (n) => ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && /^(body|params|searchParams)$/.test(n.expression.text))
    .forEach((pa) => { add("member-name", pa.name.text); add("member-expr", canonText(pa, sf)); });
  // query params: searchParams.get("x") / nextUrl.searchParams.get("x") / url.searchParams.get("x")
  findAll(fn, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "get" && /searchParams$/.test(canonText(n.expression.expression, sf)))
    .forEach((c) => add("query-param", canonText(c, sf)));
  // propagação de alias (1..3 saltos): const X = <source ident> torna X uma
  // source derivada. Direção estritamente conservadora: um alias nunca vira
  // prova de identidade (o engine emite INSUFFICIENT_ALIAS_RESOLUTION), mas
  // deixa de ser silêncio pelo motivo errado.
  const exprsNow = () => new Set([...s].map((x) => JSON.parse(x).expr));
  for (let hop = 0; hop < 3; hop++) {
    let changed = false;
    const cur = exprsNow();
    findAll(fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isIdentifier(n.initializer))
      .forEach((d) => {
        if (cur.has(d.initializer.text) && !cur.has(d.name.text)) { add("alias", d.name.text); changed = true; }
      });
    if (!changed) break;
  }
  return {
    exprs: exprsNow(),
    detail: [...s].map((x) => JSON.parse(x)),
  };
}

// ---------- client kind ----------
// Convenção de nomes de API — sempre acompanhada da assumption CLIENT_KIND_BY_API_NAME.
// ---------- server actions (Next.js "use server") ----------
// Um arquivo é de server actions quando a PRIMEIRA instrução é a diretiva
// "use server" (o Next.js exige que ela venha antes de qualquer import).
// Cada função async EXPORTADA vira um endpoint que qualquer cliente chama com
// quaisquer argumentos. Diretivas inline ("use server" dentro de uma função num
// componente) não são descobertas (GAP registrado).
// Pré-filtro em TEMPO LINEAR (sem regex): pula espaços e comentários do topo e
// olha só as strings do prólogo de diretivas. Uma regex com quantificadores
// aninhados aqui travava em arquivos inteiros de código comentado (ReDoS achado
// na validação externa) — e a detecção roda em todo arquivo do projeto.
function startsWithUseServer(code) {
  let i = 0;
  const n = code.length;
  for (;;) {
    while (i < n && /\s/.test(code[i])) i++;
    if (code.startsWith("//", i)) { const e = code.indexOf("\n", i); if (e < 0) return false; i = e + 1; continue; }
    if (code.startsWith("/*", i)) { const e = code.indexOf("*/", i + 2); if (e < 0) return false; i = e + 2; continue; }
    const q = code[i];
    if (q !== "'" && q !== '"') return false;            // primeira instrução não é diretiva
    const end = code.indexOf(q, i + 1);
    if (end < 0) return false;
    if (code.slice(i + 1, end) === "use server") return true;
    i = end + 1;                                         // outra diretiva ("use strict"...): segue
    while (i < n && (code[i] === " " || code[i] === "\t")) i++;
    if (code[i] === ";") i++;
  }
}
export function isServerActionFile(code) {
  if (!startsWithUseServer(code)) return false;
  const sf = parse(code);
  for (const st of sf.statements) {
    if (ts.isExpressionStatement(st) && ts.isStringLiteral(st.expression)) { if (st.expression.text === "use server") return true; continue; }
    return false;
  }
  return false;
}
const isExported = (n) => !!(ts.getCombinedModifierFlags(n) & ts.ModifierFlags.Export);
export function discoverServerActions(sf) {
  const found = [];
  for (const st of sf.statements) {
    if (ts.isFunctionDeclaration(st) && isExported(st)) {
      const name = st.name?.text || "default";
      found.push(st.body ? { name, fn: st, supported: true } : { name, fn: null, supported: false });
    } else if (ts.isVariableStatement(st) && isExported(st)) {
      st.declarationList.declarations.forEach((d) => {
        if (!ts.isIdentifier(d.name) || !d.initializer) return;
        const init = d.initializer;
        if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.body) found.push({ name: d.name.text, fn: init, supported: true });
        else found.push({ name: d.name.text, fn: null, supported: false }); // wrapper(...) etc.
      });
    }
  }
  return found;
}
// Fontes de uma server action: TODOS os argumentos são do cliente, inclusive
// campos de FormData (formData.get("x")) e membros de objetos recebidos.
const unwrapInit = (n) => {
  for (;;) {
    if (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(n)) || ts.isAwaitExpression(n)) { n = n.expression; continue; }
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && /^(String|Number)$/.test(n.expression.text) && n.arguments.length === 1) { n = n.arguments[0]; continue; }
    return n;
  }
};
export function collectActionSources(fn, sf) {
  const base = collectSources(fn, sf);
  const s = new Map(base.detail.map((d) => [d.expr, d]));
  const add = (kind, expr) => { if (!s.has(expr)) s.set(expr, { kind, expr }); };
  const argNames = [];
  for (const p of fn.parameters || []) for (const n of boundNames(p.name)) { argNames.push(n); add("action-arg", n); }
  const isArg = (e) => ts.isIdentifier(e) && argNames.includes(e.text);
  // arg.campo  e  arg.get("campo") (FormData)
  findAll(fn, (n) => ts.isPropertyAccessExpression(n) && isArg(n.expression) && n.name.text !== "get").forEach((pa) => add("action-arg-member", canonText(pa, sf)));
  findAll(fn, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "get" && isArg(n.expression.expression))
    .forEach((c) => add("form-field", canonText(c, sf)));
  // const x = formData.get("x") as string  /  const x = input.id
  findAll(fn, (n) => ts.isVariableDeclaration(n) && n.initializer).forEach((d) => {
    const init = unwrapInit(d.initializer);
    const fromArg = (ts.isCallExpression(init) && ts.isPropertyAccessExpression(init.expression) && init.expression.name.text === "get" && isArg(init.expression.expression)) ||
      (ts.isPropertyAccessExpression(init) && isArg(init.expression)) || isArg(init);
    if (!fromArg) return;
    if (ts.isIdentifier(d.name)) add("action-arg-derived", d.name.text);
    else boundNames(d.name).forEach((n) => add("action-arg-derived", n));
  });
  // alias (1..3 saltos), mesma regra conservadora das rotas
  for (let hop = 0; hop < 3; hop++) {
    let changed = false;
    findAll(fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isIdentifier(n.initializer))
      .forEach((d) => { if (s.has(d.initializer.text) && !s.has(d.name.text)) { add("alias", d.name.text); changed = true; } });
    if (!changed) break;
  }
  return { exprs: new Set(s.keys()), detail: [...s.values()] };
}

// Identidade contaminada: o motor reconhece a identidade do servidor pelo texto
// (user.id, session.user.id, authUser.id). Se a variável raiz dessa identidade
// vier de dado controlado pelo cliente (corpo, params, query, formData, cookies
// crus, headers, ou um parâmetro da função), qualquer prova baseada nela é falsa.
// Retorna a lista de evidências (vazia = identidade não contaminada).
const ID_ROOTS = new Set(["user", "session", "authUser"]);
const CLIENT_INIT = /\brequest\.json\(\)|\breq\.json\(\)|\brequest\.formData\(\)|\brequest\.text\(\)|\bformData\b|\bparams\b|\bsearchParams\b|\bnextUrl\b|\bbody\b|\bcookies\(\)\.get|\bheaders\(\)\.get|\brequest\.headers\.get|\brequest\.cookies\.get/;
function boundNames(nameNode, out = []) {
  if (ts.isIdentifier(nameNode)) out.push(nameNode.text);
  else if (ts.isObjectBindingPattern(nameNode) || ts.isArrayBindingPattern(nameNode))
    nameNode.elements.forEach((e) => { if (e.name) boundNames(e.name, out); });
  return out;
}
export function identityFromClient(fn, sf, sourceExprs = new Set()) {
  const ev = [];
  const clientIdents = [...sourceExprs].filter((e) => /^[A-Za-z_$][\w$]*$/.test(e) && !ID_ROOTS.has(e));
  const touchesClient = (text) => CLIENT_INIT.test(text) || clientIdents.some((id) => new RegExp(`\\b${id.replace(/\$/g, "\\$")}\\b`).test(text));
  for (const p of fn.parameters || []) for (const n of boundNames(p.name)) if (ID_ROOTS.has(n)) ev.push(`parâmetro "${n}" da função é controlado por quem chama`);
  findAll(fn, (n) => ts.isVariableDeclaration(n) && n.initializer).forEach((d) => {
    const names = boundNames(d.name).filter((n) => ID_ROOTS.has(n));
    if (names.length && touchesClient(T(d.initializer, sf))) ev.push(`${names.join(", ")} vem de dado do cliente: ${T(d.initializer, sf).replace(/\s+/g, " ").slice(0, 80)}`);
  });
  findAll(fn, (n) => ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && ID_ROOTS.has(n.left.text)).forEach((a) => {
    if (touchesClient(T(a.right, sf))) ev.push(`${a.left.text} recebe dado do cliente: ${T(a.right, sf).replace(/\s+/g, " ").slice(0, 80)}`);
  });
  return ev;
}

// Tipo de cliente POR SINK: segue a cadeia `X.from(...)...` até a variável raiz X
// e classifica X pelo próprio nome e pela expressão que o criou (mesmo
// vocabulário de clientKind). Antes era por ARQUIVO: num arquivo com vários
// handlers/actions, um único supabaseAdmin fazia TODOS virarem service_role
// (falso VULNERABLE achado na validação externa). Se X não tem declaração
// (global livre, comum em fixtures), cai no tipo do arquivo, como antes.
function receiverRoot(node) {
  let n = node;
  for (;;) {
    if (!n) return null;
    if (ts.isIdentifier(n)) return n;
    if (ts.isCallExpression(n) || ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n) ||
        ts.isNonNullExpression(n) || ts.isParenthesizedExpression(n) || ts.isAwaitExpression(n)) { n = n.expression; continue; }
    return null;
  }
}
function declOf(name, fn, sf, beforePos) {
  const inFn = findAll(fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.pos < beforePos);
  if (inFn.length) return { kind: "var", init: inFn[inFn.length - 1].initializer || null };
  for (const p of fn.parameters || []) if (boundNames(p.name).includes(name)) return { kind: "param", init: null };
  for (const st of sf.statements) if (ts.isVariableStatement(st))
    for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) return { kind: "var", init: d.initializer || null };
  return null;
}
// `prov.via` registra quando o tipo veio de uma definição importada, para a
// decisão declarar CLIENT_KIND_BY_IMPORTED_DEFINITION.
export function sinkClientKind(sink, fn, sf, fileKind, files = null, prov = {}) {
  const root = receiverRoot(sink.node);
  if (!root) return fileKind;
  const byName = clientKind(root.text);
  const decl = declOf(root.text, fn, sf, sink.pos);
  const imported = (name) => { const k = importedClientKind(name, sf, files); if (k !== "unknown") prov.via = "imported-definition"; return k; };
  if (!decl) {
    if (byName !== "unknown") return byName;
    const k = imported(root.text);                                 // `import { adminDb } from "@/lib/db"`
    return k !== "unknown" ? k : fileKind;                         // global livre: comportamento anterior
  }
  if (decl.kind === "param") return byName;                        // cliente recebido por parâmetro
  const byInit = decl.init ? clientKind(decl.init.getText(sf)) : "unknown";
  if (byInit !== "unknown") return byInit;
  if (byName !== "unknown") return byName;
  // `const supabase = await createClient()` com createClient importado de outro arquivo
  const callee = decl.init ? receiverCallee(decl.init) : null;
  return callee ? imported(callee) : byName;
}

function receiverCallee(init) {
  let n = init;
  while (n && (ts.isAwaitExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n))) n = n.expression;
  return n && ts.isCallExpression(n) && ts.isIdentifier(n.expression) ? n.expression.text : null;
}

// Resolve um nome importado no conjunto de arquivos e classifica a definição
// exportada (mais as funções do mesmo arquivo que ela chama). FAIL-CLOSED: import
// que casa com mais de um arquivo, alvo ausente, ou definição que mistura admin e
// usuário → "unknown".
export function importedClientKind(name, sf, files) {
  if (!files || !sf) return "unknown";
  for (const imp of findAll(sf, ts.isImportDeclaration)) {
    const named = imp.importClause?.namedBindings;
    if (!named || !ts.isNamedImports(named)) continue;
    const el = named.elements.find((e) => e.name.text === name);
    if (!el) continue;
    const spec = ts.isStringLiteral(imp.moduleSpecifier) ? imp.moduleSpecifier.text : "";
    if (!/^(\.|[@~]\/)/.test(spec)) return "unknown";             // pacote externo
    const suffix = spec.replace(/^[@~]\//, "").replace(/^(\.\.?\/)+/, "");
    const cands = Object.keys(files).filter((p) => [".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.js"].some((ext) => p === suffix + ext || p.endsWith("/" + suffix + ext)));
    if (cands.length !== 1) return "unknown";
    const def = exportedDefinitionText(files[cands[0]], (el.propertyName || el.name).text);
    return def ? kindOfDefinition(def) : "unknown";
  }
  return "unknown";
}

function exportedDefinitionText(code, name) {
  const dsf = parse(code);
  const exported = (n) => (ts.getCombinedModifierFlags(n) & ts.ModifierFlags.Export) !== 0;
  let node = null;
  for (const st of dsf.statements) {
    if (ts.isFunctionDeclaration(st) && st.name?.text === name && exported(st)) node = st;
    if (ts.isVariableStatement(st) && exported(st)) for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) node = d;
  }
  if (!node) return null;
  const helpers = findAll(node, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression)).map((c) => c.expression.text);
  const helperTexts = [...new Set(helpers)].map((h) => findFnIn(code, "", h)).filter(Boolean).map((r) => r.node.getText(r.sf));
  return [node.getText(dsf), ...helperTexts].join("\n");
}

function kindOfDefinition(text) {
  const admin = /SERVICE_ROLE|service_role|supabaseAdmin|createSupabaseAdminClient/.test(text);
  const user = /createServerClient|createRouteHandlerClient|supabaseAuth/.test(text);
  if (admin && !user) return "service_role";
  if (user && !admin) return "authenticated";
  return "unknown";
}

export function clientKind(code) {
  if (/supabaseAdmin|createSupabaseAdminClient|service_role/.test(code)) return "service_role";
  if (/createServerClient|supabaseAuth|createRouteHandlerClient/.test(code)) return "authenticated";
  return "unknown";
}

// ---------- queries e sinks ----------
export function queryInfo(node, sf) {
  const froms = findAll(node, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "from");
  if (!froms.length) return null;
  const table = ts.isStringLiteral(froms[0].arguments[0]) ? froms[0].arguments[0].text : null;
  const eqs = findAll(node, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && (n.expression.name.text === "eq" || n.expression.name.text === "match"));
  const filters = eqs.map((e) => ({
    col: ts.isStringLiteral(e.arguments[0]) ? e.arguments[0].text : null,
    val: e.arguments[1] ? canonText(e.arguments[1], sf) : "",
  }));
  // colunas selecionadas (para exigir que o campo owner do gate tenha sido lido)
  let selectCols = null;
  const selCall = findAll(node, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "select" && n.arguments[0] && ts.isStringLiteral(n.arguments[0]))[0];
  if (selCall) selectCols = selCall.arguments[0].text.split(",").map((s) => s.trim().replace(/"/g, "").toLowerCase()).filter(Boolean);
  let op = "read", fields = [], writeSpreads = [];
  const w = findAll(node, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && /^(insert|update|delete|upsert)$/.test(n.expression.name.text));
  if (w.length) {
    op = w[0].expression.name.text;
    const arg = w[0].arguments[0];
    const objs = arg ? (ts.isArrayLiteralExpression(arg) ? arg.elements : [arg]) : [];
    objs.forEach((o) => {
      if (o && ts.isObjectLiteralExpression(o)) o.properties.forEach((pr) => {
        if (pr.name && (ts.isPropertyAssignment(pr) || ts.isShorthandPropertyAssignment(pr))) {
          const k = pr.name.getText(sf);
          const v = pr.initializer ? canonText(pr.initializer, sf) : k;
          fields.push({ key: k, val: v });
        }
        // { ...x }: colunas desconhecidas gravadas (podem sobrescrever o dono)
        if (ts.isSpreadAssignment(pr)) writeSpreads.push(canonText(pr.expression, sf));
      });
    });
  }
  // Filters the engine does not model (.filter/.or/.in/.not/.contains/…, an !inner join): they can bind the
  // rows to the caller, so their presence forbids proving that nothing does.
  const unmodeledFilters = findAll(node, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && /^(filter|or|in|not|contains|containedBy|overlaps|textSearch|rangeGt|rangeLt|is|like|ilike)$/.test(n.expression.name.text)).map((n) => n.expression.name.text);
  if (selectCols?.some((col) => col.includes("!inner")) || (selCall && /!inner/.test(selCall.arguments[0].text))) unmodeledFilters.push("!inner");
  return { table, filters, op, fields, selectCols, writeSpreads, unmodeledFilters };
}

export function findAllSinks(fn, sf) {
  const sinks = []; const seen = new Set();
  const push = (node, returned) => {
    const q = queryInfo(node, sf);
    if (q && q.table) {
      const key = q.table + ":" + q.op + ":" + node.pos;
      if (!seen.has(key)) { seen.add(key); sinks.push({ ...Sink({ ...q, pos: node.pos, returned }), node, spreads: q.writeSpreads || [], unmodeledFilters: q.unmodeledFilters || [] }); }
    }
  };
  // reads expostos via return — M1: exclui chaves de PropertyAssignment e nomes de membro
  const rets = findAll(fn, ts.isReturnStatement).filter((r) => !isDead(r) && r.expression);
  const ids = new Set();
  rets.forEach((r) => findAll(r.expression, ts.isIdentifier).forEach((i) => {
    if (i.parent && ts.isPropertyAssignment(i.parent) && i.parent.name === i) return;
    if (i.parent && ts.isPropertyAccessExpression(i.parent) && i.parent.name === i) return;
    ids.add(i.text);
  }));
  const decls = findAll(fn, (n) => ts.isVariableDeclaration(n)).filter((d) => !isDead(d));
  for (const id of ids) for (const d of decls) {
    let names = [];
    if (ts.isIdentifier(d.name)) names = [d.name.text];
    if (ts.isObjectBindingPattern(d.name)) names = d.name.elements.map((e) => e.name.getText(sf));
    let idx = -1;
    if (ts.isArrayBindingPattern(d.name)) {
      d.name.elements.forEach((e, i) => {
        if (!e.name) return;
        if (ts.isIdentifier(e.name) && e.name.text === id) idx = i;
        if (ts.isObjectBindingPattern(e.name)) e.name.elements.forEach((oe) => { if (oe.name.getText(sf) === id) idx = i; });
      });
    } else idx = names.indexOf(id);
    if (idx < 0 || !d.initializer) continue;
    let init = d.initializer;
    if (ts.isAwaitExpression(init)) init = init.expression;
    if (ts.isCallExpression(init) && callee(init) === "all" && init.arguments[0] && ts.isArrayLiteralExpression(init.arguments[0])) {
      const el = init.arguments[0].elements[idx]; if (el) push(el, true);
    } else push(init, true);
  }
  // write sinks: qualquer chain .from(T).insert|update|delete|upsert viva
  findAll(fn, (n) => ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && /^(insert|update|delete|upsert)$/.test(n.expression.name.text) && !isDead(n)).forEach((w) => {
    let top = w;
    while (top.parent && (ts.isCallExpression(top.parent) || ts.isPropertyAccessExpression(top.parent) || ts.isAwaitExpression(top.parent))) top = top.parent;
    push(top, false);
  });
  return sinks;
}

// reads de recurso no corpo do handler (para post-read/transitive)
export function collectReads(fn, sf, beforePos = Infinity) {
  const reads = [];
  findAll(fn, (n) => ts.isVariableDeclaration(n) && !isDead(n) && n.pos < beforePos).forEach((d) => {
    if (!d.initializer) return;
    let init = d.initializer;
    if (ts.isAwaitExpression(init)) init = init.expression;
    const q = queryInfo(init, sf);
    if (!q) return;
    const bindings = [];
    if (ts.isIdentifier(d.name)) bindings.push(d.name.text);
    if (ts.isObjectBindingPattern(d.name)) d.name.elements.forEach((e) => {
      const prop = e.propertyName?.getText(sf) || e.name.getText(sf);
      bindings.push(e.name.getText(sf));
      if (prop === "data") bindings.dataBinding = e.name.getText(sf);
    });
    reads.push({ bindings, q, pos: d.pos, node: d });
  });
  return reads;
}

function findFnIn(code, p, name) {
  const sf = parse(code);
  const f = findAll(sf, (n) => (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n)) && n.name?.text === name);
  if (f.length && f[0].body) return { node: f[0], sf, code, path: p };
  const v = findAll(sf, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer)) && n.initializer.body);
  if (v.length) return { node: v[0].initializer, sf, code, path: p };
  return null;
}

// Resolve um helper por nome. FAIL-CLOSED contra ambiguidade:
//  - se `sf` (arquivo chamador) importa o nome, a busca é RESTRITA aos arquivos
//    cujo caminho casa com o module specifier do import;
//  - sem import: se o nome é definido em MAIS de um arquivo com corpos
//    diferentes, retorna null (nunca escolher silenciosamente).
export function resolveFn(name, files, sf = null) {
  const paths = Object.keys(files).sort();
  if (sf) {
    for (const imp of findAll(sf, ts.isImportDeclaration)) {
      const named = imp.importClause?.namedBindings;
      if (!named || !ts.isNamedImports(named)) continue;
      const el = named.elements.find((e) => e.name.text === name);
      if (!el) continue;
      const spec = ts.isStringLiteral(imp.moduleSpecifier) ? imp.moduleSpecifier.text : "";
      const suffix = spec.replace(/^@\//, "").replace(/^\.\.?\//, "");
      const targetName = (el.propertyName || el.name).text;
      const cands = paths.filter((p) => p.endsWith(suffix + ".ts") || p.endsWith(suffix + ".tsx") || p.endsWith(suffix));
      for (const p of cands) { const r = findFnIn(files[p], p, targetName); if (r) return r; }
      return null; // importado mas alvo fora do conjunto → não resolvível
    }
  }
  const hits = [];
  for (const p of paths) { const r = findFnIn(files[p], p, name); if (r) hits.push(r); }
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) {
    const bodies = new Set(hits.map((h) => h.node.getText(h.sf)));
    if (bodies.size === 1) return hits[0]; // definições idênticas: sem ambiguidade
    return null; // nomes duplicados com corpos diferentes → ambíguo, fail-closed
  }
  return null;
}

// O gate DOMINA o sink? Todo ancestral condicional (if/loop/switch/ternário)
// do gate precisa também conter o sink — senão o gate pode nunca executar no
// caminho que atinge o sink (prova precisa estar viva no fluxo).
export function dominatesSink(node, fn, sinkPos) {
  let p = node.parent;
  let child = node;
  while (p && p !== fn && p.pos !== undefined) {
    if (ts.isIfStatement(p) && child !== p.expression) {
      const branch = p.thenStatement && child.pos >= p.thenStatement.pos && child.end <= p.thenStatement.end ? p.thenStatement
        : p.elseStatement && child.pos >= p.elseStatement.pos && child.end <= p.elseStatement.end ? p.elseStatement : null;
      // continência ESTRITA: node.pos inclui trivia, então um sink logo após o
      // fechamento do branch tem pos igual a branch.end — está FORA.
      if (branch && !(sinkPos > branch.pos && sinkPos < branch.end)) return false;
    }
    if ((ts.isForStatement(p) || ts.isForOfStatement(p) || ts.isForInStatement(p) || ts.isWhileStatement(p) || ts.isDoStatement(p) || ts.isSwitchStatement(p) || ts.isConditionalExpression(p) || ts.isCaseClause(p) || ts.isDefaultClause(p)) &&
        !(sinkPos > p.pos && sinkPos < p.end)) return false;
    child = p; p = p.parent;
  }
  return true;
}

// o callee é importado de um módulo FORA do conjunto de arquivos analisado?
export function isImportedUnresolved(name, sf) {
  for (const imp of findAll(sf, ts.isImportDeclaration)) {
    const named = imp.importClause?.namedBindings;
    if (named && ts.isNamedImports(named) && named.elements.some((e) => e.name.text === name)) return true;
    if (imp.importClause?.name?.text === name) return true;
  }
  return false;
}

export { ts };
