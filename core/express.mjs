// Atlasxis — Express + Prisma (docs/EXPRESS-PRISMA.md).
//
// Prisma has no row-level security: every authorization decision lives in application code. This
// module discovers Express routes and their middleware chains, follows each handler across
// functions and files down to Prisma calls, and decides every data access ("sink") with the same
// Decision/ProofChain IR and the same invariants as the Supabase engine: CONTROLLED only with a
// complete proof, VULNERABLE only with positive evidence, everything else abstains with a reason.
// Nothing from the analyzed project is executed.

import ts from "typescript";
import { Source, Guard, IdentityProof, Authorization, ProofChain, Decision } from "./ir.mjs";
import { STATUS, REASON } from "./reason-codes.mjs";
import { ASSUMPTION as A } from "./assumptions.mjs";

const VERBS = new Set(["get", "post", "put", "patch", "delete"]);
const READ_OPS = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "count", "aggregate", "groupBy"]);
const WRITE_OPS = new Set(["update", "updateMany", "delete", "deleteMany", "upsert"]);
const CREATE_OPS = new Set(["create", "createMany"]);
const RAW_OPS = new Set(["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"]);
const MAX_DEPTH = 5;

const parseFile = (code) => ts.createSourceFile("f.ts", code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

function walkNodes(node, visit) {
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    visit(n);
    const kids = [];
    ts.forEachChild(n, (c) => { kids.push(c); });
    for (let i = kids.length - 1; i >= 0; i -= 1) stack.push(kids[i]);
  }
}
function findAll(node, pred) { const out = []; walkNodes(node, (n) => { if (pred(n)) out.push(n); }); return out; }
function strip(e) {
  let n = e;
  while (n && (ts.isAsExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n) || ts.isAwaitExpression(n) || ts.isTypeAssertionExpression?.(n) || ts.isSatisfiesExpression?.(n))) n = n.expression;
  return n;
}
function isFunctionLike(n) { return n && (ts.isArrowFunction(n) || ts.isFunctionExpression(n) || ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n)); }
function text(n, sf) { return n ? n.getText(sf) : ""; }
function lowerFirst(s) { return s ? s[0].toLowerCase() + s.slice(1) : s; }

export function isExpressProject(files) {
  return Object.values(files).some((c) => /from\s+["']express["']|require\(\s*["']express["']\s*\)/.test(c));
}

// ---------------- Prisma schema ----------------
// model -> { name, relations: [{ field, target, fks }] }
export function parsePrismaSchema(schemas) {
  const models = new Map();
  for (const content of Object.values(schemas)) {
    for (const m of content.matchAll(/\bmodel\s+(\w+)\s*\{([^}]*)\}/g)) {
      const relations = [];
      for (const line of m[2].split("\n")) {
        const f = line.trim().match(/^(\w+)\s+(\w+)(\[\])?\??\s*(.*)$/);
        if (!f) continue;
        const rel = f[4].match(/@relation\([^)]*fields:\s*\[([^\]]*)\]/);
        if (rel) relations.push({ field: f[1], target: f[2], fks: rel[1].split(",").map((x) => x.trim()).filter(Boolean) });
      }
      models.set(m[1], { name: m[1], relations });
    }
  }
  return models;
}

// ---------------- module resolution ----------------
class Project {
  constructor(files) {
    this.files = files;
    this.sfs = new Map();
    this.paths = Object.keys(files);
  }
  sf(path) {
    if (!this.sfs.has(path)) this.sfs.set(path, parseFile(this.files[path]));
    return this.sfs.get(path);
  }
  resolveModule(from, spec) {
    let bases;
    if (spec.startsWith(".")) {
      const dir = from.split("/").slice(0, -1);
      for (const part of spec.split("/")) { if (part === "..") dir.pop(); else if (part !== ".") dir.push(part); }
      bases = [dir.join("/")];
    } else if (/^[@~]\//.test(spec)) bases = [`src/${spec.slice(2)}`, spec.slice(2)];
    else return null;
    const hits = [];
    // NodeNext style: "./token.js" is written for the compiled output of token.ts
    bases = bases.flatMap((b) => (/\.(c|m)?js$/.test(b) ? [b.replace(/\.(c|m)?js$/, ""), b] : [b]));
    for (const base of bases) for (const ext of ["", ".ts", ".tsx", "/index.ts", "/index.tsx"]) if (this.files[base + ext] !== undefined && (ext || /\.tsx?$/.test(base))) hits.push(base + ext);
    const unique = [...new Set(hits)];
    return unique.length === 1 ? unique[0] : null;
  }
  // top-level declaration named `name` in `path`, following imports. Returns { path, node, kind }.
  resolveName(path, name, seen = new Set()) {
    const key = `${path}#${name}`;
    if (seen.has(key) || this.files[path] === undefined) return null;
    seen.add(key);
    const sf = this.sf(path);
    for (const st of sf.statements) {
      if (ts.isFunctionDeclaration(st) && st.name?.text === name) return { path, node: st, kind: "function" };
      if (ts.isClassDeclaration(st) && st.name?.text === name) return { path, node: st, kind: "class" };
      if (ts.isVariableStatement(st)) for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) return { path, node: d, kind: "var" };
      if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
        const clause = st.importClause;
        if (!clause) continue;
        const target = this.resolveModule(path, st.moduleSpecifier.text);
        const missing = { path, node: null, kind: /^(\.|[@~]\/)/.test(st.moduleSpecifier.text) ? "missing-local" : "external", spec: st.moduleSpecifier.text };
        if (clause.name?.text === name) return target ? this.resolveDefault(target, seen) : missing;
        const nb = clause.namedBindings;
        if (nb && ts.isNamedImports(nb)) for (const el of nb.elements) if (el.name.text === name) {
          return target ? this.resolveName(target, (el.propertyName || el.name).text, seen) : missing;
        }
        if (nb && ts.isNamespaceImport(nb) && nb.name.text === name) return target ? { path: target, node: null, kind: "namespace" } : missing;
      }
    }
    return null;
  }
  resolveDefault(path, seen = new Set()) {
    const sf = this.sf(path);
    for (const st of sf.statements) {
      if (ts.isExportAssignment(st)) {
        const e = strip(st.expression);
        if (ts.isIdentifier(e)) return this.resolveName(path, e.text, seen);
        return { path, node: e, kind: "expr" };
      }
      const isDefault = (n) => (ts.getCombinedModifierFlags(n) & ts.ModifierFlags.Default) !== 0;
      if ((ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) && isDefault(st)) return { path, node: st, kind: ts.isClassDeclaration(st) ? "class" : "function" };
    }
    return null;
  }
}

// ---------------- routers ----------------
function routerInit(e) {
  const n = strip(e);
  if (!n || !ts.isCallExpression(n)) return false;
  const c = n.expression;
  return (ts.isIdentifier(c) && (c.text === "Router" || c.text === "express")) || (ts.isPropertyAccessExpression(c) && c.name.text === "Router");
}

function discoverRouters(project) {
  const routers = new Map(); // key path#name -> router
  for (const path of project.paths) {
    if (!/Router\(|express\(/.test(project.files[path])) continue;
    const sf = project.sf(path);
    const local = new Map();
    for (const st of sf.statements) if (ts.isVariableStatement(st)) for (const d of st.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.initializer && routerInit(d.initializer)) {
        const r = { key: `${path}#${d.name.text}`, path, name: d.name.text, isApp: /express\(\)/.test(text(d.initializer, sf)), events: [], parents: [] };
        local.set(d.name.text, r);
        routers.set(r.key, r);
      }
    }
    if (!local.size) continue;
    // registrations in source order
    walkNodes(sf, (n) => {
      if (!ts.isCallExpression(n) || !ts.isPropertyAccessExpression(n.expression) || !ts.isIdentifier(n.expression.expression)) return;
      const r = local.get(n.expression.expression.text);
      if (!r) return;
      const m = n.expression.name.text;
      const args = [...n.arguments];
      if (VERBS.has(m)) {
        const p = args[0] && ts.isStringLiteral(args[0]) ? args[0].text : null;
        r.events.push({ type: "route", verb: m.toUpperCase(), path: p, args: args.slice(1), pos: n.pos, node: n });
      } else if (m === "use") {
        const prefix = args[0] && ts.isStringLiteral(args[0]) ? args[0].text : null;
        const rest = prefix === null ? args : args.slice(1);
        r.events.push({ type: "use", prefix, args: rest, pos: n.pos });
      } else if (m === "route") {
        r.events.push({ type: "unsupported", pos: n.pos, why: "router.route(...) chain" });
      } else if (m === "param") {
        r.events.push({ type: "param", pos: n.pos });
      }
    });
    // exports of routers
    for (const st of sf.statements) {
      if (ts.isExportAssignment(st) && ts.isIdentifier(strip(st.expression)) && local.has(strip(st.expression).text)) local.get(strip(st.expression).text).exportDefault = true;
    }
  }
  return routers;
}

function routerFor(project, routers, path, expr) {
  const e = strip(expr);
  if (!e || !ts.isIdentifier(e)) return null;
  const local = routers.get(`${path}#${e.text}`);
  if (local) return local;
  const res = project.resolveName(path, e.text);
  if (!res || !res.node) return null;
  if (res.kind === "var" && ts.isIdentifier(res.node.name)) return routers.get(`${res.path}#${res.node.name.text}`) || null;
  return null;
}

// ---------------- middleware ----------------
function firstParamName(fn) { const p = fn?.parameters?.[0]; return p && ts.isIdentifier(p.name) ? p.name.text : null; }
const VERIFY = /\b(jwt\.verify|jsonwebtoken\.verify|verify(Id|Access)?Token|jwtVerify|verifyJwt|passport\.authenticate|getAuth\(\)\.verify\w*|admin\.auth\(\)\.verify\w*)\s*\(/;
const REJECT = /\.status\(\s*40[13]\s*\)|sendStatus\(\s*40[13]\s*\)|\bthrow\b|\bnext\(\s*(new\s+\w+|[a-z]\w*Error|err)/;

function functionOf(project, path, expr, depth = 0) {
  if (depth > 4 || !expr) return null;
  const e = strip(expr);
  if (isFunctionLike(e)) return { path, fn: e };
  if (ts.isIdentifier(e)) {
    const r = project.resolveName(path, e.text);
    if (!r || !r.node) return null;
    if (r.kind === "function") return { path: r.path, fn: r.node };
    if (r.kind === "var" && r.node.initializer) return functionOf(project, r.path, r.node.initializer, depth + 1);
    if (r.kind === "expr") return functionOf(project, r.path, r.node, depth + 1);
    return null;
  }
  if (ts.isCallExpression(e)) {
    // wrapper `asyncHandler(fn)` or factory `requireRole('x')`
    const inner = e.arguments.find((a) => isFunctionLike(strip(a)));
    if (inner) {
      // a project wrapper that reads the database, params or identity may itself be the check
      let wrapperSuspicious = false;
      const w = strip(e.expression);
      if (ts.isIdentifier(w) && depth < 3) {
        const wf = functionOf(project, path, w, depth + 1);
        if (wf) wrapperSuspicious = /prisma|\.params\b|\.(user|professional|admin)\b|status\(\s*4\d\d|\bthrow\b/.test(text(wf.fn, project.sf(wf.path)));
      }
      return { path, fn: strip(inner), wrapped: true, wrapperSuspicious, wrapperName: text(e.expression, project.sf(path)).slice(0, 40) };
    }
    if (ts.isPropertyAccessExpression(e.expression) && e.expression.name.text === "bind") return functionOf(project, path, e.expression.expression, depth + 1);
    const factory = functionOf(project, path, e.expression, depth + 1);
    if (factory) {
      const ret = findAll(factory.fn, (n) => ts.isReturnStatement(n) && n.expression && isFunctionLike(strip(n.expression)))[0];
      if (ret) return { path: factory.path, fn: strip(ret.expression), factory: true };
      if (factory.fn.body && isFunctionLike(strip(factory.fn.body))) return { path: factory.path, fn: strip(factory.fn.body), factory: true };
    }
    return null;
  }
  if (ts.isPropertyAccessExpression(e)) return memberFunction(project, path, e, depth + 1);
  return null;
}

// obj.method where obj is a singleton (`new C()`), an object literal, or a namespace import.
function memberFunction(project, path, pa, depth = 0) {
  const objExpr = strip(pa.expression);
  const name = pa.name.text;
  if (!ts.isIdentifier(objExpr)) return null;
  const r = project.resolveName(path, objExpr.text);
  if (!r) return null;
  if (r.kind === "namespace") { const t = project.resolveName(r.path, name); return t?.node?.name ? functionOf(project, t.path, t.node.name, depth + 1) : null; }
  let init = r.kind === "var" ? strip(r.node.initializer) : r.kind === "expr" ? r.node : null;
  if (!init) return null;
  if (ts.isNewExpression(init) && ts.isIdentifier(init.expression)) {
    const cls = project.resolveName(r.path, init.expression.text);
    if (!cls || cls.kind !== "class") return null;
    for (const m of cls.node.members) {
      if (m.name && ts.isIdentifier(m.name) && m.name.text === name) {
        if (ts.isMethodDeclaration(m)) return { path: cls.path, fn: m, cls: cls.node };
        if (ts.isPropertyDeclaration(m) && m.initializer) { const f = functionOf(project, cls.path, m.initializer, depth + 1); return f ? { ...f, cls: cls.node } : null; }
      }
    }
    return null;
  }
  if (ts.isObjectLiteralExpression(init)) {
    for (const p of init.properties) {
      if (p.name && ts.isIdentifier(p.name) && p.name.text === name) {
        if (ts.isMethodDeclaration(p)) return { path: r.path, fn: p };
        if (ts.isPropertyAssignment(p)) return functionOf(project, r.path, p.initializer, depth + 1);
      }
    }
  }
  return null;
}

// Library calls that cryptographically verify a credential. A project function counts only if its own
// body (followed two levels) reaches one of these — `verifyToken(t) { return jwt.decode(t) }` does not.
const LIB_VERIFY = /^(jwt|jsonwebtoken)\.verify$|^jwtVerify$|\.verifyIdToken$|\.verifySessionCookie$|^passport\.authenticate$|\.verifyJwt$|^verifyJwt$/;

function isVerifyCall(project, path, call, depth = 0) {
  const sf = project.sf(path);
  const callee = strip(call.expression);
  const name = text(callee, sf);
  if (LIB_VERIFY.test(name)) return true;
  if (depth >= 2 || !/verif/i.test(name)) return false;
  if (ts.isIdentifier(callee)) {
    const r = project.resolveName(path, callee.text);
    if (r?.kind === "external") return /verif/i.test(callee.text);   // a library's own verifier
    const f = r ? functionOf(project, path, callee) : null;
    if (!f) return false;
    return findAll(f.fn, (n) => ts.isCallExpression(n)).some((c) => isVerifyCall(project, f.path, c, depth + 1));
  }
  return false;
}

// A node runs unconditionally in its function when no if/ternary/loop/logical stands between them
// (a top-level try block counts as unconditional).
function unconditional(node, fn) {
  for (let n = node.parent; n && n !== fn; n = n.parent) {
    if (ts.isIfStatement(n) || ts.isConditionalExpression(n) || ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n) || ts.isSwitchStatement(n) || ts.isCatchClause(n)) return false;
    if (ts.isBinaryExpression(n) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(n.operatorToken.kind)) return false;
    if (isFunctionLike(n)) return false;
  }
  return true;
}

function classifyMiddleware(project, path, expr, cache) {
  const key = `${path}#${text(expr, project.sf(path))}`;
  if (cache.has(key)) return cache.get(key);
  const out = { kind: "unknown", fields: [], principalModels: {}, label: text(expr, project.sf(path)).slice(0, 80) };
  cache.set(key, out);
  const e = strip(expr);
  if (ts.isCallExpression(e) && /passport\.authenticate/.test(text(e.expression, project.sf(path)))) {
    Object.assign(out, { kind: "auth", fields: ["user"], viaPassport: true });
    return out;
  }
  const f = functionOf(project, path, expr);
  if (!f) { out.kind = "unresolved"; return out; }
  const sf = project.sf(f.path);
  const body = text(f.fn, sf);
  const req = firstParamName(f.fn) || "req";
  const nextName = f.fn.parameters?.[2] && ts.isIdentifier(f.fn.parameters[2].name) ? f.fn.parameters[2].name.text : "next";
  const assigned = [...new Set([...body.matchAll(new RegExp(`\\b${req}\\s*(?:as\\s+\\w+\\)?)?\\)?\\s*\\.(\\w+)\\s*=(?!=)`, "g"))].map((m) => m[1]))].filter((x) => !["headers", "body", "query", "params"].includes(x));
  const calls = findAll(f.fn, (n) => ts.isCallExpression(n));
  // a bare next() before verification lets the request through unauthenticated (optional auth)
  const bareNexts = calls.filter((c) => ts.isIdentifier(strip(c.expression)) && strip(c.expression).text === nextName && c.arguments.length === 0);
  const verifyCalls = calls.filter((c) => isVerifyCall(project, f.path, c));
  const delegatedCalls = calls.filter((c) => ts.isIdentifier(c.expression) && c.arguments.length >= 3 && c.expression.text !== nextName)
    .map((c) => ({ c, m: classifyMiddleware(project, f.path, c.expression, cache) })).filter((x) => x.m.kind === "auth");
  const rejects = /\.status\(\s*40[13]\s*\)|sendStatus\(\s*40[13]\s*\)|\bthrow\b/.test(body) || calls.some((c) => ts.isIdentifier(strip(c.expression)) && strip(c.expression).text === nextName && c.arguments.length > 0);
  const firstGate = [...verifyCalls.filter((c) => unconditional(c, f.fn)), ...delegatedCalls.filter((x) => unconditional(x.c, f.fn)).map((x) => x.c)].sort((a, b) => a.pos - b.pos)[0];
  const inCatch = (n) => { for (let x = n.parent; x && x !== f.fn; x = x.parent) if (ts.isCatchClause(x)) return true; return false; };
  const optional = !firstGate || bareNexts.some((n) => n.pos < firstGate.pos || inCatch(n));
  if (!optional && rejects && ((verifyCalls.length && assigned.length) || delegatedCalls.length)) {
    out.kind = "auth";
    out.fields = [...new Set([...(verifyCalls.length ? assigned : []), ...delegatedCalls.flatMap((x) => x.m.fields)])];
    // which keys of req.<field> hold the identity: an object literal stores only its own keys; the
    // verified payload itself (or a variable) may carry sub/userId/uid too
    // Identity keys: only values that DERIVE from the verification result count. Derived names are
    // variables initialized from a verify call, then (transitively) from derived names — e.g. the
    // principal row looked up by payload.sub. An object literal contributes the keys whose values are
    // derived; a derived value stored whole contributes only `id` (other keys may be undefined, and
    // Prisma drops an undefined filter).
    const derived = new Set();
    const decls = findAll(f.fn, (n) => ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer);
    for (const d of decls) if (findAll(d.initializer, (n) => ts.isCallExpression(n) && verifyCalls.includes(n)).length || verifyCalls.includes(strip(d.initializer))) derived.add(d.name.text);
    for (let changed = true; changed;) {
      changed = false;
      for (const d of decls) if (!derived.has(d.name.text) && findAll(d.initializer, (n) => ts.isIdentifier(n) && derived.has(n.text)).length) { derived.add(d.name.text); changed = true; }
    }
    const isDerived = (e) => verifyCalls.includes(strip(e)) || findAll(e, (n) => ts.isIdentifier(n) && derived.has(n.text)).length > 0 || findAll(e, (n) => ts.isCallExpression(n) && verifyCalls.includes(n)).length > 0;
    out.identityKeys = {};
    for (const fld of out.fields) {
      const asg = findAll(f.fn, (n) => ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && text(strip(n.left), sf).endsWith(`.${fld}`)).map((n) => strip(n.right));
      let keys = asg.length ? null : [];
      for (const r of asg) {
        const here = ts.isObjectLiteralExpression(r)
          ? r.properties.filter((pr) => ts.isPropertyAssignment(pr) && pr.name && (ts.isIdentifier(pr.name) || ts.isStringLiteral(pr.name)) && isDerived(pr.initializer)).map((pr) => pr.name.text)
            .concat(r.properties.filter((pr) => ts.isShorthandPropertyAssignment(pr) && derived.has(pr.name.text)).map((pr) => pr.name.text))
          : isDerived(r) ? ["id"] : [];
        keys = keys === null ? here : keys.filter((k) => here.includes(k));   // every assignment must agree
      }
      out.identityKeys[fld] = (keys || []).filter((k) => ["id", "sub", "userId", "uid"].includes(k));
    }
    for (const x of delegatedCalls) for (const [k, v] of Object.entries(x.m.identityKeys || {})) out.identityKeys[k] = v;
    for (const m of body.matchAll(/\b\w+\.(\w+)\.find(?:Unique|First)\w*\(/g)) for (const fld of out.fields) if (!out.principalModels[fld] && m[1].toLowerCase().includes(fld.toLowerCase().slice(0, 4))) out.principalModels[fld] = m[1];
    for (const x of delegatedCalls) Object.assign(out.principalModels, x.m.principalModels);
    return out;
  }
  if (verifyCalls.length || delegatedCalls.length) { out.kind = "optional-auth"; return out; }
  // role gate: rejects on a condition over req.<field> role/permission/presence. Administrative only
  // when the required role is literally administrative (the factory arguments or the body say so).
  const roleCond = new RegExp(`\\b${req}\\s*\\??\\.(\\w+)\\??\\.(role|roles|permissions?|isAdmin|is_admin)\\b|!\\s*${req}\\.(admin)\\b`);
  if (roleCond.test(body) && /\.status\(\s*40[13]\s*\)|sendStatus\(\s*40[13]\s*\)|\bthrow\b|next\(\s*new/.test(body)) {
    const m = body.match(roleCond);
    out.fields = [m[1] || m[3]];
    const ADMIN = /^(admin|administrator|staff|super_?admin|superuser|root)$/i;
    const literals = ts.isCallExpression(e) ? e.arguments.map(strip).filter((a) => ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral?.(a)).map((a) => a.text) : [];
    out.kind = literals.length ? (literals.every((l) => ADMIN.test(l)) ? "role" : "role-other")
      : (/isAdmin|is_admin|!\s*\w+\.admin\b|["'](admin|super_?admin|superuser)["']/i.test(body) && !/["'](user|member|customer|patient|professional)["']/i.test(body) ? "role" : "role-other");
    return out;
  }
  // anything else that touches the database, route params or identity and can reject is a check the
  // engine does not model: it blocks VULNERABLE
  if (/prisma|\.params\b|\.(user|professional|admin|auth|session)\b/.test(body) && /\.status\(\s*4\d\d\s*\)|sendStatus\(\s*4\d\d\s*\)|\bthrow\b|next\(\s*\S/.test(body)) out.kind = "checker";
  // a middleware that hands req to project code (or to code it cannot see) may be the check
  else if (calls.some((c) => c.arguments.some((a) => ts.isIdentifier(strip(a)) && strip(a).text === req) && !(ts.isIdentifier(strip(c.expression)) && strip(c.expression).text === nextName))) out.kind = "checker";
  return out;
}

// ---------------- labels (taint) ----------------
// { k: "client", expr, src } | { k: "identity", field } | { k: "obj", props } | { k: "record", model, by }
function unwrapConv(n) {
  let e = strip(n);
  while (e && ts.isCallExpression(e) && ts.isIdentifier(e.expression) && ["Number", "String", "parseInt", "parseFloat", "BigInt"].includes(e.expression.text) && e.arguments.length) e = strip(e.arguments[0]);
  return e;
}

class Flow {
  constructor(project, chain, ctx) {
    this.project = project;
    this.chain = chain;
    this.ctx = ctx; // { identityFields, principalModels, schema, prismaModules }
    this.events = [];  // ordered: sink | gate | unresolved | conditionalGate
    this.seq = 0;
    this.stack = [];   // functions being analyzed, outermost first: { fn, name }
  }
  ev(e) { e.seq = this.seq++; e.trys = [...(this.trys || [])]; e.stack = this.stack.map((x) => x.fn); e.via = this.stack[this.stack.length - 1]?.name || null; this.events.push(e); return e; }

  labelOf(node, env, sf) {
    const e = unwrapConv(node);
    if (!e) return null;
    if (ts.isIdentifier(e)) return env.get(e.text) || null;   // may be { k: "opaque" } after a reassignment
    if (ts.isShorthandPropertyAssignment?.(e)) return env.get(e.name.text) || null;
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const chain = [];
      let cur = e;
      while (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) {
        chain.unshift(ts.isPropertyAccessExpression(cur) ? cur.name.text : (ts.isStringLiteral(cur.argumentExpression) ? cur.argumentExpression.text : "?"));
        cur = strip(cur.expression);
      }
      if (!ts.isIdentifier(cur)) return null;
      const base = env.get(cur.text);
      if (!base) return null;
      return descend(base, chain);
    }
    if (ts.isObjectLiteralExpression(e)) {
      const props = {};
      for (const p of e.properties) {
        if (ts.isShorthandPropertyAssignment(p)) props[p.name.text] = env.get(p.name.text) || null;
        else if (ts.isPropertyAssignment(p) && p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) props[p.name.text] = this.labelOf(p.initializer, env, sf);
      }
      return { k: "obj", props };
    }
    if (ts.isBinaryExpression(e) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken].includes(e.operatorToken.kind)) {
      // `record.owner === identity` kept as a derived ownership comparison (`const isOwner = ...`)
      const rec = recordAccess(this, e.left, env) || recordAccess(this, e.right, env);
      const id = this.labelOf(e.left, env, sf)?.k === "identity" ? this.labelOf(e.left, env, sf) : this.labelOf(e.right, env, sf);
      if (rec && id?.k === "identity") return { k: "ownerCompare", model: rec.model, by: rec.by, field: rec.path.join("."), identity: id.field };
      return checkRefs(this, e, env, sf);
    }
    if (ts.isBinaryExpression(e) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(e.operatorToken.kind)) return checkRefs(this, e, env, sf);
    if (ts.isBinaryExpression(e) && (e.operatorToken.kind === ts.SyntaxKind.BarBarToken || e.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
      const l = this.labelOf(e.left, env, sf), r = this.labelOf(e.right, env, sf);
      if ([l?.k, r?.k].some((k) => k === "check" || k === "ownerCompare")) return checkRefs(this, e, env, sf) || { k: "check", bys: [], identity: true };
      if (l?.k === "identity" && r?.k === "identity" && l.field !== r.field) return { k: "identity-mixed", fields: [l.field, r.field] };
      if (l?.k === "client" || r?.k === "client") return l?.k === "client" ? l : r;
      return l || r;
    }
    return null;
  }
}

// Every record binding and identity an expression touches — used to recognize checks the engine
// cannot prove, so they block a VULNERABLE verdict instead of being ignored.
function checkRefs(flow, node, env, sf) {
  const bys = new Set();
  let identity = false;
  for (const id of findAll(node, (n) => ts.isIdentifier(n))) {
    const l = env.get(id.text);
    if (!l) continue;
    if (l.k === "record" && l.by) bys.add(l.by);
    if ((l.k === "check" || l.k === "ownerCompare") && l.by) bys.add(l.by);
    if (l.k === "check") for (const b of l.bys || []) bys.add(b);
    if (l.k === "principal" || l.k === "identity" || l.k === "req" || (l.k === "check" && l.identity)) identity = true;
  }
  for (const pa of findAll(node, (n) => ts.isPropertyAccessExpression(n))) {
    const l = flow.labelOf(pa, env, sf);
    if (l?.k === "identity") identity = true;
    const rec = recordAccess(flow, pa, env);
    if (rec?.by) bys.add(rec.by);
  }
  if (!bys.size && !identity && !/\brole\b|permission|isAdmin/.test(text(node, sf))) return null;
  return { k: "check", bys: [...bys], identity };
}

function descend(base, chain) {
  let cur = base;
  for (const key of chain) {
    if (!cur) return null;
    if (cur.k === "req") {
      if (["params", "body", "query"].includes(key)) { cur = { k: "reqpart", part: key }; continue; }
      if (cur.identityFields.includes(key)) { cur = { k: "principal", field: key, keys: cur.identityKeys?.[key] ?? ["id"] }; continue; }
      return null;
    }
    if (cur.k === "reqpart") return { k: "client", expr: `req.${cur.part}.${key}`, src: cur.part };
    // `req.user = verifiedPayload` makes sub/userId/uid the identity too
    if (cur.k === "principal") return (cur.keys || ["id"]).includes(key) ? { k: "identity", field: cur.field } : null;
    if (cur.k === "obj") { cur = cur.props[key] ?? null; continue; }
    if (cur.k === "record") return { k: "recordField", model: cur.model, by: cur.by, field: key, binding: cur.binding };
    return null;
  }
  return cur;
}

// ---------------- analysis of one function body ----------------
function prismaClientOf(flow, path, expr, env, thisInfo) {
  // returns true when `expr` is a Prisma client: imported prisma, this.db/this.prisma, tx
  const e = strip(expr);
  if (ts.isIdentifier(e)) {
    const l = env.get(e.text);
    if (l?.k === "prisma") return true;
    const r = flow.project.resolveName(path, e.text);
    return !!(r && r.kind === "var" && r.node.initializer && createsPrismaClient(flow.project, r.path, r.node.initializer));
  }
  if (ts.isPropertyAccessExpression(e) && e.expression.kind === ts.SyntaxKind.ThisKeyword) return !!thisInfo?.prismaFields?.has(e.name.text);
  return false;
}

// `new PrismaClient(...)`, a typed singleton (`globalThis.prisma ?? new PrismaClient()`), or a call to
// a factory in the same file that builds one (`prismaClientSingleton()`), memoized per declaration.
const PRISMA_CACHE = new WeakMap();
function createsPrismaClient(project, path, init, depth = 0) {
  if (PRISMA_CACHE.has(init)) return PRISMA_CACHE.get(init);
  const sf = project.sf(path);
  const t = text(init, sf);
  let result = /\bnew\s+PrismaClient\b/.test(t) || /\.\$extends\(/.test(t) && /prisma/i.test(t);
  const e = strip(init);
  if (!result && depth < 3 && e && ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
    const f = project.resolveName(path, e.expression.text);
    if (f && f.path === path) {
      const body = f.kind === "function" ? f.node : f.kind === "var" ? f.node.initializer : null;
      if (body && /\bPrismaClient\b/.test(text(body, project.sf(f.path)))) result = true;
    }
  }
  if (!result && e && ts.isBinaryExpression(e)) result = createsPrismaClient(project, path, e.left, depth + 1) || createsPrismaClient(project, path, e.right, depth + 1);
  PRISMA_CACHE.set(init, result);
  return result;
}

function classPrismaFields(flow, cls, path) {
  const fields = new Set();
  if (!cls) return fields;
  const sf = flow.project.sf(path);
  for (const m of cls.members) {
    if (ts.isPropertyDeclaration(m) && m.name && ts.isIdentifier(m.name) && m.initializer) {
      const init = strip(m.initializer);
      if (ts.isIdentifier(init) && prismaClientOf(flow, path, init, new Map(), null)) fields.add(m.name.text);
    }
  }
  for (const a of findAll(cls, (n) => ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left) && n.left.expression.kind === ts.SyntaxKind.ThisKeyword)) {
    const parts = text(a.right, sf).split(/\|\||\?\?/).map((s) => s.trim());
    if (parts.some((p) => /^\w+$/.test(p) && prismaClientOf(flow, path, ts.factory.createIdentifier(p), new Map(), null))) fields.add(a.left.name.text);
  }
  return fields;
}

function whereFields(flow, objNode, env, sf, prefix = "") {
  const out = [];
  const o = strip(objNode);
  if (!o || !ts.isObjectLiteralExpression(o)) return null;
  for (const p of o.properties) {
    if (ts.isSpreadAssignment(p)) { out.push({ field: "...", label: { k: "spread" } }); continue; }
    const name = p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : null;
    if (!name) continue;
    const valueNode = ts.isShorthandPropertyAssignment(p) ? p.name : p.initializer;
    const v = strip(valueNode);
    if (v && ts.isObjectLiteralExpression(v) && !["equals"].includes(name)) {
      // compound unique key or operator object ({ in: [...] }, { equals: x }) or relation filter
      const inner = whereFields(flow, v, env, sf, `${prefix}${name}.`) || [];
      for (const x of inner) out.push(x);
      continue;
    }
    out.push({ field: prefix + name, label: flow.labelOf(valueNode, env, sf) });
  }
  return out;
}

function analyzeFunction(flow, path, fn, env, depth, thisInfo, stack, name = null) {
  if (depth > MAX_DEPTH || stack.has(fn)) { flow.ev({ type: "unresolved", why: "depth", pos: fn.pos, path }); return null; }
  stack.add(fn);
  flow.stack.push({ fn, name });
  try { return analyzeFunctionBody(flow, path, fn, env, depth, thisInfo, stack); } finally { flow.stack.pop(); }
}

// Any write to a request identity field — through any alias, element access, short-circuit or
// Object.assign/defineProperty, at any depth — makes the route's identity untrustworthy as a whole.
function scanIdentityRewrites(flow, fn, sf) {
  if (flow.identityRewritten || !flow.identityFields?.length) return;
  const body = text(fn, sf);
  for (const F of flow.identityFields) {
    const f = F.replace(/[^\w]/g, "");
    const pats = [
      new RegExp(`(\\.\\s*${f}|\\[\\s*["'\`]${f}["'\`]\\s*\\])\\s*(\\.\\s*(id|sub|userId|uid)\\s*)?=(?!=)`),
      new RegExp(`\\b${f}\\s*\\.\\s*(id|sub|userId|uid)\\s*=(?!=)`),
      new RegExp(`\\bObject\\.(assign|defineProperty|defineProperties)\\s*\\([^)]*\\b${f}\\b`),
      new RegExp(`\\bReflect\\.set\\s*\\([^)]*["'\`]?${f}`),
    ];
    if (pats.some((re) => re.test(body))) { flow.identityRewritten = `${F} reescrito em ${text(fn.name || fn, sf).slice(0, 40)}`; return; }
  }
}

function analyzeFunctionBody(flow, path, fn, env, depth, thisInfo, stack) {
  const sf = flow.project.sf(path);
  scanIdentityRewrites(flow, fn, sf);
  let returned = null;
  const body = fn.body;
  if (!body) { stack.delete(fn); return null; }
  if (!ts.isBlock(body)) { returned = analyzeExpr(flow, path, body, env, depth, thisInfo, stack, { top: true }); stack.delete(fn); return returned; }
  const visitStatements = (stmts, top) => {
    for (const st of stmts) {
      if (ts.isVariableStatement(st)) {
        for (const d of st.declarationList.declarations) {
          if (!d.initializer) continue;
          const val = analyzeExpr(flow, path, d.initializer, env, depth, thisInfo, stack, { top });
          bindPattern(flow, d.name, val, env, sf, d.initializer);
        }
      } else if (ts.isIfStatement(st)) {
        handleIf(flow, path, st, env, sf, top);
        analyzeExpr(flow, path, st.expression, env, depth, thisInfo, stack, { top: false });
        visitStatements(ts.isBlock(st.thenStatement) ? st.thenStatement.statements : [st.thenStatement], false);
        if (st.elseStatement) visitStatements(ts.isBlock(st.elseStatement) ? st.elseStatement.statements : [st.elseStatement], false);
      } else if (ts.isTryStatement(st)) {
        // a check inside try only protects what follows if the catch does not swallow the rejection
        const lastInCatch = st.catchClause?.block.statements[st.catchClause.block.statements.length - 1];
        // next(e) without return does not stop the handler: only throw/return end the catch
        const catchTerminates = !st.catchClause || (!!lastInCatch && (ts.isThrowStatement(lastInCatch) || ts.isReturnStatement(lastInCatch)));
        // a check inside a swallowing try still protects accesses later in the SAME try (the throw skips
        // them), but not accesses after the try: events remember the swallowing trys around them
        if (!catchTerminates) flow.trys = [...(flow.trys || []), st];
        try { visitStatements(st.tryBlock.statements, top); } finally { if (!catchTerminates) flow.trys = flow.trys.filter((t) => t !== st); }
        if (st.catchClause) visitStatements(st.catchClause.block.statements, false);
        if (st.finallyBlock) visitStatements(st.finallyBlock.statements, false);
      } else if (ts.isReturnStatement(st)) {
        if (st.expression) { const r = analyzeExpr(flow, path, st.expression, env, depth, thisInfo, stack, { top }); if (top && !returned) returned = r; }
      } else if (ts.isExpressionStatement(st)) {
        const ex = strip(st.expression);
        if (ts.isBinaryExpression(ex) && ex.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && ex.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
          analyzeExpr(flow, path, ex.right, env, depth, thisInfo, stack, { top });
          forgetAssigned(ex.left, env);
          continue;
        }
        analyzeExpr(flow, path, st.expression, env, depth, thisInfo, stack, { top });
      } else if (ts.isBlock(st)) {
        visitStatements(st.statements, top);
      } else {
        // loops, switch: everything inside is conditional
        ts.forEachChild(st, (c) => {
          if (ts.isBlock(c)) visitStatements(c.statements, false);
          else if (ts.isExpression(c)) analyzeExpr(flow, path, c, env, depth, thisInfo, stack, { top: false });
          else if (ts.isIfStatement(c) || ts.isExpressionStatement(c) || ts.isReturnStatement(c) || ts.isThrowStatement(c) || ts.isVariableStatement(c) || ts.isTryStatement(c)) visitStatements([c], false);
          else if (ts.isCaseBlock?.(c)) for (const cl of c.clauses) visitStatements(cl.statements, false);
        });
      }
    }
  };
  visitStatements(body.statements, true);
  stack.delete(fn);
  return returned;
}

// After `x = ...` the old label of x no longer holds: x becomes opaque (proves nothing, and a filter
// on an opaque value is never treated as absent). The env is shared across branches, so a
// conditional assignment taints too. Writing req.<identity> itself — or one of its identity keys —
// means the identity is no longer the verified one; `req.user.lastSeen = ...` does not.
function forgetAssigned(left, env, whole = false) {
  const l = strip(left);
  if (ts.isIdentifier(l)) { env.set(l.text, { k: "opaque" }); return; }
  if (ts.isObjectLiteralExpression(l) || ts.isArrayLiteralExpression(l)) {
    for (const id of findAll(l, (n) => ts.isIdentifier(n) && !(n.parent && ts.isPropertyAssignment(n.parent) && n.parent.name === n))) env.set(id.text, { k: "opaque" });
    return;
  }
  const chain = [];
  let cur = l;
  while (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) { chain.unshift(ts.isPropertyAccessExpression(cur) ? cur.name.text : "?"); cur = strip(cur.expression); }
  if (!ts.isIdentifier(cur)) return;
  const base = env.get(cur.text);
  if (base?.k === "req") {
    if (!chain.length) { if (whole) env.set(cur.text, { ...base, identityFields: [] }); return; }
    const field = chain[0];
    const keys = base.identityKeys?.[field] ?? ["id"];
    if (chain.length === 1 || keys.includes(chain[1]) || chain[1] === "?" || whole) env.set(cur.text, { ...base, identityFields: base.identityFields.filter((f) => f !== field) });
  } else if (base) env.set(cur.text, { k: "opaque" });
}

function bindPattern(flow, name, val, env, sf, init) {
  if (ts.isIdentifier(name)) { if (val) env.set(name.text, val); return; }
  if (ts.isObjectBindingPattern(name)) {
    for (const el of name.elements) {
      const key = el.propertyName && (ts.isIdentifier(el.propertyName) || ts.isStringLiteral(el.propertyName)) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : null;
      if (!key) continue;
      const sub = val ? descend(val, [key]) : null;
      if (ts.isIdentifier(el.name)) { if (sub) env.set(el.name.text, sub); }
      else bindPattern(flow, el.name, sub, env, sf, init);
    }
  }
}

// A branch rejects when it stops the request with an error: throw; return res.status(4xx)…/sendStatus;
// return next(err); or `res.status(4xx)…; return;`. next(err) WITHOUT return does not stop execution.
const RESPONSE_4XX = /^(res|response)\s*\.\s*(status\(\s*4\d\d\s*\)|sendStatus\(\s*4\d\d\s*\))/;
function rejectingBranch(stmt, sf) {
  if (!stmt) return false;
  if (ts.isBlock(stmt)) {
    const [a, b] = stmt.statements;
    if (!a) return false;
    if (rejectingBranch(a, sf)) return true;
    return ts.isExpressionStatement(a) && RESPONSE_4XX.test(text(strip(a.expression), sf)) && !!b && ts.isReturnStatement(b);
  }
  if (ts.isThrowStatement(stmt)) return true;
  if (ts.isReturnStatement(stmt) && stmt.expression) {
    const t = text(strip(stmt.expression), sf);
    return RESPONSE_4XX.test(t) || /^next\(\s*\S/.test(t);
  }
  return false;
}
function terminatingBranch(stmt) {
  if (!stmt) return false;
  if (ts.isBlock(stmt)) return stmt.statements.some((x) => terminatingBranch(x));
  return ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt) || (ts.isExpressionStatement(stmt) && ts.isCallExpression(strip(stmt.expression)) && /^next$/.test(text(strip(stmt.expression).expression)));
}

function handleIf(flow, path, st, env, sf, top) {
  // pure existence checks (`!record`, `!userId`, `x == null`, joined by ||) are not authorization
  const existenceOnly = (n) => {
    const x = strip(n);
    if (ts.isPrefixUnaryExpression(x) && x.operator === ts.SyntaxKind.ExclamationToken) {
      const o = strip(x.operand);
      // `!hasAccess` negates a derived check, not a presence test
      if (ts.isIdentifier(o) && (["check", "ownerCompare"].includes(env.get(o.text)?.k) || env.get(o.text)?.identityScoped)) return false;
      return ts.isIdentifier(o) || ts.isPropertyAccessExpression(o);
    }
    if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.BarBarToken) return existenceOnly(x.left) && existenceOnly(x.right);
    if (ts.isBinaryExpression(x) && [ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken].includes(x.operatorToken.kind)) return ["null", "undefined"].includes(text(x.right, sf));
    return false;
  };
  if (!rejectingBranch(st.thenStatement, sf)) {
    // a check that ends the request some other way (404 body, next(err) without return, redirect)
    // is not a proven gate, but it may be the real one: it blocks VULNERABLE
    if (terminatingBranch(st.thenStatement) && !existenceOnly(st.expression)) {
      const refs = checkRefs(flow, st.expression, env, sf);
      if (refs) flow.ev({ type: "otherCheck", bys: refs.bys, identity: refs.identity, pos: st.pos, path, text: text(st.expression, sf).slice(0, 120) });
    }
    return;
  }
  // gate shape: record.field !== identity  (either side; also via relation path a.rel.field)
  let gated = false;
  // strict gate shapes only: `record.field !== identity` as the condition (optionally `!record ||`
  // first), or `!isOwner` where isOwner is a derived `record.field === identity`
  const cond = strip(st.expression);
  const parts = ts.isBinaryExpression(cond) && cond.operatorToken.kind === ts.SyntaxKind.BarBarToken ? [strip(cond.left), strip(cond.right)] : [cond];
  const existence = (p) => ts.isPrefixUnaryExpression(p) && p.operator === ts.SyntaxKind.ExclamationToken && ts.isIdentifier(strip(p.operand)) && env.get(strip(p.operand).text)?.k === "record" && !env.get(strip(p.operand).text).identityScoped;
  const strictParts = parts.filter((p) => !existence(p));
  if (strictParts.length === 1) {
    const p = strictParts[0];
    let hit = null;
    if (ts.isBinaryExpression(p) && [ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(p.operatorToken.kind)) {
      const l = recordAccess(flow, p.left, env), r = flow.labelOf(p.right, env, sf);
      const l2 = recordAccess(flow, p.right, env), r2 = flow.labelOf(p.left, env, sf);
      if (l && r?.k === "identity") hit = { model: l.model, by: l.by, binding: l.binding, field: l.path.join("."), identity: r.field };
      else if (l2 && r2?.k === "identity") hit = { model: l2.model, by: l2.by, binding: l2.binding, field: l2.path.join("."), identity: r2.field };
    } else if (ts.isPrefixUnaryExpression(p) && p.operator === ts.SyntaxKind.ExclamationToken && ts.isIdentifier(strip(p.operand))) {
      const l = env.get(strip(p.operand).text);
      if (l?.k === "ownerCompare") hit = { model: l.model, by: l.by, binding: null, field: l.field, identity: l.identity };
    }
    if (hit) { flow.ev({ type: top ? "gate" : "conditionalGate", ...hit, pos: st.pos, path, text: text(st.expression, sf).slice(0, 120) }); gated = true; }
  }
  if (!gated && !existenceOnly(st.expression)) {
    // anything else that rejects while touching a read record or the identity is a check the engine
    // cannot prove: it blocks VULNERABLE (never ignored), and never supports CONTROLLED
    const refs = checkRefs(flow, st.expression, env, sf);
    if (refs) flow.ev({ type: "otherCheck", bys: refs.bys, identity: refs.identity, pos: st.pos, path, text: text(st.expression, sf).slice(0, 120) });
  }
}

function recordAccess(flow, node, env) {
  let e = strip(node);
  const chain = [];
  while (e && (ts.isPropertyAccessExpression(e))) { chain.unshift(e.name.text); e = strip(e.expression); }
  if (!e || !ts.isIdentifier(e) || !chain.length) return null;
  const base = env.get(e.text);
  if (!base || base.k !== "record") return null;
  return { model: base.model, by: base.by, binding: e.text, path: chain };
}

function analyzeExpr(flow, path, expr, env, depth, thisInfo, stack, opt) {
  const sf = flow.project.sf(path);
  const e = strip(expr);
  if (!e) return null;
  if (ts.isCallExpression(e)) return analyzeCall(flow, path, e, env, depth, thisInfo, stack, opt);
  if (ts.isConditionalExpression(e)) { analyzeExpr(flow, path, e.whenTrue, env, depth, thisInfo, stack, { top: false }); analyzeExpr(flow, path, e.whenFalse, env, depth, thisInfo, stack, { top: false }); return null; }
  if (ts.isArrayLiteralExpression(e)) { for (const x of e.elements) analyzeExpr(flow, path, x, env, depth, thisInfo, stack, opt); return null; }
  if (ts.isBinaryExpression(e)) {
    if ([ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(e.operatorToken.kind)) {
      analyzeExpr(flow, path, e.left, env, depth, thisInfo, stack, opt);
      analyzeExpr(flow, path, e.right, env, depth, thisInfo, stack, { top: false });
    }
    return flow.labelOf(e, env, sf);
  }
  // nested calls inside arguments / objects
  for (const c of findAll(e, (n) => ts.isCallExpression(n) && n !== e)) {
    // only top-level calls of this expression subtree (avoid double counting nested ones)
    if (findAll(e, (n) => ts.isCallExpression(n) && n !== c && findAll(n, (m) => m === c).length && n !== e).length) continue;
    analyzeCall(flow, path, c, env, depth, thisInfo, stack, { top: false });
  }
  return flow.labelOf(e, env, sf);
}

function analyzeCall(flow, path, call, env, depth, thisInfo, stack, opt) {
  const sf = flow.project.sf(path);
  // arguments first (nested calls execute before this one)
  for (const a of call.arguments) {
    const s = strip(a);
    if (s && ts.isCallExpression(s)) analyzeCall(flow, path, s, env, depth, thisInfo, stack, opt);
    else if (s && !isFunctionLike(s) && findAll(s, (n) => ts.isCallExpression(n)).length) analyzeExpr(flow, path, s, env, depth, thisInfo, stack, opt);
  }
  const callee = strip(call.expression);
  // prisma sink: <client>.<model>.<op>(...)   |   <client>.$transaction(cb)   |   raw
  if (ts.isPropertyAccessExpression(callee)) {
    const op = callee.name.text;
    const target = strip(callee.expression);
    if (op === "$transaction" && prismaClientOf(flow, path, target, env, thisInfo)) {
      const cb = call.arguments.map(strip).find(isFunctionLike);
      if (cb) {
        const inner = new Map(env);
        const p = cb.parameters[0];
        if (p && ts.isIdentifier(p.name)) inner.set(p.name.text, { k: "prisma" });
        analyzeFunction(flow, path, cb, inner, depth + 1, thisInfo, stack);
      }
      return null;
    }
    if (RAW_OPS.has(op) && prismaClientOf(flow, path, target, env, thisInfo)) { flow.ev({ type: "sink", raw: true, op, model: null, pos: call.pos, path, top: opt.top }); return null; }
    if (ts.isPropertyAccessExpression(target) && prismaClientOf(flow, path, target.expression, env, thisInfo) && (READ_OPS.has(op) || WRITE_OPS.has(op) || CREATE_OPS.has(op))) {
      const model = target.name.text;
      const arg = call.arguments[0] ? strip(call.arguments[0]) : null;
      let where = null, data = null;
      if (arg && ts.isObjectLiteralExpression(arg)) {
        for (const p of arg.properties) {
          if (!ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p)) continue;
          const nm = p.name && ts.isIdentifier(p.name) ? p.name.text : null;
          const val = ts.isShorthandPropertyAssignment(p) ? p.name : p.initializer;
          if (nm === "where") where = whereFields(flow, val, env, sf);
          if (nm === "data") data = whereFields(flow, val, env, sf);
          if (nm === "create" && op === "upsert") data = whereFields(flow, val, env, sf);
        }
      }
      const sink = flow.ev({ type: "sink", op, model, where, data, pos: call.pos, path, top: opt.top, kind: READ_OPS.has(op) ? "read" : CREATE_OPS.has(op) ? "create" : "write" });
      const by = (where || []).find((w) => w.label?.k === "client");
      // a record read with the identity in its filter (membership/ACL row): `if (!share)` is a check
      return { k: "record", model, by: by ? by.label.expr : null, sink, identityScoped: (where || []).some((w) => w.label?.k === "identity") };
    }
  }
  if (text(callee, sf) === "Object.assign" && call.arguments[0]) forgetAssigned(call.arguments[0], env, true);
  // project function / method
  const target = resolveCallee(flow, path, callee, env, thisInfo);
  const argLabels = call.arguments.map((a) => flow.labelOf(a, env, sf));
  if (!target) {
    // an unknown function handed the request id, the identity, the principal or a read record may be
    // the real check
    const carries = argLabels.some((l) => l && ["client", "identity", "obj", "record", "recordField", "principal", "req", "check", "ownerCompare"].includes(l.k));
    if (carries && !isBenignCallee(text(callee, sf))) flow.ev({ type: "unresolved", why: `call ${text(callee, sf).slice(0, 60)}`, pos: call.pos, path, top: opt.top,
      bys: argLabels.filter((l) => l?.k === "record" || l?.k === "recordField").map((l) => l.by).filter(Boolean),
      identity: argLabels.some((l) => ["identity", "principal", "req"].includes(l?.k)) });
    return null;
  }
  const inner = new Map();
  target.fn.parameters.forEach((p, i) => {
    const l = argLabels[i] || null;
    if (ts.isIdentifier(p.name)) { if (l) inner.set(p.name.text, l); }
    else bindPattern(flow, p.name, l, inner, sf, null);
  });
  const thisNext = target.cls ? { prismaFields: classPrismaFields(flow, target.cls, target.path), cls: target.cls, path: target.path } : thisInfo;
  const before = flow.events.length;
  const r = analyzeFunction(flow, target.path, target.fn, inner, depth + 1, thisNext, stack, text(callee, sf).slice(0, 60));
  // a callee that rewrites the request's identity rewrites it for the caller too
  target.fn.parameters.forEach((p, i) => {
    const argNode = call.arguments[i];
    if (!argNode || !ts.isIdentifier(p.name) || argLabels[i]?.k !== "req") return;
    const tsf = flow.project.sf(target.path);
    for (const a of findAll(target.fn, (n) => ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken)) {
      const lt = text(strip(a.left), tsf);
      if (lt.startsWith(`${p.name.text}.`)) forgetAssigned(ts.factory.createPropertyAccessExpression(argNode, lt.slice(p.name.text.length + 1).split(".")[0]), env, lt.split(".").length === 2 || /\.(id|sub|userId|uid)$/.test(lt));
    }
    if (findAll(target.fn, (n) => ts.isCallExpression(n) && text(n.expression, tsf) === "Object.assign" && text(n.arguments[0], tsf).startsWith(`${p.name.text}`)).length) env.set(argNode.text, { ...argLabels[i], identityFields: [] });
  });
  // events inside a callee inherit "top" only if the call itself is top-level here
  if (!opt.top) for (let i = before; i < flow.events.length; i += 1) flow.events[i].top = false, flow.events[i].type = flow.events[i].type === "gate" ? "conditionalGate" : flow.events[i].type;
  return r;
}

const BENIGN = /^(res|response|console|JSON|Math|Object|Array|Promise|String|Number|Boolean|Date|logger|log|encodeURIComponent|decodeURIComponent)\b|\.(json|send|status|push|map|filter|reduce|includes|join|split|trim|toString|toISOString|log|info|warn|error|debug)$/;
function isBenignCallee(t) { return BENIGN.test(t); }

// A name declared inside an enclosing function (a local helper, a parameter) shadows the top-level one.
function shadowed(node, name) {
  for (let n = node.parent; n && !ts.isSourceFile(n); n = n.parent) {
    if (!isFunctionLike(n)) continue;
    if (n.parameters?.some((p) => ts.isIdentifier(p.name) && p.name.text === name)) return true;
    if (n.parameters?.some((p) => !ts.isIdentifier(p.name) && findAll(p.name, (x) => ts.isIdentifier(x) && x.text === name).length)) return true;
    if (n.body && findAll(n.body, (d) => (ts.isVariableDeclaration(d) && findAll(d.name, (x) => ts.isIdentifier(x) && x.text === name && !(x.parent && ts.isBindingElement(x.parent) && x.parent.propertyName === x)).length) || (ts.isFunctionDeclaration(d) && d.name?.text === name)).length) return true;
  }
  return false;
}

function resolveCallee(flow, path, callee, env, thisInfo) {
  if (ts.isIdentifier(callee)) {
    if (shadowed(callee, callee.text)) return null;
    const r = flow.project.resolveName(path, callee.text);
    if (!r || !r.node) return null;
    return functionOf(flow.project, path, callee);
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const obj = strip(callee.expression);
    if (obj.kind === ts.SyntaxKind.ThisKeyword && thisInfo?.cls) {
      for (const m of thisInfo.cls.members) if (m.name && ts.isIdentifier(m.name) && m.name.text === callee.name.text) {
        if (ts.isMethodDeclaration(m)) return { path: thisInfo.path, fn: m, cls: thisInfo.cls };
        if (ts.isPropertyDeclaration(m) && m.initializer) { const f = functionOf(flow.project, thisInfo.path, m.initializer); return f ? { ...f, cls: thisInfo.cls } : null; }
      }
      return null;
    }
    if (ts.isIdentifier(obj) && shadowed(callee, obj.text)) return null;
    return memberFunction(flow.project, path, callee);
  }
  return null;
}

// ---------------- decisions ----------------
function schemaModel(schema, model) {
  return schema.get(model[0].toUpperCase() + model.slice(1)) || [...schema.values()].find((x) => lowerFirst(x.name) === model) || null;
}

// A field binds a record to a principal only if the schema says so: a foreign key of a relation to
// the principal's model (`Appointment.userId → User`), the principal's own `id`, or a relation path
// ending in such a key (`carePlan.professionalId`, `user.id`).
function ownershipField(schema, model, fieldPath, principalModel) {
  if (!principalModel) return false;
  let m = schemaModel(schema, model);
  if (!m) return false;
  const parts = fieldPath.split(".").filter((x) => x && !["equals", "is"].includes(x));
  for (let i = 0; i < parts.length; i += 1) {
    const last = i === parts.length - 1;
    const f = parts[i];
    if (last) {
      if (m.name === principalModel && f === "id") return true;
      return m.relations.some((r) => r.target === principalModel && r.fks.includes(f));
    }
    const rel = m.relations.find((r) => r.field === f) || null;
    const relTarget = rel?.target || [...schema.values()].find((x) => lowerFirst(x.name) === f)?.name;
    if (!relTarget) return false;
    if (relTarget === principalModel && parts[i + 1] === "id" && i + 1 === parts.length - 1) return true;
    m = schema.get(relTarget);
    if (!m) return false;
  }
  return false;
}

function ownedByPrincipal(schema, model, principalModels) {
  const m = schema.get(model[0].toUpperCase() + model.slice(1)) || [...schema.values()].find((x) => lowerFirst(x.name) === model);
  if (!m) return null;
  return m.relations.filter((r) => principalModels.includes(r.target));
}

function decide(flow, sink, ctx, route) {
  const D = (status, reasonCode, proof, assumptions, unknowns = [], applicable = true) => ({
    applicable,
    decision: Decision({ unit: "sink", method: route.label, path: route.handlerPath, status, reasonCode, proof, assumptions: assumptions.map((a) => ({ id: a.id, text: a.text })), unknowns, sink: { table: sink.model, op: sink.op, pos: sink.pos, file: sink.path } }),
  });
  const baseAsm = [A.EXPRESS_CHAIN_STATIC, ...(route.wrapped ? [A.WRAPPER_PASSES_THROUGH] : [])];
  if (sink.raw) return D(STATUS.NOT_ANALYZED, REASON.NOT_ANALYZED_UNSUPPORTED_SYNTAX, null, [], [`${sink.op}: SQL bruto não é analisado`]);
  const fields = [...(sink.where || []), ...(sink.kind === "create" ? sink.data || [] : [])];
  const clientFields = fields.filter((f) => f.label?.k === "client");
  const principalOf = (field) => route.principalMap[field] || null;
  const identityAll = fields.filter((f) => f.label?.k === "identity");
  const identityFields = identityAll.filter((f) => ownershipField(ctx.schema, sink.model, f.field, principalOf(f.label.field)));
  const mixed = fields.find((f) => f.label?.k === "identity-mixed");
  const sinkInfo = { table: sink.model, op: sink.op, pos: sink.pos };

  // Admin-only route: what protects every access is the role, not ownership — attribution writes
  // (createdByAdminId) and admin-chosen target ids are the intended semantics.
  if (route.adminOnly) {
    const proof = ProofChain({
      mechanism: "role-middleware",
      source: Source("server-identity", `req.${route.adminOnly}`),
      resource: { table: sink.model, idExpr: clientFields.map((f) => f.label.expr).join(",") || "(sem id do cliente)" },
      authorization: Authorization({ kind: "role-gate", expr: route.roleLabel }),
      guard: Guard({ kind: "middleware", pos: -1, rejects: true, text: route.roleLabel }),
      identity: IdentityProof({ verified: { idExpr: `req.${route.adminOnly}` }, sinkBound: { idExpr: "(papel administrativo)" }, same: true, method: "role-middleware", witness: [{ kind: "role-middleware", label: route.roleLabel }] }),
      sink: sinkInfo,
      steps: [{ kind: "role-middleware", middleware: route.roleLabel }],
    });
    return D(STATUS.OOS_PROVEN, REASON.OOS_PROVEN_ROLE_MIDDLEWARE, proof, [...baseAsm, A.ADMIN_ROLE_GRANTS_ACCESS]);
  }
  if (flow.identityRewritten) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_IDENTITY_FROM_CLIENT, null, baseAsm, [`a identidade da requisição é reescrita no caminho (${flow.identityRewritten}) — nenhuma prova de dono vale`]);
  if (mixed) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RESOURCE_IDENTITY, null, baseAsm, [`${mixed.field} recebe a identidade de mais de um tipo de principal (${mixed.label.fields.join(" || ")})`]);
  if (fields.some((f) => f.label?.k === "spread") && identityFields.length) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_OWNER_OVERRIDABLE, null, baseAsm, ["spread junto do dono pode sobrescrever o campo de dono"]);
  const opaqueField = (sink.where || []).find((f) => f.label?.k === "opaque");
  if (opaqueField) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RESOURCE_IDENTITY, null, baseAsm, [`${opaqueField.field} recebe um valor reatribuído no caminho — origem não provada`]);

  // 1. owner bound in the access itself
  if (identityFields.length) {
    if (sink.kind === "create" && clientFields.some((f) => /Id$/.test(f.field))) {
      return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_CROSS_RESOURCE, null, baseAsm, clientFields.filter((f) => /Id$/.test(f.field)).map((f) => `${f.field} = ${f.label.expr}: o registro do principal referencia um recurso escolhido pelo cliente`));
    }
    // the owner filter holds, but data the write stores may point at someone else's resource
    const crossData = (sink.kind === "write" ? sink.data || [] : []).filter((d) => d.label?.k === "client" && (/Id$/.test(d.field) || /(^|\.)(connect|set|connectOrCreate)(\.|$)/.test(d.field)));
    const crossCreate = sink.kind === "create" ? clientFields.filter((d) => /(^|\.)(connect|set|connectOrCreate)(\.|$)/.test(d.field)) : [];
    if (crossData.length || crossCreate.length) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_CROSS_RESOURCE, null, baseAsm, [...crossData, ...crossCreate].map((d) => `${d.field} = ${d.label.expr}: grava referência escolhida pelo cliente`));
    const f = identityFields[0];
    const proof = ProofChain({
      mechanism: "self-scope",
      source: Source("server-identity", `req.${f.label.field}.id`),
      resource: { table: sink.model, idExpr: f.field },
      authorization: Authorization({ kind: "owner-filter", expr: `${f.field} = req.${f.label.field}.id` }),
      guard: Guard({ kind: "sink-filter", pos: sink.pos, rejects: true, text: `${sink.model}.${sink.op} where ${f.field}` }),
      identity: IdentityProof({ verified: { idExpr: `req.${f.label.field}.id` }, sinkBound: { idExpr: f.field }, same: true, method: "sink-binds-owner", witness: [{ kind: "auth-middleware", label: route.authLabel }, { kind: "sink-filter", file: sink.path, pos: sink.pos }] }),
      sink: sinkInfo,
      steps: [{ kind: "auth-middleware", middleware: route.authLabel, field: f.label.field }, { kind: "owner-bound-sink", model: sink.model, op: sink.op, field: f.field }],
    });
    return D(STATUS.CONTROLLED, REASON.CONTROLLED_SELF_SCOPE, proof, [...baseAsm, A.SERVER_IDENTITY, A.OWNER_FIELD_BOUND_TO_IDENTITY]);
  }
  if (identityAll.length && !identityFields.length) {
    return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_RESOURCE_IDENTITY, null, baseAsm, identityAll.map((f) => `${sink.model}.${f.field} recebe a identidade, mas o schema não prova que é chave do ${principalOf(f.label.field) || "principal"}`));
  }
  if (fields.some((f) => f.label?.k === "client" && /^(userId|ownerId|authorId|professionalId|patientId|createdById)$/.test(f.field))) {
    return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_IDENTITY_FROM_CLIENT, null, baseAsm, ["campo de dono recebe valor vindo do cliente"]);
  }
  if (!clientFields.length) return D(STATUS.NOT_ANALYZED, REASON.NOT_ANALYZED_NO_CLIENT_RESOURCE_ID, null, [], [], false);

  const ids = new Set(clientFields.map((f) => f.label.expr));
  if (!route.authFields.length) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_UNAUTHENTICATED_ROUTE, null, baseAsm, [`${route.label}: nenhum middleware de autenticação provado na cadeia — recurso pode ser público`]);

  // 2. dominating gate on the same id (same model, or parent model selected by the same id)
  const before = flow.events.filter((x) => x.seq < sink.seq);
  const after = flow.events.filter((x) => x.seq > sink.seq);
  // a gate inside a swallowing try only protects accesses inside that same try
  const sameTry = (g) => (g.trys || []).every((t) => (sink.trys || []).includes(t));
  const provenGate = (g) => sameTry(g) && ownershipField(ctx.schema, g.model, g.field, principalOf(g.identity));
  const gateFor = (g) => g.by && ids.has(g.by) && provenGate(g) && (g.model === sink.model || fields.some((f) => f.label?.k === "client" && f.label.expr === g.by && f.field.toLowerCase() === `${g.model.toLowerCase()}id`));
  let gate = before.find((g) => g.type === "gate" && gateFor(g));
  // the read sink itself, gated on its binding before anything else uses it
  if (!gate && sink.kind === "read") gate = after.find((g) => g.type === "gate" && provenGate(g) && g.model === sink.model && g.by && ids.has(g.by) && g.seq === after.filter((x) => x.type !== "unresolved")[0]?.seq);
  // a gate is a helper when it ran inside a function that had already returned before the access
  // (its call stack is not a prefix of the access's call stack)
  if (gate) gate.helper = gate.stack.length > sink.stack.length || gate.stack.some((fn, i) => sink.stack[i] !== fn) ? gate.via : null;
  if (gate && sink.top) {
    const mechanism = gate.helper ? "helper-ownership" : "post-read-gate";
    const proof = ProofChain({
      mechanism,
      source: Source(clientFields[0].label.src === "params" ? "route-param" : clientFields[0].label.src === "body" ? "body" : "search-param", clientFields[0].label.expr),
      resource: { table: gate.model, idExpr: gate.by },
      authorization: Authorization({ kind: gate.helper ? "helper-predicate" : "authz-expr", expr: gate.text }),
      guard: Guard({ kind: "if-reject", pos: -1, rejects: true, helper: gate.helper || null, text: gate.text }),
      identity: IdentityProof({ verified: { idExpr: `req.${gate.identity}.id` }, sinkBound: { idExpr: gate.by }, same: true, method: "record-owner-compare", witness: [{ kind: "auth-middleware", label: route.authLabel }, { kind: "gate", file: gate.path, pos: gate.pos, field: gate.field }] }),
      sink: sinkInfo,
      steps: [{ kind: "auth-middleware", middleware: route.authLabel }, { kind: "gate", model: gate.model, field: gate.field, identity: gate.identity, helper: gate.helper || null }, { kind: "sink", model: sink.model, op: sink.op }],
    });
    return D(STATUS.CONTROLLED, gate.helper ? REASON.CONTROLLED_OWNERSHIP_HELPER : REASON.CONTROLLED_POST_READ_GATE, proof, [...baseAsm, A.SERVER_IDENTITY, A.OWNERSHIP_GRANTS_ACCESS]);
  }
  if (!sink.top) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_UNRESOLVED_GATING, null, baseAsm, ["acesso dentro de um ramo condicional — caminho não provado"]);
  // a check that does not dominate — before the access, or on the record a read returns — means the
  // path is not proven either way
  const touches = (g) => (g.by && ids.has(g.by)) || (g.bys || []).some((b) => ids.has(b));
  // for a read, any later rejecting check on identity or a record may be its gate in a shape not
  // proven here — that blocks VULNERABLE (safe direction: it can only lower a verdict)
  const conditional = flow.events.find((g) => ((g.type === "conditionalGate" || g.type === "otherCheck" || (g.type === "gate" && !provenGate(g))) && (g.seq < sink.seq || (sink.kind === "read" && (touches(g) || g.identity || (g.bys || []).length || g.by))))
    // an unknown function that receives the record a read returned may be its check
    || (g.type === "unresolved" && sink.kind === "read" && g.seq > sink.seq && (touches(g) || (g.bys || []).length)));
  if (conditional) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_UNRESOLVED_GATING, null, baseAsm, [`checagem que não domina o acesso: ${conditional.text || conditional.type}`]);
  if (route.blockers.length) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_GUARD_UNRESOLVED, null, baseAsm, route.blockers);
  // a filter the engine cannot read (spread, AND/OR/NOT, an owner key with an unlabeled value) may be
  // the ownership binding
  const opaque = (sink.where || []).find((w) => w.label?.k === "spread" || /(^|\.)(AND|OR|NOT)(\.|$)/.test(w.field) || (w.label?.k !== "client" && route.principalModels.some((pm) => ownershipField(ctx.schema, sink.model, w.field, pm))));
  if (opaque) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_UNRESOLVED_GATING, null, baseAsm, [`filtro ${opaque.field} em forma não provada — pode ser a ligação de dono`]);
  const unresolved = before.find((u) => u.type === "unresolved");
  if (unresolved) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_GUARD_UNRESOLVED, null, baseAsm, [`chamada não resolvida antes do acesso: ${unresolved.why}`]);
  const owned = ownedByPrincipal(ctx.schema, sink.model, route.principalModels);
  if (!owned) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_TRANSITIVE_OWNERSHIP, null, baseAsm, [`schema Prisma não disponível para ${sink.model}`]);
  if (!owned.length) return D(STATUS.INSUFFICIENT, REASON.INSUFFICIENT_TRANSITIVE_OWNERSHIP, null, baseAsm, [`${sink.model} não tem relação direta com ${route.principalModels.join("/") || "o principal"} no schema — posse não provada`]);
  const lateGate = after.find((g) => g.type === "gate" && gateFor(g));
  const proof = ProofChain({
    mechanism: "absence-of-ownership-check",
    source: Source(clientFields[0].label.src === "params" ? "route-param" : clientFields[0].label.src === "body" ? "body" : "search-param", clientFields[0].label.expr),
    resource: { table: sink.model, idExpr: [...ids].join(",") },
    authorization: Authorization({ kind: "authz-expr", expr: null }),
    guard: Guard({ kind: "if-reject", pos: -1, rejects: false, text: "(nenhuma checagem de dono antes do acesso)" }),
    identity: IdentityProof({ verified: { idExpr: route.authFields.map((f) => `req.${f}.id`).join(" | ") }, sinkBound: { idExpr: [...ids].join(",") }, same: false, method: "same-identifier", witness: [] }),
    sink: sinkInfo,
    steps: [
      { kind: "auth-middleware", middleware: route.authLabel, fields: route.authFields },
      { kind: "client-selects-record", ids: [...ids] },
      { kind: "schema-ownership", model: sink.model, relations: owned.map((r) => `${r.field}→${r.target}`) },
      { kind: "absence", checks: ["no-owner-filter", "no-dominating-gate", "no-role-middleware", "no-unresolved-call"] },
      ...(lateGate ? [{ kind: "late-check", note: "existe checagem de dono, mas DEPOIS deste acesso", file: lateGate.path, pos: lateGate.pos }] : []),
      { kind: "sink", model: sink.model, op: sink.op, file: sink.path },
    ],
  });
  return D(STATUS.VULNERABLE, REASON.VULNERABLE_NO_OWNERSHIP_CHECK, proof, [...baseAsm, A.SCHEMA_RELATION_IS_OWNERSHIP, ...(route.principalByName ? [A.PRINCIPAL_MODEL_BY_NAME] : [])]);
}

// ---------------- entry ----------------
export function analyzeExpressProject(files, schemas = {}) {
  const project = new Project(files);
  const schema = parsePrismaSchema(schemas);
  const routers = discoverRouters(project);
  const mwCache = new Map();
  // parents: mounts with their middleware
  for (const r of routers.values()) {
    for (const ev of r.events) {
      if (ev.type !== "use" || !ev.args.length) continue;
      const last = ev.args[ev.args.length - 1];
      const child = routerFor(project, routers, r.path, last);
      if (child) { child.parents.push({ parent: r, prefix: ev.prefix || "", mws: ev.args.slice(0, -1), pos: ev.pos }); ev.mount = child; }
    }
  }
  // inherited chains (middleware expressions with their file). Path-scoped middleware deeper than a
  // mount travels as `scoped` and is matched against the full route path, by whole segments.
  const join = (a, b) => `${a}/${b}`.replace(/\/+/g, "/").replace(/(.)\/$/, "$1");
  // whole segments; a `:param` segment on either side matches any single segment
  // whole segments; a `:param` in the PREFIX matches any segment. A route `:param` facing a literal
  // prefix segment only MAYBE matches: such middleware can add doubt (blockers), never auth or role.
  const segMode = (p, prefix) => {
    const pr = join(prefix || "/", "").split("/").filter(Boolean);
    const pp = join(p || "/", "").split("/").filter(Boolean);
    if (pr.length > pp.length) return "no";
    let mode = "yes";
    for (let i = 0; i < pr.length; i += 1) {
      if (pr[i] === pp[i] || pr[i].startsWith(":")) continue;
      if (pp[i].startsWith(":")) { mode = "maybe"; continue; }
      return "no";
    }
    return mode;
  };
  const segMatch = (p, prefix) => segMode(p, prefix) === "yes";
  const segMaybe = (p, prefix) => segMode(p, prefix) === "maybe";
  const inherited = (r, seen = new Set()) => {
    if (seen.has(r.key)) return [{ prefix: "", mws: [], scoped: [], cyclic: true }];
    seen.add(r.key);
    const params = r.events.some((e) => e.type === "param");
    if (!r.parents.length) return [{ prefix: "", mws: [], scoped: [], root: r.isApp, unmounted: !r.isApp, params }];
    const out = [];
    for (const p of r.parents) {
      for (const up of inherited(p.parent, new Set(seen))) {
        const mountAbs = join(up.prefix, p.prefix || "/");
        const mws = [...up.mws];
        const scoped = [...up.scoped];
        const maybes = [...(up.maybes || [])];
        for (const u of p.parent.events.filter((e) => e.type === "use" && !e.mount && e.pos < p.pos)) {
          const items = u.args.map((a) => ({ expr: a, path: p.parent.path }));
          if (u.prefix === null) { mws.push(...items); continue; }
          const abs = join(up.prefix, u.prefix);
          if (segMatch(mountAbs, abs)) mws.push(...items);
          else if (segMaybe(mountAbs, abs)) maybes.push(...items);
          else if (segMode(abs, mountAbs) !== "no") scoped.push({ abs, items });
        }
        mws.push(...p.mws.map((a) => ({ expr: a, path: p.parent.path })));
        out.push({ prefix: up.prefix + p.prefix, mws, scoped, maybes, unmounted: up.unmounted, cyclic: up.cyclic, params: up.params || params || p.parent.events.some((e) => e.type === "param") });
      }
    }
    return out;
  };
  const results = new Map(); // handlerPath -> handlers[]
  const principalByName = (field) => {
    const cap = field[0].toUpperCase() + field.slice(1);
    return schema.has(cap) ? cap : null;
  };
  for (const r of routers.values()) {
    const chains = inherited(r);
    for (const ev of r.events) {
      if (ev.type !== "route") continue;
      const handlerExpr = ev.args[ev.args.length - 1];
      const routeMws = ev.args.slice(0, -1).map((a) => ({ expr: a, path: r.path }));
      const ownUses = r.events.filter((e) => e.type === "use" && !e.mount && e.pos < ev.pos && (e.prefix === null || segMatch(ev.path || "", e.prefix))).flatMap((u) => u.args.map((a) => ({ expr: a, path: r.path })));
      const ownParams = r.events.some((e) => e.type === "param");
      for (const chain of chains) {
        const fullPath = (chain.prefix + (ev.path ?? "<dinâmico>")).replace(/\/+/g, "/");
        const label = `${ev.verb} ${fullPath}`;
        const scopedHere = chain.scoped.filter((sc) => segMatch(fullPath, sc.abs)).flatMap((sc) => sc.items);
        const maybeHere = [...(chain.maybes || []), ...chain.scoped.filter((sc) => segMaybe(fullPath, sc.abs)).flatMap((sc) => sc.items),
          ...r.events.filter((e) => e.type === "use" && !e.mount && e.pos < ev.pos && e.prefix !== null && segMaybe(ev.path || "", e.prefix)).flatMap((u) => u.args.map((a) => ({ expr: a, path: r.path })))];
        const mws = [...chain.mws, ...scopedHere, ...ownUses, ...routeMws].map((m) => classifyMiddleware(project, m.path, m.expr, mwCache));
        const auths = mws.filter((m) => m.kind === "auth");
        const roles = mws.filter((m) => m.kind === "role");
        const authFields = [...new Set(auths.flatMap((m) => m.fields))];
        const principalModels = [];
        const principalMap = {};
        let byName = false;
        for (const f of authFields) {
          const explicit = auths.map((m) => m.principalModels[f]).find(Boolean);
          const model = explicit ? (schema.has(explicit[0].toUpperCase() + explicit.slice(1)) ? explicit[0].toUpperCase() + explicit.slice(1) : null) : principalByName(f);
          if (!explicit && model) byName = true;
          if (model) { principalModels.push(model); principalMap[f] = model; }
        }
        const roleFields = roles.flatMap((m) => m.fields);
        const adminPrincipal = (f) => /admin|staff|superuser|backoffice/i.test(f) || /admin|staff/i.test(principalModels[authFields.indexOf(f)] || "");
        const adminOnly = authFields.length && (authFields.every((f) => roleFields.includes(f)) || authFields.every(adminPrincipal)) ? (roleFields[0] || authFields[0]) : null;
        let handler = null;
        try { handler = functionOf(project, r.path, handlerExpr); } catch { handler = null; }
        const handlerPath = handler?.path || r.path;
        // things on the chain the engine does not model, each able to hold the real ownership check
        const maybeMws = maybeHere.map((m) => classifyMiddleware(project, m.path, m.expr, mwCache));
        const blockers = [
          ...mws.filter((m) => ["checker", "unresolved", "role-other"].includes(m.kind)).map((m) => `middleware não modelado: ${m.label}`),
          ...maybeMws.filter((m) => m.kind !== "unknown").map((m) => `middleware de prefixo que pode valer para este caminho conforme o valor do parâmetro: ${m.label}`),
          ...(chain.params || ownParams ? ["router.param(...) pode carregar e checar o recurso"] : []),
          ...(handler?.wrapperSuspicious ? [`wrapper ${handler.wrapperName} lê banco/identidade antes do handler`] : []),
        ];
        const route = { label, handlerPath, authFields, principalMap, authLabel: auths.map((m) => m.label).join(", "), principalModels, principalByName: byName, adminOnly, roleLabel: roles.length ? roles.map((m) => m.label).join(", ") : `${auths.map((m) => m.label).join(", ")} (só admite principal administrativo)`, wrapped: !!handler?.wrapped, blockers };
        const entry = { method: label, client: "prisma", sinkDecisions: [], decision: null };
        if (!handler) {
          entry.decision = Decision({ unit: "handler", method: label, path: r.path, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_UNSUPPORTED_SYNTAX, unknowns: ["handler não resolvido estaticamente (despacho dinâmico ou forma não suportada)"] });
        } else if (chain.cyclic) {
          entry.decision = Decision({ unit: "handler", method: label, path: handlerPath, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_DISCOVERY, unknowns: ["montagem cíclica de routers"] });
        } else {
          const flow = new Flow(project, chain, { schema });
          flow.identityFields = authFields;
          const env = new Map();
          const reqName = firstParamName(handler.fn);
          const identityKeys = {};
          for (const m of auths) for (const [k, v] of Object.entries(m.identityKeys || {})) identityKeys[k] = [...new Set([...(identityKeys[k] || []), ...v])];
          if (reqName) env.set(reqName, { k: "req", identityFields: authFields, identityKeys });
          const thisInfo = handler.cls ? { prismaFields: classPrismaFields(flow, handler.cls, handler.path), cls: handler.cls, path: handler.path } : null;
          try { analyzeFunction(flow, handler.path, handler.fn, env, 0, thisInfo, new Set()); }
          catch (e) { flow.events.length = 0; entry.decision = Decision({ unit: "handler", method: label, path: handlerPath, status: STATUS.NOT_ANALYZED, reasonCode: REASON.NOT_ANALYZED_PARSE_ERROR, unknowns: [String(e.message).slice(0, 160)] }); }
          if (!entry.decision) {
            if (process.env.ATLASXIS_EXPRESS_TRACE && label === process.env.ATLASXIS_EXPRESS_TRACE) {
              for (const x of flow.events) process.stderr.write(`trace ${x.seq} ${x.type} ${x.model || ""}.${x.op || ""} by=${x.by || (x.bys || []).join("|")} top=${x.top} via=${x.via} ${x.why || x.text || (x.where ? JSON.stringify(x.where.map((w) => [w.field, w.label?.k, w.label?.expr || w.label?.field])) : "")}\n`);
            }
            const unmountedNote = chain.unmounted ? ["router sem montagem resolvida — middleware herdado desconhecido"] : [];
            const evals = flow.events.filter((x) => x.type === "sink").map((s) => {
              const d = decide(flow, s, { schema }, route);
              if (chain.unmounted && d.decision.status === STATUS.VULNERABLE) return { applicable: true, decision: Decision({ ...d.decision, status: STATUS.INSUFFICIENT, reasonCode: REASON.INSUFFICIENT_CROSS_FILE_EVIDENCE, proof: null, unknowns: unmountedNote }) };
              if (chain.unmounted && d.decision.status === STATUS.INSUFFICIENT && d.decision.reasonCode === REASON.INSUFFICIENT_UNAUTHENTICATED_ROUTE) return { applicable: true, decision: Decision({ ...d.decision, reasonCode: REASON.INSUFFICIENT_CROSS_FILE_EVIDENCE, unknowns: unmountedNote }) };
              return d;
            });
            entry.sinkDecisions = evals.map((x) => x.decision);
            const appl = evals.filter((x) => x.applicable).map((x) => x.decision);
            const pick = (s) => appl.find((d) => d.status === s);
            const agg = pick(STATUS.VULNERABLE) || (appl.length && appl.every((d) => d.status === STATUS.CONTROLLED) ? appl[0] : null) || pick(STATUS.INSUFFICIENT) || pick(STATUS.OOS_PROVEN) || pick(STATUS.NOT_ANALYZED);
            entry.decision = agg ? Decision({ ...agg, unit: "handler" }) : Decision({ unit: "handler", method: label, path: handlerPath, status: STATUS.NOT_ANALYZED, reasonCode: evals.length ? REASON.NOT_ANALYZED_NO_CLIENT_RESOURCE_ID : REASON.NOT_ANALYZED_NO_SINK });
          }
        }
        if (!results.has(handlerPath)) results.set(handlerPath, []);
        results.get(handlerPath).push(entry);
      }
    }
  }
  return [...results.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([path, handlers]) => ({ path, handlers }));
}
