// ORÁCULO CORE — FASE 4: RLS como evidência de primeira classe.
// Parser estrutural de um SUBSET de SQL (PostgreSQL/Supabase) → RLS IR.
// Fail-closed em tudo: expressão não classificada = unproven; ambiguidade =
// nada provado; função só autoriza por CORPO resolvido, nunca por nome.

// ---------- split de statements (respeita $$..$$, strings, comentários) ----------
export function splitStatements(sql) {
  const out = []; let cur = ""; let i = 0;
  let inDollar = null, inLine = false, inBlock = false, inStr = false;
  while (i < sql.length) {
    const rest = sql.slice(i);
    if (inLine) { if (sql[i] === "\n") inLine = false; cur += sql[i++]; continue; }
    if (inBlock) { if (rest.startsWith("*/")) { inBlock = false; cur += "*/"; i += 2; continue; } cur += sql[i++]; continue; }
    if (inStr) { if (sql[i] === "'" && sql[i + 1] === "'") { cur += "''"; i += 2; continue; } if (sql[i] === "'") inStr = false; cur += sql[i++]; continue; }
    if (inDollar) { if (rest.startsWith(inDollar)) { cur += inDollar; i += inDollar.length; inDollar = null; continue; } cur += sql[i++]; continue; }
    const dm = rest.match(/^\$[a-zA-Z_]*\$/);
    if (dm) { inDollar = dm[0]; cur += dm[0]; i += dm[0].length; continue; }
    if (rest.startsWith("--")) { inLine = true; cur += "--"; i += 2; continue; }
    if (rest.startsWith("/*")) { inBlock = true; cur += "/*"; i += 2; continue; }
    if (sql[i] === "'") { inStr = true; cur += sql[i++]; continue; }
    if (sql[i] === ";") { out.push(cur.trim()); cur = ""; i++; continue; }
    cur += sql[i++];
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const stripComments = (s) => s.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");
const normName = (s) => s.replace(/^[\w]+\./, "").replace(/"/g, "").toLowerCase().trim();

function balanced(text, openIdx) {
  // text[openIdx] === "(" → retorna conteúdo interno e índice final
  let depth = 0, inStr = false;
  for (let i = openIdx; i < text.length; i++) {
    const ch = text[i];
    if (inStr) { if (ch === "'" && text[i + 1] === "'") { i++; continue; } if (ch === "'") inStr = false; continue; }
    if (ch === "'") { inStr = true; continue; }
    if (ch === "(") depth++;
    if (ch === ")") { depth--; if (depth === 0) return { inner: text.slice(openIdx + 1, i), end: i }; }
  }
  return null;
}

function splitTopLevel(s, sepRegex) {
  const parts = []; let depth = 0, inStr = false, cur = "", i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (inStr) { cur += ch; if (ch === "'" && s[i + 1] !== "'") inStr = false; else if (ch === "'") { cur += s[++i]; } i++; continue; }
    if (ch === "'") { inStr = true; cur += ch; i++; continue; }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (depth === 0) {
      const m = s.slice(i).match(sepRegex);
      if (m && m.index === 0) { parts.push(cur); cur = ""; i += m[0].length; continue; }
    }
    cur += ch; i++;
  }
  parts.push(cur);
  return parts;
}

// ---------- classificação de expressão de policy ----------
// {kind:"authz", owners:[col], adminFns:[fn]} | {kind:"unproven", why}
export function classifyPolicyExpr(raw, functions) {
  if (raw == null) return { kind: "unproven", why: "sem expressão" };
  let e = stripComments(raw)
    .replace(/\(\s*select\s+auth\.uid\(\)\s*\)/gi, "auth.uid()")
    .replace(/::[a-z_]+(\[\])?/gi, "")
    .trim();
  // desembrulha parênteses em torno de operandos atômicos: (user_id) / (auth.uid())
  for (let prev = null; prev !== e;) {
    prev = e;
    e = e.replace(/\(\s*((?:\w+\.)?"?\w+"?)\s*\)/g, "$1").replace(/\(\s*(auth\.uid\(\))\s*\)/gi, "$1");
  }
  const stripOuter = (t) => {
    t = t.trim();
    while (t.startsWith("(")) { const b = balanced(t, 0); if (b && b.end === t.length - 1) t = b.inner.trim(); else break; }
    return t;
  };
  e = stripOuter(e);
  const disjuncts = splitTopLevel(e, /^\s+or\s+/i).map(stripOuter).filter(Boolean);
  const owners = [], adminFns = [];
  for (const d of disjuncts) {
    const own = d.match(/^(?:(?:\w+\.)?"?(\w+)"?\s*=\s*auth\.uid\(\)|auth\.uid\(\)\s*=\s*(?:\w+\.)?"?(\w+)"?)$/i);
    if (own) { owners.push((own[1] || own[2]).toLowerCase()); continue; }
    const call = d.match(/^(?:\w+\.)?(\w+)\s*\(\s*\)$/);
    if (call && functions[call[1].toLowerCase()]?.adminPredicate) { adminFns.push(call[1].toLowerCase()); continue; }
    return { kind: "unproven", why: `disjunto não classificado: ${d.slice(0, 60)}` };
  }
  if (!owners.length && !adminFns.length) return { kind: "unproven", why: "vazia" };
  return { kind: "authz", owners, adminFns };
}

// ---------- parser do corpus ----------
export function parseSqlCorpus(sqlFiles) {
  const model = { tables: {}, functions: {}, ambiguousTables: new Set(), stats: { files: 0, statements: 0, policies: 0 } };
  const T = (name) => (model.tables[name] ??= { name, columns: [], rlsEnabled: false, forced: false, policies: [], fks: [] });
  const paths = Object.keys(sqlFiles).sort(); // ordem determinística
  for (const path of paths) {
    model.stats.files++;
    for (const rawStmt of splitStatements(sqlFiles[path])) handle(rawStmt, path);
  }

  function handle(rawStmt, path) {
    for (let _once = 0; _once < 1; _once++) { // preserva os `continue` do corpo
      model.stats.statements++;
      const stmt = stripComments(rawStmt).replace(/\s+/g, " ").trim();
      const low = stmt.toLowerCase();

      // DO $$ ... $$: processa SOMENTE segmentos guardados pelo padrão de
      // idempotência `if not exists (select ... from pg_policies ...) then ...`.
      // Qualquer outra condição dentro do DO é ignorada (fail-closed: nunca
      // fabricamos evidência a partir de lógica condicional não compreendida).
      if (/^do\s/.test(low)) {
        const body = rawStmt.match(/\$[a-zA-Z_]*\$([\s\S]*?)\$[a-zA-Z_]*\$/)?.[1] || "";
        const guarded = [...body.matchAll(/if\s+not\s+exists\s*\([^)]*pg_policies[\s\S]*?\)\s*then([\s\S]*?)end\s+if/gi)];
        for (const g of guarded) for (const inner of splitStatements(g[1])) handle(inner, path);
        return;
      }

      // CREATE TABLE
      let m = stmt.match(/^create\s+table\s+(?:if\s+not\s+exists\s+)?((?:\w+\.)?"?\w+"?)\s*\(/i);
      if (m) {
        const t = T(normName(m[1]));
        const b = balanced(stmt, stmt.indexOf("(", m[0].length - 1));
        if (b) {
          for (const item0 of splitTopLevel(b.inner, /^,/)) {
            const item = item0.trim();
            const first = item.match(/^"?([a-zA-Z_][\w]*)"?/)?.[1]?.toLowerCase();
            if (!first || ["primary", "unique", "constraint", "foreign", "check", "exclude"].includes(first)) {
              const fk = item.match(/foreign\s+key\s*\(\s*"?(\w+)"?\s*\)\s*references\s+((?:\w+\.)?"?\w+"?)\s*(?:\(\s*"?(\w+)"?\s*\))?/i);
              if (fk) t.fks.push({ column: fk[1].toLowerCase(), refTable: normName(fk[2]), refColumn: (fk[3] || "id").toLowerCase() });
              continue;
            }
            t.columns.push(first);
            const ref = item.match(/references\s+((?:\w+\.)?"?\w+"?)\s*(?:\(\s*"?(\w+)"?\s*\))?/i);
            if (ref) t.fks.push({ column: first, refTable: normName(ref[1]), refColumn: (ref[2] || "id").toLowerCase() });
          }
        }
        continue;
      }

      // ALTER TABLE ... ROW LEVEL SECURITY
      m = low.match(/^alter\s+table\s+(?:only\s+)?((?:\w+\.)?"?[\w]+"?)\s+(enable|disable|force|no\s+force)\s+row\s+level\s+security/);
      if (m) {
        const t = T(normName(m[1]));
        if (m[2] === "enable") t.rlsEnabled = true;
        if (m[2] === "disable") t.rlsEnabled = false;
        if (m[2] === "force") t.forced = true;
        continue;
      }

      // DROP POLICY
      m = stmt.match(/^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[\w\-]+)\s+on\s+((?:\w+\.)?"?\w+"?)/i);
      if (m) {
        const t = T(normName(m[2]));
        const pname = m[1].replace(/"/g, "").toLowerCase();
        t.policies = t.policies.filter((p) => p.name !== pname);
        continue;
      }

      // CREATE POLICY
      m = stmt.match(/^create\s+policy\s+("[^"]+"|[\w\-]+)\s+on\s+((?:\w+\.)?"?\w+"?)([\s\S]*)$/i);
      if (m) {
        model.stats.policies++;
        const tbl = normName(m[2]);
        const t = T(tbl);
        const pname = m[1].replace(/"/g, "").toLowerCase();
        const rest = m[3];
        const restLow = rest.toLowerCase();
        const permissive = !/\bas\s+restrictive\b/.test(restLow);
        const cmd = restLow.match(/\bfor\s+(all|select|insert|update|delete)\b/)?.[1] || "all";
        let roles = [];
        const toM = restLow.match(/\bto\s+([\w ,"]+?)(?=\s+using\b|\s+with\s+check\b|$)/);
        if (toM) roles = toM[1].split(",").map((r) => r.replace(/"/g, "").trim()).filter(Boolean);
        const grab = (kw) => {
          const idx = restLow.search(kw);
          if (idx < 0) return null;
          const open = rest.indexOf("(", idx);
          if (open < 0) return null;
          const b = balanced(rest, open);
          return b ? b.inner.trim() : null;
        };
        const usingRaw = grab(/\busing\s*\(/);
        const checkRaw = grab(/\bwith\s+check\s*\(/);
        const pol = { name: pname, table: tbl, cmd, permissive, roles, usingRaw, checkRaw, sourceFile: path };
        const dup = t.policies.find((p) => p.name === pname);
        if (dup) {
          const same = dup.usingRaw === usingRaw && dup.checkRaw === checkRaw && dup.cmd === cmd && dup.permissive === permissive;
          if (!same) model.ambiguousTables.add(tbl); // recriação conflitante sem DROP
        } else t.policies.push(pol);
        continue;
      }

      // CREATE FUNCTION (para admin-predicate)
      m = stmt.match(/^create\s+(?:or\s+replace\s+)?function\s+((?:\w+\.)?\w+)\s*\(\s*\)/i);
      if (m) {
        const fname = normName(m[1]);
        const body = rawStmt.match(/\$[a-zA-Z_]*\$([\s\S]*?)\$[a-zA-Z_]*\$/)?.[1] || "";
        const bl = stripComments(body).replace(/\s+/g, " ").toLowerCase();
        // admin-predicate estrutural: exists(select 1 from T where <col>=auth.uid() and role='V')
        const adminPredicate =
          /select\s+exists\s*\(\s*select\s+1\s+from\s+(?:\w+\.)?\w+\s+where\s+/.test(bl) &&
          /\b\w+\s*=\s*auth\.uid\(\)/.test(bl) &&
          /\brole\s*=\s*'[^']+'/.test(bl);
        model.functions[fname] = { body: bl.slice(0, 400), adminPredicate };
        continue;
      }
    }
  }
  // classifica todas as policies (após todas as funções conhecidas)
  for (const t of Object.values(model.tables))
    for (const p of t.policies) {
      p.usingClass = classifyPolicyExpr(p.usingRaw, model.functions);
      p.checkClass = classifyPolicyExpr(p.checkRaw, model.functions);
    }
  return model;
}

// ---------- avaliação de acesso ----------
// op ∈ select|update|delete (insert/upsert são excluídos no engine — fail-closed)
export function evaluateAccess(model, table, op) {
  const t = model.tables[table];
  if (!t) return { unknownTable: true };
  if (model.ambiguousTables.has(table)) return { ambiguous: true };
  if (!t.rlsEnabled) return { disabled: true };
  const coversRole = (p) => !p.roles.length || p.roles.includes("authenticated") || p.roles.includes("public");
  const coversCmd = (p) => p.cmd === "all" || p.cmd === op;
  const applicable = t.policies.filter((p) => coversRole(p) && coversCmd(p));
  // expressão relevante: UPDATE usa USING (WITH CHECK ausente herda USING no PG);
  // SELECT/DELETE usam USING. Para UPDATE, um WITH CHECK PRESENTE e não provado
  // derruba a prova (fail-closed: a policy poderia permitir reatribuição fora
  // do modelo suportado).
  const relevant = (p) => p.usingClass && p.usingRaw != null ? p.usingClass : { kind: "unproven", why: "sem USING" };
  const perm = applicable.filter((p) => p.permissive);
  const restr = applicable.filter((p) => !p.permissive);
  if (!perm.length) return { provable: false, noPolicy: true, applicable };
  const ok = (p) => relevant(p).kind === "authz" &&
    !(op === "update" && p.checkRaw != null && p.checkClass?.kind !== "authz");
  const provable = perm.every(ok) || restr.some(ok);
  const used = perm.every(ok) ? perm : restr.filter(ok);
  return {
    provable, applicable,
    policies: used.map((p) => ({ name: p.name, cmd: p.cmd, permissive: p.permissive, class: relevant(p), file: p.sourceFile, using: (p.usingRaw || "").slice(0, 120) })),
    disabled: false,
  };
}

// ---------- normalização da entrada de evidência do engine ----------
// aceita: dict legado {tabela:"owner"|"complex"}  OU  {model, declared, options}
export function normalizeRlsInput(rls) {
  if (!rls) return { declared: {}, model: null, options: {} };
  if (rls.model || rls.declared || rls.options)
    return { declared: rls.declared || {}, model: rls.model || null, options: rls.options || {} };
  return { declared: rls, model: null, options: {} };
}
