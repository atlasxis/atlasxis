#!/usr/bin/env node
// Atlasxis — CLI de produto.
//
// Comandos:
//   atlasxis scan <path> [--format json|markdown|sarif] [--rls <dir>] [--ci]
//   atlasxis report <path> [--rls <dir>] [--out <file>]
//   atlasxis rls <path> [--rls <dir> | --schema-dump <arquivo.sql>] [--assume-default-grants] [--format ...] [--ci]
//   atlasxis explain <REASON_CODE>
//   atlasxis baseline <path>
//   atlasxis diff <baseline.json> <path>
//   atlasxis version
//
// Exit codes (estáveis, documentados em docs/CLI-SPEC.md):
//   0 sucesso
//   1 uso incorreto / erro interno
//   2 política de CI violada (--ci: ao menos um VULNERABLE)
//   3 caminho inexistente ou não-diretório
//   4 limite operacional excedido (timeout, arquivos, bytes)
//
// Garantias operacionais (FASE E):
//   - nunca executa código do projeto analisado (análise 100% estática);
//   - nunca roda lifecycle scripts do alvo (não há npm install do alvo);
//   - nunca carrega .env do alvo como configuração do Atlasxis;
//   - symlinks NÃO são seguidos (lstat) — sem escape do root nem loops;
//   - limites: arquivos, bytes por arquivo, bytes totais, profundidade, tempo;
//   - saída sanitizada: strings com formato de segredo são redigidas.

import { readFileSync, readdirSync, lstatSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeFileIR } from "./engine.mjs";
import { isServerActionFile } from "./extract.mjs";
import { parseSqlCorpus } from "./rls.mjs";
import { buildReport, toJSON, toMarkdown, toSARIF } from "./report.mjs";
import { EXPLANATIONS } from "./explanations.mjs";
import { auditTables } from "./rls-audit.mjs";
import { rlsToJSON, rlsToMarkdown, rlsToSARIF } from "./rls-report.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));

// ---------------- limites operacionais ----------------
const LIMITS = {
  maxFiles: 20000,          // arquivos candidatos lidos
  maxFileBytes: 2 * 1024 * 1024,   // por arquivo (maiores são ignorados como NOT_ANALYZED implícito)
  maxTotalBytes: 256 * 1024 * 1024, // projeto inteiro
  maxDepth: 12,
  timeoutMs: 120000,
};

class LimitError extends Error { constructor(msg) { super(msg); this.name = "LimitError"; } }

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", ".claude", "worktrees", ".turbo", "coverage", ".vercel", ".cache", "out"]);

// walk endurecido: lstat (não segue symlink), limites de arquivos/bytes/profundidade
function walk(dir, test, state, out = [], depth = 0) {
  if (depth > LIMITS.maxDepth) return out;
  let ents;
  try { ents = readdirSync(dir); } catch { return out; }
  for (const e of ents.sort()) {
    if (SKIP_DIRS.has(e)) continue;
    const p = join(dir, e);
    let st; try { st = lstatSync(p); } catch { continue; }
    if (st.isSymbolicLink()) { state.symlinksSkipped++; continue; }
    if (st.isDirectory()) walk(p, test, state, out, depth + 1);
    else if (st.isFile() && test(p)) {
      if (st.size > LIMITS.maxFileBytes) { state.oversizedSkipped++; continue; }
      state.files++; state.bytes += st.size;
      if (state.files > LIMITS.maxFiles) throw new LimitError(`limite de arquivos excedido (${LIMITS.maxFiles})`);
      if (state.bytes > LIMITS.maxTotalBytes) throw new LimitError(`limite de bytes do projeto excedido (${LIMITS.maxTotalBytes})`);
      out.push(p);
    }
  }
  return out;
}

function newWalkState() { return { files: 0, bytes: 0, symlinksSkipped: 0, oversizedSkipped: 0 }; }

function loadProject(root, state) {
  const tsFiles = walk(root, (p) => /\.(ts|tsx)$/.test(p) && !/\.d\.ts$/.test(p), state);
  const files = {};
  for (const p of tsFiles) {
    const rel = relative(root, p);
    if (rel.startsWith("..")) continue; // contenção: nada fora do root
    try { files[rel] = readFileSync(p, "utf8"); } catch {}
  }
  const routes = Object.keys(files).filter((p) => /(^|\/)app\/api\/.*route\.(ts|tsx)$/.test(p) || /(^|\/)src\/app\/api\/.*route\.(ts|tsx)$/.test(p) || /(^|\/)pages\/api\/.*\.(ts|tsx)$/.test(p));
  // server actions: arquivos cuja primeira instrução é "use server"
  const routeSet = new Set(routes);
  const actions = Object.keys(files).filter((p) => !routeSet.has(p) && isServerActionFile(files[p]));
  return { files, routes, actions };
}

function loadRls(root, rlsDir, state) {
  const dirs = rlsDir ? [resolve(rlsDir)] : [join(root, "supabase"), join(root, "supabase", "migrations"), join(root, "migrations"), join(root, "db")];
  const sql = {};
  for (const d of dirs) {
    if (!existsSync(d)) continue;
    for (const p of walk(d, (x) => x.endsWith(".sql"), state)) { try { sql[relative(root, p) || p] = readFileSync(p, "utf8"); } catch {} }
  }
  return Object.keys(sql).length ? { model: parseSqlCorpus(sql), declared: {}, options: {} } : {};
}

function analyzeProject(root, opts) {
  const state = newWalkState();
  const deadline = Date.now() + (opts.timeoutMs || LIMITS.timeoutMs);
  const { files, routes, actions } = loadProject(root, state);
  const rls = loadRls(root, opts.rls, state);
  const out = [];
  // server actions: certificadas (validação externa em 7 repositórios reais).
  // Ligadas por padrão; --no-server-actions desliga.
  const actionUnits = opts.serverActions !== false ? actions.sort().map((p) => [p, { kind: "action" }]) : [];
  const units = [...routes.sort().map((p) => [p, {}]), ...actionUnits];
  for (const [rp, mode] of units) {
    if (Date.now() > deadline) throw new LimitError(`timeout de análise excedido (${opts.timeoutMs || LIMITS.timeoutMs}ms) após ${out.length}/${units.length} arquivos`);
    let handlers;
    try { handlers = analyzeFileIR(files, rp, rls, mode); }
    catch (e) { handlers = [{ method: "?", client: "unknown", sinkDecisions: [], decision: { status: "NOT_ANALYZED", reasonCode: "NOT_ANALYZED_PARSE_ERROR", assumptions: [], unknowns: [String(e.message).slice(0, 100)] } }]; }
    out.push({ path: rp, handlers });
  }
  return { files, routes, actions: opts.serverActions !== false ? actions : [], actionsFound: actions.length, rls, analyzed: out, state };
}

// ---------------- sanitização de saída ----------------
// Nunca reproduzir material com formato de segredo vindo do projeto analisado.
const SECRET_PATTERNS = [
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, // JWT
  /\b(sk|pk|rk)[-_](live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b/g,      // chaves estilo stripe/openai
  /\bAKIA[0-9A-Z]{16}\b/g,                                          // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,                                // github tokens
  /(["'`])(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^"'`\s]{8,}\1/g, // connection strings
];
function sanitize(text) {
  let t = text;
  for (const re of SECRET_PATTERNS) t = t.replace(re, "[REDACTED-SECRET]");
  return t;
}
function emit(text) { process.stdout.write(sanitize(text)); }

function resolveRoot(p) {
  const root = resolve(p || ".");
  if (!existsSync(root)) { process.stderr.write(`erro: caminho inexistente: ${root}\n`); process.exit(3); }
  let st; try { st = statSync(root); } catch { process.stderr.write(`erro: caminho ilegível: ${root}\n`); process.exit(3); }
  if (!st.isDirectory()) { process.stderr.write(`erro: não é um diretório: ${root}\n`); process.exit(3); }
  return root;
}

function lineOf(content, pos) {
  if (content == null || pos == null || pos < 0) return null;
  let line = 1;
  for (let i = 0; i < pos && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

// ---------------- comandos ----------------
function cmdScan(rootArg, opts) {
  const root = resolveRoot(rootArg);
  const { analyzed, routes, actions, actionsFound, rls, state } = analyzeProject(root, opts);
  const report = buildReport(analyzed);
  report.meta = {
    engine: `atlasxis ${PKG.version}`, root: relative(process.cwd(), root) || ".",
    routes: routes.length, serverActionFiles: actions.length, rlsModel: !!rls.model,
    ...(actionsFound && opts.serverActions === false ? { serverActionsSkipped: `${actionsFound} arquivo(s) "use server" encontrados e NÃO analisados (--no-server-actions)` } : {}),
    filesRead: state.files, symlinksSkipped: state.symlinksSkipped, oversizedSkipped: state.oversizedSkipped,
  };
  if (routes.length === 0 && actions.length === 0) report.meta.note = "0 rotas e 0 arquivos de server actions descobertos — nenhum handler no escopo de descoberta (app/api/**/route.ts[x], src/app/api/**, pages/api/**, arquivos \"use server\")";
  const fmt = opts.ci ? "json" : (opts.format || "markdown");
  emit(fmt === "json" ? toJSON(report) : fmt === "sarif" ? toSARIF(report) : toMarkdown(report));
  emit("\n");
  if (opts.ci) {
    const s = report.summary;
    const vuln = s.VULNERABLE || 0, insuf = (s.INSUFFICIENT_EVIDENCE || 0) + (s.OUT_OF_SCOPE_UNVERIFIED || 0), na = s.NOT_ANALYZED || 0;
    process.stderr.write(`atlasxis --ci: VULNERABLE=${vuln} INSUFFICIENT/UNVERIFIED=${insuf} NOT_ANALYZED=${na} — INSUFFICIENT e NOT_ANALYZED NÃO significam seguro\n`);
    if (vuln > 0) process.exitCode = 2;
    if (opts.failOn === "insufficient" && (vuln > 0 || insuf > 0)) process.exitCode = 2;
  }
  return report;
}

function cmdReport(rootArg, opts) {
  const root = resolveRoot(rootArg);
  const { files, analyzed, routes, actions, actionsFound, rls, state } = analyzeProject(root, opts);
  const L = [];
  L.push("# Atlasxis — Proof Report por sink", "");
  L.push(`Engine: atlasxis ${PKG.version} — análise estática; nenhum código do projeto foi executado.`, "");
  L.push("> Este relatório afirma somente: (a) caminhos com evidência suficiente de autorização; (b) caminhos com evidência suficiente de vulnerabilidade; (c) o que não foi possível provar. Ele NUNCA afirma \"o sistema está seguro\".", "");
  L.push(`Rotas descobertas: ${routes.length} · arquivos de server actions: ${actions.length} · arquivos lidos: ${state.files} · symlinks ignorados: ${state.symlinksSkipped} · RLS corpus: ${rls.model ? "sim" : "não"}`, "");
  if (actionsFound && opts.serverActions === false) L.push(`> ${actionsFound} arquivo(s) "use server" encontrados e NÃO analisados (--no-server-actions). Não analisado NÃO significa seguro.`, "");
  const order = ["VULNERABLE", "CONTROLLED", "INSUFFICIENT_EVIDENCE", "OUT_OF_SCOPE_UNVERIFIED", "OUT_OF_SCOPE_PROVEN", "NOT_ANALYZED"];
  const buckets = Object.fromEntries(order.map((k) => [k, []]));
  for (const f of analyzed) for (const h of f.handlers) {
    const units = h.sinkDecisions.length ? h.sinkDecisions : [h.decision];
    for (const d of units) {
      const pos = d.sink?.pos ?? d.proof?.sink?.pos ?? null;
      (buckets[d.status] || (buckets[d.status] = [])).push({ file: f.path, method: h.method, client: h.client, d, line: lineOf(files[f.path], pos) });
    }
  }
  for (const status of order) {
    const items = buckets[status];
    if (!items || !items.length) continue;
    L.push(`## ${status} (${items.length})`, "");
    items.sort((a, b) => a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
    for (const { file, method, client, d, line } of items) {
      const sink = d.sink ?? d.proof?.sink ?? {};
      L.push(`### \`${method} ${file}${line ? `:${line}` : ""}\``, "");
      L.push(`- **Arquivo**: ${file}${line ? ` (linha ${line})` : ""}`);
      if (sink.table) L.push(`- **Sink**: ${sink.op ?? "?"} \`${sink.table}\` (cliente: ${client})`);
      L.push(`- **Reason code**: \`${d.reasonCode}\``);
      const ex = EXPLANATIONS[d.reasonCode];
      if (ex) L.push(`- **Significado**: ${ex.meaning}`);
      const p = d.proof;
      if (p) {
        L.push("- **ProofChain**:");
        L.push("  ```");
        L.push(`  MECHANISM     ${p.mechanism ?? "-"}`);
        L.push(`  SOURCE        ${p.source?.expr ?? p.source?.kind ?? "-"}`);
        L.push(`  RESOURCE      ${p.resource?.table ?? "-"} id=${p.resource?.idExpr ?? "-"}`);
        L.push(`  AUTHORIZATION ${p.authorization?.kind ?? "-"}`);
        L.push(`  GUARD         ${p.guard?.kind ?? "-"}${p.guard?.text ? ` — ${String(p.guard.text).slice(0, 80)}` : ""}`);
        L.push(`  IDENTITY      same=${p.identity?.same ?? "-"} method=${p.identity?.method ?? "-"} witnesses=${(p.identity?.witness || []).length}`);
        L.push(`  SINK          ${p.sink ? `${p.sink.op} ${p.sink.table}` : "-"}`);
        for (const s of p.steps || []) L.push(`  STEP          ${s.kind}${s.detail ? ` — ${String(s.detail).slice(0, 80)}` : ""}`);
        L.push("  ```");
      }
      if (status === "VULNERABLE") {
        L.push("- **Evidência positiva**: entrada controlável alcança o sink sem gating vivo; ver ProofChain acima (fonte→recurso→sink e ausência de guard).");
      }
      if (status === "INSUFFICIENT_EVIDENCE" && ex) {
        L.push(`- **O que faltou provar**: ${ex.not_proven}`);
      }
      if ((d.assumptions || []).length) L.push(`- **Assumptions**: ${(d.assumptions || []).map((a) => a.id ?? a).join(", ")}`);
      if ((d.unknowns || []).length) L.push(`- **Não provado**: ${(d.unknowns || []).join("; ")}`);
      L.push("");
    }
  }
  if (!Object.values(buckets).some((b) => b && b.length)) L.push("_Nenhum sink descoberto._", "");
  const text = sanitize(L.join("\n") + "\n");
  if (opts.out) { writeFileSync(opts.out, text); process.stdout.write(`relatório escrito em ${opts.out}\n`); }
  else process.stdout.write(text);
}

function cmdExplain(code) {
  if (!code) {
    emit("uso: atlasxis explain <REASON_CODE>\n\ncódigos disponíveis:\n");
    for (const k of Object.keys(EXPLANATIONS).sort()) emit(`  ${k}\n`);
    process.exitCode = 1; return;
  }
  const ex = EXPLANATIONS[code];
  if (!ex) {
    emit(`código desconhecido: ${code}\n\ncódigos disponíveis:\n`);
    for (const k of Object.keys(EXPLANATIONS).sort()) emit(`  ${k}\n`);
    process.exitCode = 1; return;
  }
  emit(`${code}\n  status:    ${ex.status}\n  significa: ${ex.meaning}\n  provado:   ${ex.proven}\n  não prova: ${ex.not_proven}\n`);
}

function cmdBaseline(rootArg, opts) {
  const root = resolveRoot(rootArg);
  const { analyzed } = analyzeProject(root, opts);
  const report = buildReport(analyzed);
  const base = report.findings.map((f) => ({ path: f.path, method: f.method, resource: f.resource, operation: f.operation, decision: f.decision, reasonCode: f.reasonCode }));
  writeFileSync(join(root, ".atlasxis-baseline.json"), JSON.stringify(base, null, 2));
  process.stdout.write(`baseline escrito: ${base.length} sinks em .atlasxis-baseline.json\n`);
}

function cmdDiff(baselinePath, rootArg, opts) {
  if (!baselinePath || !existsSync(baselinePath)) { process.stderr.write(`erro: baseline inexistente: ${baselinePath}\n`); process.exit(3); }
  const root = resolveRoot(rootArg);
  const base = JSON.parse(readFileSync(baselinePath, "utf8"));
  const key = (f) => `${f.path}|${f.method}|${f.resource}|${f.operation}`;
  const bmap = new Map(base.map((f) => [key(f), f.decision]));
  const { analyzed } = analyzeProject(root, opts);
  const cur = buildReport(analyzed).findings;
  const regress = [];
  for (const f of cur) {
    const prev = bmap.get(key(f));
    if (prev === "CONTROLLED" && f.decision !== "CONTROLLED") regress.push({ ...f, was: prev });
    if (f.decision === "VULNERABLE" && prev !== "VULNERABLE") regress.push({ ...f, was: prev || "novo" });
  }
  if (regress.length) {
    emit(`REGRESSÕES/NOVOS RISCOS (${regress.length}):\n`);
    for (const r of regress) emit(`  ${r.was} → ${r.decision}  ${r.method} ${r.path} [${r.resource}/${r.operation}]\n`);
    process.exitCode = 1;
  } else emit("sem regressões de autorização\n");
}

// Auditoria de RLS por tabela: lê o SQL (migrações ou dump de produção) e
// decide, por tabela × papel × operação, sem depender de rotas de API.
function cmdRls(rootArg, opts) {
  const root = resolveRoot(rootArg);
  const state = newWalkState();
  let model, source;
  if (opts.schemaDump) {
    const f = resolve(opts.schemaDump);
    let st; try { st = lstatSync(f); } catch { process.stderr.write(`erro: dump inexistente: ${f}\n`); process.exit(3); }
    if (!st.isFile()) { process.stderr.write(`erro: dump não é arquivo: ${f}\n`); process.exit(3); }
    if (st.size > LIMITS.maxTotalBytes) throw new LimitError(`dump maior que o limite (${LIMITS.maxTotalBytes} bytes)`);
    model = parseSqlCorpus({ [relative(root, f) || f]: readFileSync(f, "utf8") });
    source = "dump de schema (--schema-dump)";
    if (!model.dumpHeader) process.stderr.write("aviso: o arquivo não tem cabeçalho de pg_dump; ele será tratado como dump completo de produção por declaração sua\n");
    if (model.grantsSeen === 0) process.stderr.write("aviso: o dump não contém GRANT/REVOKE (gerado sem privilégios?); exposição não pode ser provada\n");
  } else {
    const rls = loadRls(root, opts.rls, state);
    model = rls.model;
    source = "migrações SQL";
    if (!model) {
      process.stderr.write("nenhum arquivo .sql encontrado (procurado em supabase/, migrations/, db/ ou --rls <dir>)\n");
      model = parseSqlCorpus({});
    }
  }
  const audit = auditTables(model, { schemaDump: !!opts.schemaDump, assumeDefaultGrants: !!opts.assumeDefaultGrants });
  const meta = { engine: `atlasxis ${PKG.version}`, version: PKG.version, source, assumeDefaultGrants: !!opts.assumeDefaultGrants };
  const fmt = opts.ci ? "json" : (opts.format || "markdown");
  emit(fmt === "json" ? rlsToJSON(audit, meta) : fmt === "sarif" ? rlsToSARIF(audit, meta) : rlsToMarkdown(audit, meta));
  emit("\n");
  if (opts.ci) {
    const s = audit.summary, vuln = s.VULNERABLE || 0, insuf = s.INSUFFICIENT_EVIDENCE || 0;
    process.stderr.write(`atlasxis rls --ci: VULNERABLE=${vuln} INSUFFICIENT=${insuf} — INSUFFICIENT NÃO significa seguro\n`);
    if (vuln > 0) process.exitCode = 2;
    if (opts.failOn === "insufficient" && (vuln > 0 || insuf > 0)) process.exitCode = 2;
  }
}

function cmdVersion() {
  process.stdout.write(`atlasxis ${PKG.version}\n`);
}

// ---------------- entrada ----------------
function parseArgs(argv) {
  const opts = {}; const pos = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--format") opts.format = argv[++i];
    else if (argv[i] === "--rls") opts.rls = argv[++i];
    else if (argv[i] === "--ci") opts.ci = true;
    else if (argv[i] === "--fail-on") opts.failOn = argv[++i];
    else if (argv[i] === "--out") opts.out = argv[++i];
    else if (argv[i] === "--schema-dump") opts.schemaDump = argv[++i];
    else if (argv[i] === "--assume-default-grants") opts.assumeDefaultGrants = true;
    else if (argv[i] === "--server-actions") opts.serverActions = true;
    else if (argv[i] === "--no-server-actions") opts.serverActions = false;
    else if (argv[i] === "--timeout") opts.timeoutMs = Math.max(1, Math.floor((Number(argv[++i]) || 0) * 1000));
    else if (argv[i].startsWith("--")) { process.stderr.write(`erro: flag desconhecida: ${argv[i]}\n`); process.exit(1); }
    else pos.push(argv[i]);
  }
  return { opts, pos };
}

const USAGE = `Atlasxis — Authorization Proof Engine (${PKG.version})

Certifica evidência estrutural de autorização por sink.
Nunca afirma "seguro" — afirma somente: provado controlado, provado vulnerável, ou não foi possível provar.

Uso:
  atlasxis scan <path> [--format json|markdown|sarif] [--rls <dir>] [--ci] [--fail-on insufficient] [--timeout <s>] [--no-server-actions]
  atlasxis report <path> [--rls <dir>] [--out <arquivo.md>]
  atlasxis rls <path> [--rls <dir> | --schema-dump <arquivo.sql>] [--assume-default-grants] [--format json|markdown|sarif] [--ci]
  atlasxis explain <REASON_CODE>
  atlasxis baseline <path>
  atlasxis diff <baseline.json> <path>
  atlasxis version

Exit codes: 0 ok · 1 uso/erro · 2 política --ci violada · 3 caminho inválido · 4 limite operacional
`;

const [cmd, ...rest] = process.argv.slice(2);
const { opts, pos } = parseArgs(rest);
try {
  if (cmd === "scan") cmdScan(pos[0] || ".", opts);
  else if (cmd === "report") cmdReport(pos[0] || ".", opts);
  else if (cmd === "rls") cmdRls(pos[0] || ".", opts);
  else if (cmd === "explain") cmdExplain(pos[0]);
  else if (cmd === "baseline") cmdBaseline(pos[0] || ".", opts);
  else if (cmd === "diff") cmdDiff(pos[0], pos[1] || ".", opts);
  else if (cmd === "version" || cmd === "--version" || cmd === "-v") cmdVersion();
  else { process.stdout.write(USAGE); process.exitCode = cmd ? 1 : 0; }
} catch (e) {
  if (e instanceof LimitError) { process.stderr.write(`erro operacional: ${e.message}\n`); process.exit(4); }
  process.stderr.write(`erro interno: ${e.message}\n`);
  process.exit(1);
}
