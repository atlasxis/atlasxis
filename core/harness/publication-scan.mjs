// ORÁCULO CORE — scanner de publicação (proteção contra vazamento).
// Varre uma árvore e FALHA se encontrar material que não pode ser publicado:
//   - segredos (JWT, chaves de API, connection strings com senha, AWS/GitHub);
//   - arquivos .env;
//   - caminhos pessoais absolutos (/Users/<nome>, /private/tmp, Desktop);
//   - nomes de projetos privados / corpora não redistribuíveis;
//   - o diretório rescue/ (baseline congelado + código privado/terceiro).
//
// Uso:
//   node publication-scan.mjs [dir]         # varre dir (padrão: raiz do repo)
//   node publication-scan.mjs --self-test   # roda os próprios casos adversariais
//
// O scanner testa a si mesmo: injeta cada categoria de vazamento em arquivos
// temporários e exige que TODAS sejam detectadas (senão o scanner é inútil).

import { readFileSync, readdirSync, statSync, existsSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join, relative, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, "../..");

// ---- regras de detecção (cada uma: id, regex, o que significa) ----
const RULES = [
  { id: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, why: "JSON Web Token" },
  { id: "stripe-openai-key", re: /\b(sk|pk|rk)[-_](live|test|proj)?[-_]?[A-Za-z0-9]{20,}\b/g, why: "chave estilo stripe/openai" },
  { id: "aws-key", re: /\bAKIA[0-9A-Z]{16}\b/g, why: "AWS access key id" },
  { id: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, why: "GitHub token" },
  { id: "conn-string", re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`]*:[^\s"'`@]{6,}@/g, why: "connection string com senha" },
  { id: "personal-path", re: /\/Users\/[a-z][a-z0-9._-]+\//gi, why: "caminho pessoal absoluto (/Users/<nome>)" },
  { id: "scratchpad-path", re: /\/private\/tmp\/|\/scratchpad\//g, why: "caminho de scratchpad/temporário" },
  { id: "desktop-path", re: /\/Desktop\//g, why: "caminho de Desktop pessoal" },
  { id: "private-project", re: /cabeca-fria|cabeça fria|codigo quantcare|quantcare/gi, why: "nome de projeto privado (Cabeça Fria)" },
  { id: "private-corpus", re: /\b(fifa2?|gymn|hikari|supastart)\b/gi, why: "nome de corpus de terceiro não redistribuível" },
  { id: "personal-email", re: /\bcorreiasobrinhohelio\b/gi, why: "email/handle pessoal" },
];

// arquivos/dirs onde certas ocorrências são ESPERADAS e legítimas (o próprio
// scanner e sua doc citam os padrões que procura). Allowlist explícita e mínima.
const SELF_REFERENTIAL = new Set([
  "core/harness/publication-scan.mjs",
  "docs/PUBLICATION.md",
]);

const SKIP_DIRS = new Set(["node_modules", ".git", ".github"]);
const TEXT_EXT = /\.(mjs|js|ts|tsx|json|md|yml|yaml|sql|txt|sh)$/;

function walk(dir, out = [], depth = 0) {
  if (depth > 20) return out;
  let ents; try { ents = readdirSync(dir); } catch { return out; }
  for (const e of ents.sort()) {
    if (SKIP_DIRS.has(e)) continue;
    const p = join(dir, e); let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, out, depth + 1);
    else out.push(p);
  }
  return out;
}

function scanTree(root) {
  const findings = [];
  // 1. rescue/ nunca pode estar na árvore pública
  if (existsSync(join(root, "rescue"))) findings.push({ file: "rescue/", rule: "rescue-dir", why: "baseline congelado + código privado/terceiro não pode ser publicado" });
  // 2. arquivos .env
  for (const f of walk(root)) {
    const rel = relative(root, f);
    const base = basename(f);
    if (/^\.env(\..+)?$/.test(base)) { findings.push({ file: rel, rule: "dotenv", why: "arquivo .env" }); continue; }
    if (!TEXT_EXT.test(base)) continue;
    if (SELF_REFERENTIAL.has(rel)) continue;
    let content; try { content = readFileSync(f, "utf8"); } catch { continue; }
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(content);
      if (m) findings.push({ file: rel, rule: rule.id, why: rule.why, sample: m[0].slice(0, 40) });
    }
  }
  return findings;
}

// ---- self-test: injeta cada categoria e exige detecção ----
function selfTest() {
  const base = join(tmpdir(), "oracle-pubscan-selftest");
  if (existsSync(base)) rmSync(base, { recursive: true, force: true });
  mkdirSync(base, { recursive: true });
  // Canários MONTADOS por concatenação: em runtime cada string é um segredo
  // "válido" que exercita o regex correspondente, mas o texto-fonte deste
  // arquivo NÃO contém nenhum segredo contíguo — assim nem o secret-scanning do
  // GitHub nem este próprio scanner acusam o arquivo de teste. São todos FALSOS
  // (padrões de exemplo), nunca segredos reais.
  const cJwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxMjMifQ" + ".abcdef123456";
  const cStripe = "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUV12";
  const cAws = "AK" + "IA" + "IOSFODNN7EXAMPLE";
  const cGh = "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const cConn = "postgres" + "://user:" + "super" + "secret@db.host:5432/x";
  const inject = {
    "a.ts": `const t = "${cJwt}";`,
    "b.ts": `const k = "${cStripe}";`,
    "c.ts": `// ${cAws}`,
    "d.ts": `const g = "${cGh}";`,
    "e.ts": `const url = "${cConn}";`,
    "f.ts": `import x from "/Users/someone/proj/lib.js";`,
    "g.ts": `// /private/tmp/foo/scratchpad/bar`,
    "h.ts": `// /Desktop/private/thing`,
    "i.ts": `// projeto cabeca-fria`,
    "j.ts": `// corpus fifa2 gymn hikari`,
    "k.ts": `// correiasobrinhohelio`,
    ".env": `SECRET=x`,
  };
  for (const [f, c] of Object.entries(inject)) writeFileSync(join(base, f), c);
  mkdirSync(join(base, "rescue"), { recursive: true });
  const findings = scanTree(base);
  const rulesHit = new Set(findings.map((f) => f.rule));
  const expected = ["jwt", "stripe-openai-key", "aws-key", "github-token", "conn-string", "personal-path", "scratchpad-path", "desktop-path", "private-project", "private-corpus", "personal-email", "dotenv", "rescue-dir"];
  const missed = expected.filter((r) => !rulesHit.has(r));
  rmSync(base, { recursive: true, force: true });
  console.log("=== SELF-TEST do scanner ===");
  for (const r of expected) console.log(`  ${rulesHit.has(r) ? "✓" : "✗"} detecta ${r}`);
  if (missed.length) { console.log(`\nSELF-TEST FALHOU: não detectou ${missed.join(", ")}`); process.exit(1); }
  console.log("\nself-test: todas as categorias detectadas");
}

// ---- main ----
const args = process.argv.slice(2);
if (args.includes("--self-test")) { selfTest(); process.exit(0); }
const target = args[0] ? args[0] : REPO_ROOT;
const findings = scanTree(target);
console.log(`=== PUBLICATION SCAN — ${relative(process.cwd(), target) || target} ===`);
if (!findings.length) { console.log("limpo: nenhum material não-publicável encontrado"); process.exit(0); }
for (const f of findings) console.log(`  ✗ ${f.file} [${f.rule}] ${f.why}${f.sample ? ` — "${f.sample}"` : ""}`);
console.log(`\n${findings.length} ocorrência(s) não-publicável(is)`);
process.exit(1);
