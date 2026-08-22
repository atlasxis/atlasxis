// ORÁCULO CORE — harness de segurança operacional (FASE E do produto).
// Prova que analisar um projeto MALICIOSO não executa código, não escapa do
// root, não trava, não vaza segredos e respeita limites. Fixtures são
// construídas em diretório temporário a cada execução (nada é commitado).

import { mkdirSync, writeFileSync, symlinkSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "cli.mjs");
const BASE = join(tmpdir(), "oracle-opsec-fixtures");

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; process.stdout.write(`  ✓ ${name}\n`); }
  else { fail++; process.stdout.write(`  ✗ ${name}${detail ? ` — ${detail}` : ""}\n`); }
}

function runCli(args, opts = {}) {
  try {
    const out = execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 60000, ...opts });
    return { code: 0, out, err: "" };
  } catch (e) {
    return { code: e.status ?? -1, out: e.stdout || "", err: e.stderr || "", signal: e.signal };
  }
}

function proj(name) {
  const p = join(BASE, name);
  mkdirSync(join(p, "src", "app", "api", "x"), { recursive: true });
  return p;
}
function route(p, body) {
  writeFileSync(join(p, "src", "app", "api", "x", "route.ts"), body);
}
const BENIGN_ROUTE = `import { createClient } from "@supabase/supabase-js";
const supabaseAdmin = createClient(process.env.URL!, process.env.SERVICE_ROLE_KEY!);
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabaseAdmin.from("things").select("*").eq("id", params.id);
  return Response.json(data);
}
`;

if (existsSync(BASE)) rmSync(BASE, { recursive: true, force: true });
mkdirSync(BASE, { recursive: true });
process.stdout.write("SEGURANÇA OPERACIONAL — projeto malicioso não pode comprometer o analisador\n\n");

// 1. symlink de escape: aponta para fora do projeto — não pode ser seguido
{
  const p = proj("symlink-escape");
  route(p, BENIGN_ROUTE);
  const outside = join(BASE, "outside-secret");
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(outside, "leak.ts"), `export const CANARY_OUTSIDE = "CANARY_ESCAPE_9911";`);
  symlinkSync(outside, join(p, "src", "linked"), "dir");
  symlinkSync(join(outside, "leak.ts"), join(p, "src", "leak.ts"), "file");
  const r = runCli(["scan", p, "--format", "json"]);
  check("symlink (dir e arquivo) não é seguido", r.code === 0 && !r.out.includes("CANARY_ESCAPE_9911"), `code=${r.code}`);
  const meta = r.code === 0 ? JSON.parse(r.out).meta : {};
  check("symlinks contabilizados como ignorados", (meta.symlinksSkipped ?? 0) >= 2, `skipped=${meta.symlinksSkipped}`);
}

// 2. loop de symlinks: não pode travar
{
  const p = proj("symlink-loop");
  route(p, BENIGN_ROUTE);
  symlinkSync(join(p, "src"), join(p, "src", "app", "loop"), "dir");
  const r = runCli(["scan", p, "--format", "json"]);
  check("loop de symlink não trava nem quebra", r.code === 0 && !r.signal, `code=${r.code} signal=${r.signal}`);
}

// 3. arquivo gigante é ignorado, análise continua
{
  const p = proj("oversized");
  route(p, BENIGN_ROUTE);
  writeFileSync(join(p, "src", "big.ts"), "// x\n".repeat(1_200_000)); // ~4.8MB > limite de 2MB
  const r = runCli(["scan", p, "--format", "json"]);
  const meta = r.code === 0 ? JSON.parse(r.out).meta : {};
  check("arquivo acima do limite é pulado sem abortar", r.code === 0 && meta.oversizedSkipped === 1, `code=${r.code} oversized=${meta.oversizedSkipped}`);
}

// 4. TS malformado / lixo binário: nunca crash, decisão NOT_ANALYZED ou parse recuperado
{
  const p = proj("malformed");
  route(p, "export async function GET(\x00\x01{{{{ ((((");
  writeFileSync(join(p, "src", "junk.ts"), Buffer.from([0xff, 0xfe, 0x00, 0x99, 0x12]));
  const r = runCli(["scan", p, "--format", "json"]);
  check("arquivo malformado não derruba o scanner", r.code === 0, `code=${r.code} err=${r.err.slice(0, 80)}`);
  if (r.code === 0) {
    const rep = JSON.parse(r.out);
    const ok = rep.findings.every((f) => ["NOT_ANALYZED", "INSUFFICIENT_EVIDENCE"].includes(f.decision));
    check("malformado nunca vira CONTROLLED/SAFE", ok, JSON.stringify(rep.summary));
  }
}

// 5. lifecycle scripts do alvo NUNCA executam (postinstall/prepare com canário)
{
  const p = proj("lifecycle");
  route(p, BENIGN_ROUTE);
  const canary = join(BASE, "lifecycle-canary.txt");
  writeFileSync(join(p, "package.json"), JSON.stringify({
    name: "malicioso", version: "1.0.0",
    scripts: { postinstall: `node -e "require('fs').writeFileSync('${canary}','pwned')"`, prepare: `node -e "require('fs').writeFileSync('${canary}','pwned')"` },
  }));
  const r = runCli(["scan", p, "--format", "json"]);
  check("scan não executa lifecycle scripts do alvo", r.code === 0 && !existsSync(canary));
}

// 6. .env do alvo não é lido como configuração nem vaza no relatório
{
  const p = proj("dotenv");
  route(p, BENIGN_ROUTE);
  // JWT canário montado por concatenação: em runtime é um JWT válido para o
  // teste de vazamento, mas o texto-fonte não contém um JWT contíguo (para não
  // acionar o scanner de publicação sobre este próprio arquivo).
  const jwtEnv = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJ" + "yb2xlIjoic2VydmljZV9yb2xlIn0" + ".SEGREDO_ENV_CANARIO_77";
  writeFileSync(join(p, ".env"), `SERVICE_ROLE_KEY=${jwtEnv}\n`);
  const r1 = runCli(["scan", p, "--format", "json"]);
  const r2 = runCli(["report", p]);
  check(".env do alvo não aparece em nenhum output", r1.code === 0 && !((r1.out + r2.out).includes("SEGREDO_ENV_CANARIO_77")));
}

// 7. segredo embutido em código .ts é redigido na saída
{
  const p = proj("secret-in-code");
  const jwtCode = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".TOKEN_CANARIO_ABCDEF";
  route(p, `const KEY = "${jwtCode}";\n` + BENIGN_ROUTE);
  const r = runCli(["report", p]);
  check("JWT em código não é reproduzido no relatório", !r.out.includes("TOKEN_CANARIO_ABCDEF"));
}

// 8. caminhos inválidos: exit codes estáveis
{
  const r1 = runCli(["scan", join(BASE, "nao-existe")]);
  check("caminho inexistente → exit 3", r1.code === 3, `code=${r1.code}`);
  const f = join(BASE, "arquivo-plano.txt");
  writeFileSync(f, "x");
  const r2 = runCli(["scan", f]);
  check("caminho não-diretório → exit 3", r2.code === 3, `code=${r2.code}`);
}

// 9. timeout explícito → exit 4 (limite operacional)
{
  const p = proj("timeout");
  for (let i = 0; i < 8; i++) {
    mkdirSync(join(p, "src", "app", "api", `r${i}`), { recursive: true });
    writeFileSync(join(p, "src", "app", "api", `r${i}`, "route.ts"), BENIGN_ROUTE);
  }
  const r = runCli(["scan", p, "--timeout", "0"]); // clampa para 1ms
  check("timeout estourado → exit 4 com erro explícito", r.code === 4 && /timeout/.test(r.err), `code=${r.code}`);
}

// 10. determinismo do produto: scan e report byte-idênticos em duas execuções
{
  const p = proj("determinism");
  route(p, BENIGN_ROUTE);
  const a = runCli(["scan", p, "--format", "json"]).out, b = runCli(["scan", p, "--format", "json"]).out;
  const c = runCli(["report", p]).out, d = runCli(["report", p]).out;
  check("scan determinístico (2 execuções idênticas)", a === b && a.length > 0);
  check("report determinístico (2 execuções idênticas)", c === d && c.length > 0);
}

rmSync(BASE, { recursive: true, force: true });
process.stdout.write(`\nopsec: pass=${pass} fail=${fail}\n`);
if (fail > 0) process.exit(1);
