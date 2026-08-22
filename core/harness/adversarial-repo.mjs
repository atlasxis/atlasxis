// ORÁCULO CORE — teste de repositório adversarial (§7 da diretiva de encerramento).
// Um projeto sintético com 17 padrões deliberados. O requisito NÃO é cobertura
// máxima: é que, quando o ORÁCULO não conseguir provar, ele ABSTENHA — e que
// nunca emita false-control nem false-vulnerable.

import { analyzeFileIR } from "../engine.mjs";
import { parseSqlCorpus } from "../rls.mjs";
import { validateDecision } from "../ir.mjs";

const LIB = {
  "lib/legit.ts": `export async function ensureOwnsDoc(admin,uid,docId){ const {data}=await admin.from("docs").select("id,user_id").eq("id",docId).maybeSingle(); if(!data) throw new Error("404"); if(data.user_id!==uid) throw new Error("403"); return data; }`,
};
const H = (m, b, extra = {}) => ({ files: { "route.ts": `export async function ${m}(request,{params}){ try {\n${b}\n} catch(e){ return jsonError(e); } }`, ...LIB, ...extra }, entry: "route.ts" });
const admin = "const {user}=await auth(request);";
const authed = "const {user}=await supabaseAuth(request);";

// cada caso: {n, requirement: "PROVE_CONTROLLED"|"PROVE_VULNERABLE"|"MUST_ABSTAIN", ...}
// MUST_ABSTAIN = qualquer coisa que NÃO seja CONTROLLED nem VULNERABLE (i.e. o
// motor não pode afirmar nem uma coisa nem outra sem prova). É o coração do §7.
const CASES = [];
const add = (n, requirement, spec) => CASES.push({ n, requirement, ...spec });

// 1. ownership correto (self-scope)
add("01 ownership correto (self-scope)", "PROVE_CONTROLLED", H("GET", `${admin} const {data}=await supabaseAdmin.from("docs").select("*").eq("user_id",user.id); return Response.json({data});`));
// 2. IDOR evidente
add("02 IDOR evidente", "PROVE_VULNERABLE", H("DELETE", `const {id}=await params; ${admin} await supabaseAdmin.from("docs").delete().eq("id",id); return Response.json({ok:true});`));
// 3. post-read correto
add("03 post-read correto", "PROVE_CONTROLLED", H("POST", `const {id}=await params; ${admin} const {data:d}=await supabaseAdmin.from("docs").select("id,user_id").eq("id",id).maybeSingle(); if(d.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); return Response.json({ok:true});`));
// 4. post-read falso (gate compara flag não-owner)
add("04 post-read falso (flag não-owner)", "MUST_ABSTAIN", H("POST", `const {id}=await params; ${admin} const {data:d}=await supabaseAdmin.from("docs").select("id,locked").eq("id",id).maybeSingle(); if(d.locked) throw new Error("403"); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); return Response.json({ok:true});`));
// 5. check-A/write-B
add("05 check-A/write-B", "MUST_ABSTAIN", H("POST", `const {id,otherId}=await params; ${admin} const {data:d}=await supabaseAdmin.from("docs").select("id,user_id").eq("id",id).maybeSingle(); if(d.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("docs").update({s:1}).eq("id",otherId); return Response.json({ok:true});`));
// 6. alias
add("06 alias de id", "MUST_ABSTAIN", H("POST", `const {id}=await params; const target=id; ${admin} const {data:d}=await supabaseAdmin.from("docs").select("id,user_id").eq("id",id).maybeSingle(); if(d.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("docs").delete().eq("id",target); return Response.json({ok:true});`));
// 7. helper importado legítimo
add("07 helper importado legítimo", "PROVE_CONTROLLED", { files: { "route.ts": `import {ensureOwnsDoc} from "@/lib/legit"; export async function DELETE(request,{params}){ const {id}=await params; ${admin} await ensureOwnsDoc(supabaseAdmin,user.id,id); await supabaseAdmin.from("docs").delete().eq("id",id); return Response.json({ok:true}); }`, ...LIB }, entry: "route.ts" });
// 8. helper importado ambíguo (dois arquivos, corpos diferentes)
add("08 helper ambíguo", "MUST_ABSTAIN", { files: { "route.ts": `export async function DELETE(request,{params}){ const {id}=await params; ${admin} await guard(supabaseAdmin,user.id,id); await supabaseAdmin.from("docs").delete().eq("id",id); return Response.json({ok:true}); }`, "a.ts": `export async function guard(a,u,i){ return true; }`, "b.ts": `export async function guard(a,u,i){ const {data}=await a.from("docs").select("user_id").eq("id",i).maybeSingle(); if(data.user_id!==u) throw new Error("403"); }` }, entry: "route.ts" });
// 9. RLS owner
add("09 RLS owner", "PROVE_CONTROLLED", { files: { "route.ts": `export async function GET(request,{params}){ const {id}=await params; ${authed} const {data}=await supabaseAuthed.from("docs").select("*").eq("id",id); return Response.json({data}); }` }, entry: "route.ts", sql: { "s.sql": `create table public.docs(id uuid primary key, user_id uuid); alter table public.docs enable row level security; create policy p on public.docs for select using (auth.uid()=user_id);` } });
// 10. RLS permissiva perigosa (open OR owner)
add("10 RLS permissiva perigosa", "MUST_ABSTAIN", { files: { "route.ts": `export async function GET(request,{params}){ const {id}=await params; ${authed} const {data}=await supabaseAuthed.from("docs").select("*").eq("id",id); return Response.json({data}); }` }, entry: "route.ts", sql: { "s.sql": `create table public.docs(id uuid primary key, user_id uuid); alter table public.docs enable row level security; create policy own on public.docs for select using (auth.uid()=user_id); create policy open on public.docs for select using (true);` } });
// 11. RLS desconhecida (authenticated, sem schema)
add("11 RLS desconhecida", "MUST_ABSTAIN", { files: { "route.ts": `export async function GET(request,{params}){ const {id}=await params; ${authed} const {data}=await supabaseAuthed.from("docs").select("*").eq("id",id); return Response.json({data}); }` }, entry: "route.ts" });
// 12. admin legítimo (role-gate inline provado)
add("12 admin legítimo", "MUST_ABSTAIN", H("POST", `const {id}=await params; ${admin} const {data:p}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); if(!p||p.role!=="admin") return Response.json({},{status:403}); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); return Response.json({ok:true});`)); // OOS_PROVEN é aceitável (não é CONTROLLED nem VULNERABLE) → MUST_ABSTAIN
// 13. admin apenas por nome (helper vácuo importado)
add("13 admin só por nome", "MUST_ABSTAIN", { files: { "route.ts": `import {isAdmin} from "@/fake"; export async function POST(request,{params}){ const {id}=await params; ${admin} if(!isAdmin(user)) return Response.json({},{status:403}); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); return Response.json({ok:true}); }`, "fake.ts": `export function isAdmin(u){ const x=lookup(u); return x && x.role==="admin"; }` }, entry: "route.ts" });
// 14. multi-sink (um provado, um não)
add("14 multi-sink misto", "MUST_ABSTAIN", H("POST", `const {id,otherId}=await params; ${admin} const {data:d}=await supabaseAdmin.from("docs").select("id,user_id").eq("id",id).maybeSingle(); if(d.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); await supabaseAdmin.from("docs").delete().eq("id",otherId); return Response.json({ok:true});`));
// 15. sink com identidade diferente (tabela)
add("15 verifica tabela A, escreve tabela B", "MUST_ABSTAIN", H("POST", `const {id}=await params; ${admin} const {data:d}=await supabaseAdmin.from("other").select("id,user_id").eq("id",id).maybeSingle(); if(d.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("docs").update({s:1}).eq("id",id); return Response.json({ok:true});`));
// 16. parent-child authorization (legítimo)
add("16 parent-child (dono do pai modera filho)", "PROVE_CONTROLLED", H("POST", `const {commentId}=await params; ${admin} const {data:c}=await supabaseAdmin.from("comments").select("id,post_id").eq("id",commentId).maybeSingle(); if(!c) throw new Error("404"); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",c.post_id).maybeSingle(); if(post?.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("comments").update({status:"removed"}).eq("id",commentId); return Response.json({ok:true});`));
// 17. código não suportado
add("17 código não suportado (wrapper)", "MUST_ABSTAIN", { files: { "route.ts": `export const GET = withAuth(async (req)=>{ const {data}=await supabaseAdmin.from("docs").select("*"); return Response.json({data}); });` }, entry: "route.ts" });

let fail = 0, falseControl = 0, falseVuln = 0, integrity = 0;
console.log("=== REPOSITÓRIO ADVERSARIAL (17 padrões) ===");
for (const c of CASES) {
  const rls = c.sql ? { model: parseSqlCorpus(c.sql), declared: {}, options: {} } : {};
  const res = analyzeFileIR(c.files, c.entry, rls);
  const d = res[0].decision;
  for (const sd of res[0].sinkDecisions) if (validateDecision(sd).length) integrity++;
  if (validateDecision(d).length) integrity++;
  const st = d.status;
  let ok;
  if (c.requirement === "PROVE_CONTROLLED") ok = st === "CONTROLLED";
  else if (c.requirement === "PROVE_VULNERABLE") ok = st === "VULNERABLE";
  else ok = st !== "CONTROLLED" && st !== "VULNERABLE"; // MUST_ABSTAIN
  // erros fatais absolutos (independente do requirement declarado)
  if (c.requirement === "PROVE_VULNERABLE" && st === "CONTROLLED") falseControl++;
  if (c.requirement === "MUST_ABSTAIN" && st === "CONTROLLED") falseControl++;
  if (c.requirement === "PROVE_CONTROLLED" && st === "VULNERABLE") falseVuln++;
  if (!ok) fail++;
  console.log(`  ${ok ? "✓" : "✗"} ${c.n.padEnd(42)} req=${c.requirement.padEnd(17)} → ${st} [${d.reasonCode}]`);
}
console.log(`\nfail=${fail} false-control=${falseControl} false-vuln=${falseVuln} integrity=${integrity}`);
process.exit(fail || falseControl || falseVuln || integrity ? 1 : 0);
