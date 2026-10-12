// Atlasxis — gerador de benchmark (FASE 5).
// Ground truth por CONSTRUÇÃO: cada gerador sabe qual padrão montou (SAFE_PROVABLE,
// SAFE_UNPROVABLE, VULNERABLE, OOS, UNSUPPORTED, AMBIGUOUS) e qual a decisão
// esperada do Atlasxis — NUNCA derivado do resultado do analyzer.
//
// Distinção central: `groundTruth` = verdade de segurança do código;
// `expectedDecision` = o que um certificador conservador CORRETO deve emitir.
// Um SAFE que o Atlasxis não consegue provar tem groundTruth=SAFE mas
// expectedDecision=INSUFFICIENT (isso é CORRETO, não um erro — CORRETUDE>COBERTURA).

let SEED = 1;
const rnd = () => (SEED = (SEED * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const pick = (a) => a[Math.floor(rnd() * a.length)];

const CASES = [];
let idc = 0;
function emit(c) {
  CASES.push({ id: `B${String(++idc).padStart(4, "0")}-${c.cat}`, ...c });
}

// tabelas/colunas genéricas (sem nomes de projeto real)
const TBL = ["notes", "items", "docs", "records", "entries", "assets", "tickets", "orders"];
const OWNCOL = ["user_id", "owner_id", "created_by", "author_id"];
const CONTAINER = ["conversation_id", "post_id", "thread_id", "parent_id"];
const WRITE = ["update", "delete"];
const READVERB = "select";

const wrap = (method, body) => ({ "route.ts": `export async function ${method}(request,{params}){ try {\n${body}\n} catch(e){ return jsonError(e); } }` });
const clientAuthed = "const {user}=await supabaseAuth(request);";
const clientAdmin = "const {user}=await auth(request);";

// ---- A. self-scope ----
for (let i = 0; i < 62; i++) {
  const t = pick(TBL), oc = pick(OWNCOL), verb = pick(["select", "update", "delete", "insert"]);
  let body;
  if (verb === "insert") body = `${clientAdmin} const b=await request.json(); await supabaseAdmin.from("${t}").insert({${oc}:user.id,data:b.d}); return Response.json({ok:true});`;
  else if (verb === "select") body = `${clientAdmin} const {data}=await supabaseAdmin.from("${t}").select("*").eq("${oc}",user.id); return Response.json({data});`;
  else body = `${clientAdmin} await supabaseAdmin.from("${t}").${verb}(${verb === "update" ? "{s:1}" : ""}).eq("${oc}",user.id); return Response.json({ok:true});`;
  emit({ cat: "self-scope", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_SELF_SCOPE"], expectedMechanism: "self-scope", expectedSinkCount: 1, files: wrap(verb === "select" ? "GET" : "POST", body), entry: "route.ts", rls: {} });
}

// ---- B. post-read ownership (positivo e near-miss) ----
for (let i = 0; i < 62; i++) {
  const t = pick(TBL), oc = pick(OWNCOL), verb = pick(WRITE);
  const good = rnd() < 0.5;
  const sinkId = good ? "id" : "otherId";
  const params = good ? "{id}" : "{id,otherId}";
  const body = `const ${params}=await params; ${clientAdmin} const {data:r}=await supabaseAdmin.from("${t}").select("id,${oc}").eq("id",id).maybeSingle(); if(r.${oc}!==user.id) throw new Error("403"); await supabaseAdmin.from("${t}").${verb}(${verb === "update" ? "{s:1}" : ""}).eq("id",${sinkId}); return Response.json({ok:true});`;
  if (good) emit({ cat: "post-read", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_POST_READ_GATE"], expectedMechanism: "post-read-gate", expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
  else emit({ cat: "post-read-nearmiss", groundTruth: "VULNERABLE", expectedDecision: "INSUFFICIENT_EVIDENCE", expectedReasonCodes: ["INSUFFICIENT_CROSS_RESOURCE", "INSUFFICIENT_RESOURCE_IDENTITY"], expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
}

// ---- D. admin bypass (owner || admin) ----
for (let i = 0; i < 40; i++) {
  const t = pick(TBL), oc = pick(OWNCOL), verb = pick(WRITE);
  const body = `const {id}=await params; ${clientAdmin} const {data:prof}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); const {data:r}=await supabaseAdmin.from("${t}").select("id,${oc}").eq("id",id).maybeSingle(); if(prof?.role!=="admin" && r.${oc}!==user.id) throw new Error("403"); await supabaseAdmin.from("${t}").${verb}(${verb === "update" ? "{s:1}" : ""}).eq("id",id); return Response.json({ok:true});`;
  emit({ cat: "admin-owner", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_POST_READ_GATE"], expectedMechanism: "post-read-gate", expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
}

// ---- VULNERABLE: IDOR nua service_role ----
for (let i = 0; i < 62; i++) {
  const t = pick(TBL), cc = pick(CONTAINER), verb = pick(["select", ...WRITE]);
  const src = verb === "select" ? `const {data}=await supabaseAdmin.from("${t}").select("*").eq("${cc}",id); return Response.json({data});`
    : `await supabaseAdmin.from("${t}").${verb}(${verb === "update" ? "{s:1}" : ""}).eq("id",id); return Response.json({ok:true});`;
  const body = `const {id}=await params; ${clientAdmin} ${src}`;
  emit({ cat: "idor-service-role", groundTruth: "VULNERABLE", expectedDecision: "VULNERABLE", expectedReasonCodes: ["VULNERABLE_NO_GATING_SERVICE_ROLE"], expectedSinkCount: 1, files: wrap(verb === "select" ? "GET" : "POST", body), entry: "route.ts", rls: {} });
}

// ---- INSUFFICIENT: authenticated client sem RLS conhecida ----
for (let i = 0; i < 46; i++) {
  const t = pick(TBL);
  const body = `const {id}=await params; ${clientAuthed} const {data}=await supabaseAuthed.from("${t}").select("*").eq("id",id); return Response.json({data});`;
  emit({ cat: "authed-no-rls", groundTruth: "UNKNOWN", expectedDecision: "INSUFFICIENT_EVIDENCE", expectedReasonCodes: ["INSUFFICIENT_RLS_UNKNOWN"], expectedSinkCount: 1, files: wrap("GET", body), entry: "route.ts", rls: {} });
}

// ---- G/H/J/K. RLS parseada ----
for (let i = 0; i < 62; i++) {
  const t = pick(TBL), oc = pick(OWNCOL);
  const shape = pick(["owner", "open", "none", "admin-or-owner", "restrictive"]);
  let policy, gt, dec, reason;
  if (shape === "owner") { policy = `create policy p on public.${t} for select using (auth.uid() = ${oc});`; gt = "SAFE"; dec = "CONTROLLED"; reason = "CONTROLLED_RLS_POLICY_OWNER"; }
  else if (shape === "admin-or-owner") { policy = `create or replace function public.is_admin() returns boolean language sql as $$ select exists (select 1 from public.profiles where id=auth.uid() and role='admin'); $$; create policy p on public.${t} for select using (${oc}=auth.uid() or public.is_admin());`; gt = "SAFE"; dec = "CONTROLLED"; reason = "CONTROLLED_RLS_POLICY_OWNER"; }
  else if (shape === "restrictive") { policy = `create policy o on public.${t} for select using (true); create policy r on public.${t} as restrictive for select using (auth.uid()=${oc});`; gt = "SAFE"; dec = "CONTROLLED"; reason = "CONTROLLED_RLS_POLICY_OWNER"; }
  else if (shape === "open") { policy = `create policy p on public.${t} for select using (true);`; gt = "VULNERABLE"; dec = "INSUFFICIENT_EVIDENCE"; reason = "INSUFFICIENT_RLS_POLICY_UNPROVEN"; }
  else { policy = ``; gt = "UNKNOWN"; dec = "INSUFFICIENT_EVIDENCE"; reason = "INSUFFICIENT_RLS_ABSENT"; }
  const sql = { "schema.sql": `create table public.${t} ( id uuid primary key, ${oc} uuid );` + (shape === "none" ? "" : `alter table public.${t} enable row level security;`) + policy };
  const body = `const {id}=await params; ${clientAuthed} const {data}=await supabaseAuthed.from("${t}").select("*").eq("id",id); return Response.json({data});`;
  emit({ cat: "rls-" + shape, groundTruth: gt, expectedDecision: dec, expectedReasonCodes: [reason], expectedSinkCount: 1, files: wrap("GET", body), entry: "route.ts", sql });
}

// ---- L. multi-sink (mix) ----
for (let i = 0; i < 40; i++) {
  const t = pick(TBL), oc = pick(OWNCOL);
  const secondSafe = rnd() < 0.5;
  const body = `const {id${secondSafe ? "" : ",otherId"}}=await params; ${clientAdmin} const {data:r}=await supabaseAdmin.from("${t}").select("id,${oc}").eq("id",id).maybeSingle(); if(r.${oc}!==user.id) throw new Error("403"); await supabaseAdmin.from("${t}").update({s:1}).eq("id",id); await supabaseAdmin.from("${t}").delete().eq("id",${secondSafe ? "id" : "otherId"}); return Response.json({ok:true});`;
  if (secondSafe) emit({ cat: "multi-sink-allsafe", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_POST_READ_GATE"], expectedSinkCount: 2, files: wrap("POST", body), entry: "route.ts", rls: {} });
  else emit({ cat: "multi-sink-mixed", groundTruth: "VULNERABLE", expectedDecision: "INSUFFICIENT_EVIDENCE", expectedReasonCodes: ["INSUFFICIENT_CROSS_RESOURCE", "INSUFFICIENT_RESOURCE_IDENTITY"], expectedSinkCount: 2, files: wrap("POST", body), entry: "route.ts", rls: {} });
}

// ---- Y. dead-code guard (adversarial) ----
for (let i = 0; i < 24; i++) {
  const t = pick(TBL), oc = pick(OWNCOL), cc = pick(CONTAINER);
  const body = `const {id}=await params; ${clientAdmin} if(false){ const {data:r}=await supabaseAdmin.from("${t}").select("${oc}").eq("id",id); if(r.${oc}!==user.id) throw new Error("403"); } const {data}=await supabaseAdmin.from("${t}").select("*").eq("${cc}",id); return Response.json({data});`;
  emit({ cat: "dead-guard", groundTruth: "VULNERABLE", expectedDecision: "VULNERABLE", expectedReasonCodes: ["VULNERABLE_NO_GATING_SERVICE_ROLE"], expectedSinkCount: 1, files: wrap("GET", body), entry: "route.ts", rls: {} });
}

// ---- AB. unsupported syntax ----
for (let i = 0; i < 16; i++) {
  const body = `export const GET = withMiddleware(async (request)=>{ const {data}=await supabaseAdmin.from("x").select("*"); return Response.json({data}); });`;
  emit({ cat: "unsupported", groundTruth: "UNKNOWN", expectedDecision: "NOT_ANALYZED", expectedReasonCodes: ["NOT_ANALYZED_UNSUPPORTED_SYNTAX"], expectedSinkCount: 0, files: { "route.ts": body }, entry: "route.ts", rls: {} });
}

// ---- F. admin-only route (OOS) ----
for (let i = 0; i < 24; i++) {
  const t = pick(TBL);
  const body = `const {id}=await params; ${clientAdmin} const {data:p}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); if(!p||p.role!=="admin") return Response.json({},{status:403}); await supabaseAdmin.from("${t}").update({s:1}).eq("id",id); return Response.json({ok:true});`;
  emit({ cat: "admin-only", groundTruth: "SAFE", expectedDecision: "OUT_OF_SCOPE_PROVEN", expectedReasonCodes: ["OOS_PROVEN_ADMIN_INLINE_ROLE_GATE"], expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
}

// ---- N. cross-file helper (positivo) ----
for (let i = 0; i < 24; i++) {
  const t = pick(TBL), oc = pick(OWNCOL);
  const files = {
    "route.ts": `import {ensureOwns} from "@/lib/g"; export async function DELETE(request,{params}){ const {id}=await params; ${clientAdmin} await ensureOwns(supabaseAdmin,user.id,id); await supabaseAdmin.from("${t}").delete().eq("id",id); return Response.json({ok:true}); }`,
    "lib/g.ts": `export async function ensureOwns(admin,uid,rid){ const {data}=await admin.from("${t}").select("id,${oc}").eq("id",rid).maybeSingle(); if(!data) throw new Error("404"); if(data.${oc}!==uid) throw new Error("403"); return data; }`,
  };
  emit({ cat: "cross-file-helper", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_OWNERSHIP_HELPER"], expectedMechanism: "helper-ownership", expectedSinkCount: 1, files, entry: "route.ts", rls: {} });
}

// ---- E. transitive ownership ----
for (let i = 0; i < 24; i++) {
  const good = rnd() < 0.6;
  const memberFilter = good ? `.eq("team_id",lineup.team_id).eq("user_id",user.id)` : `.eq("team_id",teamId).eq("user_id",user.id)`;
  const params = good ? "{id}" : "{id,teamId}";
  const body = `const ${params}=await params; ${clientAdmin} const {data:lineup}=await supabaseAdmin.from("lineups").select("id,team_id").eq("id",id).maybeSingle(); if(!lineup) throw new Error("404"); const {data:member}=await supabaseAdmin.from("players").select("id")${memberFilter}.maybeSingle(); if(!member) throw new Error("403"); await supabaseAdmin.from("lineups").delete().eq("id",id); return Response.json({ok:true});`;
  if (good) emit({ cat: "transitive", groundTruth: "SAFE", expectedDecision: "CONTROLLED", expectedReasonCodes: ["CONTROLLED_TRANSITIVE_OWNERSHIP"], expectedMechanism: "transitive-ownership", expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
  else emit({ cat: "transitive-broken", groundTruth: "VULNERABLE", expectedDecision: "VULNERABLE", expectedReasonCodes: ["VULNERABLE_NO_GATING_SERVICE_ROLE"], expectedSinkCount: 1, files: wrap("POST", body), entry: "route.ts", rls: {} });
}

// ---- AC. adversarial: nome/comentário/string nunca é prova ----
for (let i = 0; i < 30; i++) {
  const t = pick(TBL), cc = pick(CONTAINER);
  const trick = pick([
    `// if(owner!==user.id) throw new Error("403"); authorized check here`,
    `const authorized="owner check"; const isAdmin="admin";`,
    `const s='if(r.user_id!==user.id) throw';`,
  ]);
  const body = `const {id}=await params; ${clientAdmin} ${trick}\n const {data}=await supabaseAdmin.from("${t}").select("*").eq("${cc}",id); return Response.json({data});`;
  emit({ cat: "adversarial-nameonly", groundTruth: "VULNERABLE", expectedDecision: "VULNERABLE", expectedReasonCodes: ["VULNERABLE_NO_GATING_SERVICE_ROLE"], expectedSinkCount: 1, files: wrap("GET", body), entry: "route.ts", rls: {} });
}

// ---- fake admin helper by name (adversarial) ----
for (let i = 0; i < 16; i++) {
  const t = pick(TBL);
  const files = {
    "route.ts": `import {isAdmin} from "@/lib/fake"; export async function POST(request,{params}){ const {id}=await params; ${clientAdmin} if(!isAdmin(user)) return Response.json({},{status:403}); await supabaseAdmin.from("${t}").update({s:1}).eq("id",id); return Response.json({ok:true}); }`,
    "lib/fake.ts": `export function isAdmin(u){ return true; }`,
  };
  // helper importado provado VÁCUO (return true) → guard oco → exploração real → VULNERABLE
  emit({ cat: "fake-admin-name", groundTruth: "VULNERABLE", expectedDecision: "VULNERABLE", expectedReasonCodes: ["VULNERABLE_NO_GATING_SERVICE_ROLE"], expectedSinkCount: 1, files, entry: "route.ts", rls: {} });
}

export const BENCHMARK = CASES;
