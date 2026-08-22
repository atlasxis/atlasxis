// ORÁCULO CORE — fixtures da FASE 3 (REQUISITO 12: positiva, negativa,
// adversarial, UNKNOWN e regressão para cada capacidade nova).
// Expectativas em reason codes (nunca texto livre).

const LIB = {
  "lib/pm.ts": `
export async function getConversation(admin,cid){ const {data}=await admin.from("private_conversations").select("id,requester_id,recipient_id").eq("id",cid).maybeSingle(); if(!data) throw new Error("404"); return data; }
export function isConversationParticipant(uid,c){ return c.requester_id===uid || c.recipient_id===uid; }`,
};

const POST = (b) => `export async function POST(request,{params}){ try {\n${b}\n} catch(e){ return jsonError(e); } }`;
const GET = (b) => `export async function GET(request,{params}){ try {\n${b}\n} catch(e){ return jsonError(e); } }`;

export const FIXTURES = [];
const add = (n, spec, files, entry = "route.ts") =>
  FIXTURES.push({ n, ...spec, files: typeof files === "string" ? { [entry]: files, ...LIB } : { ...files, ...LIB }, entry, rls: spec.rls || {} });

// ============ REQUISITO 1 — MULTI-SINK ============
// positiva: sinks divergem e o handler é derivado deles
add("MS-01 update provado + delete outro id", {
  handler: "INSUFFICIENT_EVIDENCE",
  sinks: { "posts/update": "CONTROLLED", "posts/delete": "INSUFFICIENT_EVIDENCE" },
}, POST(`const {id,otherId}=await params; const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); await supabaseAdmin.from("posts").delete().eq("id",otherId); return Response.json({ok:true});`));

add("MS-02 dois sinks provados", {
  handler: "CONTROLLED",
  sinks: { "posts/update": "CONTROLLED", "posts/delete": "CONTROLLED" },
}, POST(`const {id}=await params; const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); await supabaseAdmin.from("posts").delete().eq("id",id); return Response.json({ok:true});`));

// adversarial: VULNERABLE domina a agregação mesmo com sink CONTROLLED ao lado
add("MS-03 self-scope + IDOR nua no mesmo handler", {
  handler: "VULNERABLE",
  sinks: { "notes/insert": "CONTROLLED", "private_messages/delete": "VULNERABLE" },
}, POST(`const {messageId}=await params; const {user}=await auth(request); await supabaseAdmin.from("notes").insert({user_id:user.id,c:1}); await supabaseAdmin.from("private_messages").delete().eq("id",messageId); return Response.json({ok:true});`));

// ============ REQUISITO 10 — IDENTIDADE ============
add("ID-01 check A sink B → cross-resource", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_CROSS_RESOURCE",
}, GET(`const {id,otherId}=await params; const {user}=await auth(request); const {data:a}=await supabaseAdmin.from("notes").select("id,user_id").eq("id",id).maybeSingle(); if(a.user_id!==user.id) throw new Error("403"); const {data}=await supabaseAdmin.from("notes").select("*").eq("id",otherId); return Response.json({data});`));

add("ID-02 alias de rid nunca vira CONTROLLED", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_ALIAS_RESOLUTION",
}, GET(`const {id}=await params; const other=id; const {user}=await auth(request); const {data:a}=await supabaseAdmin.from("notes").select("id,user_id").eq("id",id).maybeSingle(); if(a.user_id!==user.id) throw new Error("403"); const {data}=await supabaseAdmin.from("notes").select("*").eq("id",other); return Response.json({data});`));

add("ID-03 alias sem nenhum gate (service_role) não silencia", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_ALIAS_RESOLUTION",
}, GET(`const {id}=await params; const target=id; const {user}=await auth(request); const {data}=await supabaseAdmin.from("private_messages").select("*").eq("conversation_id",target); return Response.json({data});`));

// ============ REQUISITO 3 — AUTHORIZATION IR / De Morgan ============
add("AZ-01 deny(role!==admin && owner!==user)", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:prof}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(prof?.role!=="admin" && post.user_id!==user.id) return Response.json({},{status:403}); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

add("AZ-02 deny(!(owner || admin))", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:prof}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(!(post.user_id===user.id || prof?.role==="admin")) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

add("AZ-03 deny(locked || owner!==user) → allow=conjunção estrita", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id,locked").eq("id",id).maybeSingle(); if(post.locked || post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

// quando admin é condição NECESSÁRIA para passar, a rota é admin-only → OOS provado
add("AZ-07 deny(role!==admin || owner!==user) → admin necessário = OOS", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_ADMIN_INLINE_ROLE_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:prof}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(prof?.role!=="admin" || post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

// adversarial: disjunto desconhecido passa sem autorização → abster
add("AZ-04 bypass por flag desconhecida", { handler: "INSUFFICIENT_EVIDENCE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(!(post.user_id===user.id || someFlag)) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

add("AZ-05 dupla negação + expansão de booleanos", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:prof}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); const notOwner=!(post.user_id===user.id); const isAdm=prof?.role==="admin"; if(notOwner && !isAdm) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

// adversarial: variável chamada isAdmin NÃO expandível nunca autoriza (convenção ≠ fato)
add("AZ-06 isAdmin não-expansível não autoriza", { handler: "INSUFFICIENT_EVIDENCE" },
  POST(`const {id}=await params; const {user}=await auth(request); const isAdmin=await checkSomewhere(user); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(!(post.user_id===user.id || isAdmin)) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

// ============ REQUISITO 4 — UNKNOWN força abstenção ============
add("UN-01 helper importado de módulo fora do conjunto", { handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_CROSS_FILE_EVIDENCE" },
  { "route.ts": `import {chk} from "@/externo/nao-analisado"; export async function GET(request,{params}){ const {id}=await params; const {user}=await auth(request); if(!(await chk(user.id,id))) return Response.json({},{status:403}); const {data}=await supabaseAdmin.from("private_messages").select("*").eq("conversation_id",id); return Response.json({data}); }` }),

add("UN-02 client desconhecido → RLS unknown, nunca VULNERABLE", { handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_UNKNOWN" },
  { "route.ts": `export async function GET(request,{params}){ const {id}=await params; const {data}=await someDb.from("gym").select("*").eq("referral_code",id); return Response.json({data}); }` }),

// ============ REQUISITO 9 — DISCOVERY ============
add("DS-01 arrow handler com IDOR nua", { handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE" },
  { "route.ts": `export const DELETE = async (request,{params}) => { const {messageId}=await params; const {user}=await auth(request); await supabaseAdmin.from("private_messages").delete().eq("id",messageId); return Response.json({ok:true}); };` }),

add("DS-02 arrow handler self-scope", { handler: "CONTROLLED", reason: "CONTROLLED_SELF_SCOPE" },
  { "route.ts": `export const GET = async (request) => { const {user}=await auth(request); const {data}=await supabaseAdmin.from("notes").select("*").eq("user_id",user.id); return Response.json({data}); };` }),

add("DS-03 params.id inline sem gating", { handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE" },
  { "route.ts": `export async function DELETE(request,{params}){ const {user}=await auth(request); await supabaseAdmin.from("private_messages").delete().eq("id",params.id); return Response.json({ok:true}); }` }),

add("DS-04 params.id inline com post-read gate", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  { "route.ts": `export async function DELETE(request,{params}){ const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",params.id).maybeSingle(); if(post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").delete().eq("id",params.id); return Response.json({ok:true}); }` }),

add("DS-05 export const GET = wrapper(...) → nunca silêncio como seguro", { handler: "NOT_ANALYZED", reason: "NOT_ANALYZED_UNSUPPORTED_SYNTAX" },
  { "route.ts": `export const GET = withAuth(async (request)=>{ const {data}=await supabaseAdmin.from("x").select("*"); return Response.json({data}); });` }),

// ============ admin role-gate inline (genérico) ============
add("AD-01 role gate inline domina params.id", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_ADMIN_INLINE_ROLE_GATE" },
  { "route.ts": `export async function POST(request,{params}){ const {user}=await auth(request); const {data:profile}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); if(!profile || profile.role!=="admin") return Response.json({},{status:403}); await supabaseAdmin.from("forum_posts").update({pinned:true}).eq("id",params.id); return Response.json({ok:true}); }` }),

// adversarial: role lido SEM filtro por user.id não prova nada
add("AD-02 role de origem não ligada ao user", { handler: "INSUFFICIENT_EVIDENCE" },
  { "route.ts": `export async function POST(request,{params}){ const {id,who}=await params; const {user}=await auth(request); const {data:profile}=await supabaseAdmin.from("profiles").select("role").eq("id",who).single(); if(!profile || profile.role!=="admin") return Response.json({},{status:403}); await supabaseAdmin.from("forum_posts").update({pinned:true}).eq("id",id); return Response.json({ok:true}); }` }),

// adversarial: gate admin DEPOIS do sink não domina
add("AD-03 role gate depois do sink", { handler: "INSUFFICIENT_EVIDENCE" },
  { "route.ts": `export async function POST(request,{params}){ const {id}=await params; const {user}=await auth(request); await supabaseAdmin.from("forum_posts").update({pinned:true}).eq("id",id); const {data:profile}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).single(); if(!profile || profile.role!=="admin") return Response.json({},{status:403}); return Response.json({ok:true}); }` }),

// ============ webhook genérico (REQUISITO 5 — zero tokens de projeto) ============
add("WH-01 header vs process.env com rejeição", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_WEBHOOK_SIGNATURE" },
  { "billing/webhook/route.ts": `export async function POST(request){ const token=request.headers.get("x-hook-token"); const secret=process.env.HOOK_SECRET; if(token!==secret) return Response.json({},{status:401}); const body=await request.json(); await supabaseAdmin.from("payments").update({status:body.status}).eq("id",body.id); return Response.json({ok:true}); }` }, "billing/webhook/route.ts"),

add("WH-02 webhook sem verificação", { handler: "OUT_OF_SCOPE_UNVERIFIED", reason: "OUT_OF_SCOPE_UNVERIFIED_WEBHOOK" },
  { "billing/webhook/route.ts": `export async function POST(request){ const body=await request.json(); await supabaseAdmin.from("payments").update({status:body.status}).eq("id",body.id); return Response.json({ok:true}); }` }, "billing/webhook/route.ts"),

add("WH-03 HMAC verificado com rejeição", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_WEBHOOK_SIGNATURE" },
  { "hooks/webhook/route.ts": `import {createHmac,timingSafeEqual} from "node:crypto"; export async function POST(request){ const raw=await request.text(); const sig=request.headers.get("x-signature"); const ok=timingSafeEqual(Buffer.from(sig||""),Buffer.from(createHmac("sha256",process.env.WH_SECRET).update(raw).digest("hex"))); if(!ok) return Response.json({},{status:401}); const body=JSON.parse(raw); await supabaseAdmin.from("events").insert({kind:body.kind}); return Response.json({ok:true}); }` }, "hooks/webhook/route.ts"),

// ============ fecho confiável: dono de recurso-pai derivado de R ============
add("PC-01 admin || dono do comment || dono do post-pai", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {commentId}=await params; const {user}=await auth(request); const {data:profile}=await supabaseAdmin.from("profiles").select("role").eq("id",user.id).maybeSingle(); const {data:comment}=await supabaseAdmin.from("comments").select("id,user_id,post_id").eq("id",commentId).maybeSingle(); if(!comment) throw new Error("404"); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",comment.post_id).maybeSingle(); const canDelete=profile?.role==="admin"||comment.user_id===user.id||post?.user_id===user.id; if(!canDelete) throw new Error("403"); await supabaseAdmin.from("comments").update({status:"removed"}).eq("id",commentId); return Response.json({ok:true});`));

// adversarial: o "pai" vem de um id do CLIENTE, não de R → fora do fecho → abster
add("PC-02 dono de objeto NÃO derivado de R não autoriza", { handler: "INSUFFICIENT_EVIDENCE" },
  POST(`const {commentId,otherPostId}=await params; const {user}=await auth(request); const {data:comment}=await supabaseAdmin.from("comments").select("id,user_id,post_id").eq("id",commentId).maybeSingle(); if(!comment) throw new Error("404"); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",otherPostId).maybeSingle(); const canDelete=post?.user_id===user.id; if(!canDelete) throw new Error("403"); await supabaseAdmin.from("comments").update({status:"removed"}).eq("id",commentId); return Response.json({ok:true});`));

add("PC-03 apenas dono do pai derivado (moderador de thread)", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {commentId}=await params; const {user}=await auth(request); const {data:comment}=await supabaseAdmin.from("comments").select("id,post_id").eq("id",commentId).maybeSingle(); if(!comment) throw new Error("404"); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",comment.post_id).maybeSingle(); if(post?.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("comments").update({status:"removed"}).eq("id",commentId); return Response.json({ok:true});`));

// ============ webhook cross-file: helper de segredo e delegação ============
add("WH-04 segredo via helper cross-file (2 saltos até process.env)", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_WEBHOOK_SIGNATURE" },
  { "pay/webhook/route.ts": `import {getHookToken} from "@/lib/env-billing"; export async function POST(request){ const expected=getHookToken(); if(!expected) throw new Error("503"); const token=request.headers.get("x-hook-token"); if(token!==expected) throw new Error("401"); const body=await request.json(); await supabaseAdmin.from("payments").update({status:body.status}).eq("id",body.id); return Response.json({ok:true}); }`,
    "lib/env-billing.ts": `function readEnv(key){ const v=process.env[key]; return v||null; } export function getHookToken(){ return readEnv("HOOK_TOKEN"); }` }, "pay/webhook/route.ts"),

// adversarial: helper devolve constante, não env → nada provado
add("WH-05 helper que NÃO lê env não prova segredo", { handler: "OUT_OF_SCOPE_UNVERIFIED", reason: "OUT_OF_SCOPE_UNVERIFIED_WEBHOOK" },
  { "pay/webhook/route.ts": `import {getHookToken} from "@/lib/env-billing"; export async function POST(request){ const expected=getHookToken(); const token=request.headers.get("x-hook-token"); if(token!==expected) throw new Error("401"); const body=await request.json(); await supabaseAdmin.from("payments").update({status:body.status}).eq("id",body.id); return Response.json({ok:true}); }`,
    "lib/env-billing.ts": `export function getHookToken(){ return "token-fixo"; }` }, "pay/webhook/route.ts"),

add("WH-06 delegação por import-alias herda prova", { handler: "OUT_OF_SCOPE_PROVEN", reason: "OOS_PROVEN_WEBHOOK_SIGNATURE" },
  { "outer/webhook/route.ts": `import { POST as inner } from "@/pay/webhook/route"; export async function POST(request){ return inner(request); }`,
    "pay/webhook/route.ts": `export async function POST(request){ const token=request.headers.get("x-hook-token"); if(token!==process.env.HOOK_SECRET) throw new Error("401"); const body=await request.json(); await supabaseAdmin.from("payments").update({status:body.status}).eq("id",body.id); return Response.json({ok:true}); }` }, "outer/webhook/route.ts"),

// ============ hardening: cross-file, discovery de query params ============
add("CH-01 helper const-arrow cross-file prova ownership", { handler: "CONTROLLED", reason: "CONTROLLED_OWNERSHIP_HELPER" },
  { "route.ts": `import {ensureOwnsNote} from "@/lib/notes"; export async function DELETE(request,{params}){ const {id}=await params; const {user}=await auth(request); await ensureOwnsNote(supabaseAdmin,user.id,id); await supabaseAdmin.from("notes").delete().eq("id",id); return Response.json({ok:true}); }`,
    "lib/notes.ts": `export const ensureOwnsNote = async (admin,uid,noteId) => { const {data}=await admin.from("notes").select("id,user_id").eq("id",noteId).maybeSingle(); if(!data) throw new Error("404"); if(data.user_id!==uid) throw new Error("403"); return data; };` }),

add("CH-02 helper não-resolvível local (sem import) mantém GUARD_UNRESOLVED", { handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE" },
  { "route.ts": `export async function GET(request,{params}){ const {id}=await params; const {user}=await auth(request); maybeCheck(id); const {data}=await supabaseAdmin.from("private_messages").select("*").eq("conversation_id",id); return Response.json({data}); }` }),

add("DS-06 query param como source (searchParams.get)", { handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE" },
  { "route.ts": `export async function GET(request){ const {searchParams}=new URL(request.url); const {user}=await auth(request); const {data}=await supabaseAdmin.from("private_messages").select("*").eq("conversation_id",searchParams.get("conversationId")); return Response.json({data}); }` }),

add("DS-07 query param com post-read gate", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  { "route.ts": `export async function GET(request){ const {searchParams}=new URL(request.url); const {user}=await auth(request); const {data:note}=await supabaseAdmin.from("notes").select("id,user_id").eq("id",searchParams.get("id")).maybeSingle(); if(note.user_id!==user.id) throw new Error("403"); const {data}=await supabaseAdmin.from("notes").select("*").eq("id",searchParams.get("id")); return Response.json({data}); }` }),

// ============ dominância de guard e ambiguidade de helper (soundness) ============
// adversarial: gate DENTRO de branch não domina o sink → nunca CONTROLLED
add("BR-01 gate aninhado em branch não domina sink", { handler: "INSUFFICIENT_EVIDENCE" },
  POST(`const {id}=await params; const {user}=await auth(request); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(request.headers.get("x-debug")){ if(post.user_id!==user.id) throw new Error("403"); } await supabaseAdmin.from("posts").update({t:1}).eq("id",id); return Response.json({ok:true});`));

// positivo: gate e sink no MESMO branch → domina, prova válida
add("BR-02 gate e sink no mesmo branch dominam-se", { handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE" },
  POST(`const {id}=await params; const {user}=await auth(request); const body=await request.json(); const {data:post}=await supabaseAdmin.from("posts").select("id,user_id").eq("id",id).maybeSingle(); if(body.mode==="edit"){ if(post.user_id!==user.id) throw new Error("403"); await supabaseAdmin.from("posts").update({t:1}).eq("id",id); } return Response.json({ok:true});`));

// adversarial: helper com MESMO nome em dois arquivos, corpos diferentes → ambíguo, nunca provar
add("HD-01 helper duplicado com corpos diferentes é ambíguo", { handler: "INSUFFICIENT_EVIDENCE" },
  { "route.ts": `export async function DELETE(request,{params}){ const {id}=await params; const {user}=await auth(request); await ensureOwns(supabaseAdmin,user.id,id); await supabaseAdmin.from("notes").delete().eq("id",id); return Response.json({ok:true}); }`,
    "a_first.ts": `export async function ensureOwns(admin,uid,noteId){ return true; }`,
    "z_real.ts": `export async function ensureOwns(admin,uid,noteId){ const {data}=await admin.from("notes").select("id,user_id").eq("id",noteId).maybeSingle(); if(!data||data.user_id!==uid) throw new Error("403"); return data; }` }),

// positivo de controle: import explícito desfaz a ambiguidade
add("HD-02 import explícito resolve o helper certo", { handler: "CONTROLLED", reason: "CONTROLLED_OWNERSHIP_HELPER" },
  { "route.ts": `import {ensureOwns} from "@/z_real"; export async function DELETE(request,{params}){ const {id}=await params; const {user}=await auth(request); await ensureOwns(supabaseAdmin,user.id,id); await supabaseAdmin.from("notes").delete().eq("id",id); return Response.json({ok:true}); }`,
    "a_first.ts": `export async function ensureOwns(admin,uid,noteId){ return true; }`,
    "z_real.ts": `export async function ensureOwns(admin,uid,noteId){ const {data}=await admin.from("notes").select("id,user_id").eq("id",noteId).maybeSingle(); if(!data||data.user_id!==uid) throw new Error("403"); return data; }` }),

// ============ soundness: guard-call não analisável nunca vira VULNERABLE ============
// real imported admin check (faz trabalho) → abster, NUNCA VULNERABLE (evita FP)
add("GC-01 guard importado que faz trabalho real → INSUFFICIENT", { handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_CROSS_FILE_EVIDENCE" },
  { "route.ts": `import {ensureAdmin} from "@/lib/a"; export async function POST(request,{params}){ const {id}=await params; const {user}=await auth(request); if(!ensureAdmin(user)) return Response.json({},{status:403}); await supabaseAdmin.from("notes").update({s:1}).eq("id",id); return Response.json({ok:true}); }`,
    "lib/a.ts": `export function ensureAdmin(u){ const d=lookup(u); if(!d) return false; return d.role==="admin"; }` }),
// helper importado provado VÁCUO (return true) → guard oco → VULNERABLE (exploração real)
add("GC-02 guard importado provado vácuo → VULNERABLE", { handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE" },
  { "route.ts": `import {isAdmin} from "@/lib/f"; export async function POST(request,{params}){ const {id}=await params; const {user}=await auth(request); if(!isAdmin(user)) return Response.json({},{status:403}); await supabaseAdmin.from("notes").update({s:1}).eq("id",id); return Response.json({ok:true}); }`,
    "lib/f.ts": `export function isAdmin(u){ return true; }` }),

// ============ assumptions expostas (REQUISITO 5/6) ============
add("AS-01 self-scope declara assumptions", {
  handler: "CONTROLLED", reason: "CONTROLLED_SELF_SCOPE",
  assumptionsInclude: ["OWNER_COLUMN_CONVENTION", "SERVER_IDENTITY"],
}, GET(`const {user}=await auth(request); const {data}=await supabaseAdmin.from("notes").select("*").eq("user_id",user.id); return Response.json({data});`));

add("AS-02 RLS declarada vira assumption, não fato", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_DECLARED_OWNER",
  assumptionsInclude: ["RLS_DECLARED_BY_CONFIG"],
  rls: { profiles: "owner" },
}, GET(`const {id}=await params; const {user}=await supabaseAuth(request); const {data}=await supabaseAuthed.from("profiles").select("*").eq("id",id); return Response.json({data});`));
