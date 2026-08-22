// ORÁCULO CORE — fixtures da FASE 4 (RLS parseada como evidência).
// Cada fixture: { n, handler, reason?, assumptionsInclude?, sql:{arquivo:conteúdo},
// defaultGrants?, files, entry }. O harness monta o RlsModel via parseSqlCorpus.

const AUTH = (b) => `export async function GET(request,{params}){ const {id}=await params; const {user}=await supabaseAuth(request); ${b} }`;
const AUTHW = (m, b) => `export async function ${m}(request,{params}){ const {id}=await params; const {user}=await supabaseAuth(request); ${b} }`;

const SEL = `const {data}=await supabaseAuthed.from("notes").select("*").eq("id",id); return Response.json({data});`;
const UPD = `await supabaseAuthed.from("notes").update({t:1}).eq("id",id); return Response.json({ok:true});`;
const DEL = `await supabaseAuthed.from("notes").delete().eq("id",id); return Response.json({ok:true});`;

const NOTES = `create table public.notes ( id uuid primary key, user_id uuid references auth.users(id), content text );`;
const EN = `alter table public.notes enable row level security;`;

export const FIXTURES = [];
const add = (n, spec) => FIXTURES.push({ n, ...spec, entry: spec.entry || "route.ts" });

// ---------- positivas ----------
add("F4-01 policy owner FOR SELECT → prova parseada", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  assumptionsInclude: ["SUPABASE_AUTH_UID_SEMANTICS"],
  sql: { "schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using (auth.uid() = user_id);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-02 ordem invertida + casts + (select auth.uid())", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using ( (user_id::text) = ((select auth.uid()))::text );` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-07 UPDATE com USING owner sem WITH CHECK (herda USING)", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": NOTES + EN + `create policy notes_upd on public.notes for update using (auth.uid() = user_id);` },
  files: { "route.ts": AUTHW("POST", UPD) },
});
add("F4-13 owner OR is_admin() resolvida no corpus SQL", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": `create or replace function public.is_admin() returns boolean language sql as $$ select exists ( select 1 from public.profiles where id = auth.uid() and role = 'admin' ); $$;` + NOTES + EN + `create policy notes_sel on public.notes for select using (user_id = auth.uid() or public.is_admin());` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-15 participação: requester OR recipient = auth.uid()", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": `create table public.notes ( id uuid primary key, requester_id uuid, recipient_id uuid );` + EN + `create policy notes_sel on public.notes for select using (requester_id = auth.uid() or recipient_id = auth.uid());` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-18 DELETE coberto por FOR ALL owner", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": NOTES + EN + `create policy notes_all on public.notes for all using (auth.uid() = user_id);` },
  files: { "route.ts": AUTHW("DELETE", DEL) },
});
add("F4-05 restritiva owner + permissiva true → AND restritivo prova", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": NOTES + EN + `create policy notes_open on public.notes for select using (true); create policy notes_own on public.notes as restrictive for select using (auth.uid() = user_id);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-20 DROP + CREATE idempotente não é ambiguidade", {
  handler: "CONTROLLED", reason: "CONTROLLED_RLS_POLICY_OWNER",
  sql: { "schema.sql": NOTES + EN + `drop policy if exists notes_sel on public.notes; create policy notes_sel on public.notes for select using (auth.uid() = user_id);`,
         "fix.sql": `drop policy if exists notes_sel on public.notes; create policy notes_sel on public.notes for select using (auth.uid() = user_id);` },
  files: { "route.ts": AUTH(SEL) },
});

// ---------- negativas / adversariais (fail-closed) ----------
add("F4-03 USING(true) nunca prova", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_open on public.notes for select using (true);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-04 permissiva owner + permissiva true → OR permissivo vaza", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_own on public.notes for select using (auth.uid() = user_id); create policy notes_open on public.notes for select using (true);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-06 policy só FOR SELECT não cobre update", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using (auth.uid() = user_id);` },
  files: { "route.ts": AUTHW("POST", UPD) },
});
add("F4-08 INSERT em container não é provado por owner-policy", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": `create table public.reports ( id uuid primary key, conversation_id uuid, user_id uuid );` + `alter table public.reports enable row level security;` + `create policy rep_ins on public.reports for insert with check (auth.uid() = user_id);` },
  files: { "route.ts": `export async function POST(request,{params}){ const {conversationId}=await params; const {user}=await supabaseAuth(request); await supabaseAuthed.from("reports").insert({conversation_id:conversationId,user_id:user.id}); return Response.json({ok:true}); }` },
});
add("F4-09 service_role bypassa RLS mesmo com policy owner", {
  handler: "VULNERABLE", reason: "VULNERABLE_NO_GATING_SERVICE_ROLE",
  sql: { "schema.sql": NOTES + EN + `create policy notes_all on public.notes for all using (auth.uid() = user_id);` },
  files: { "route.ts": `export async function DELETE(request,{params}){ const {id}=await params; const {user}=await auth(request); await supabaseAdmin.from("notes").delete().eq("id",id); return Response.json({ok:true}); }` },
});
add("F4-12 policy TO service_role não cobre authenticated", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_sr on public.notes for select to service_role using (auth.uid() = user_id);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-14 owner OR função NÃO resolvível não prova", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using (user_id = auth.uid() or public.mystery_check());` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-16 policy recriada conflitante entre arquivos → ambíguo", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_AMBIGUOUS",
  sql: { "a_schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using (auth.uid() = user_id);`,
         "b_later.sql": `create policy notes_sel on public.notes for select using (true);` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-21 EXISTS/subquery é unproven (fail-closed)", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_sel on public.notes for select using (exists (select 1 from public.members m where m.note_id = id and m.user_id = auth.uid()));` },
  files: { "route.ts": AUTH(SEL) },
});

add("F4-22 UPDATE com USING owner mas WITH CHECK aberto → não prova", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_POLICY_UNPROVEN",
  sql: { "schema.sql": NOTES + EN + `create policy notes_upd on public.notes for update using (auth.uid() = user_id) with check (true);` },
  files: { "route.ts": AUTHW("POST", UPD) },
});
add("F4-23 upsert nunca certificado por policy", {
  handler: "INSUFFICIENT_EVIDENCE",
  sql: { "schema.sql": NOTES + EN + `create policy notes_all on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);` },
  files: { "route.ts": `export async function POST(request,{params}){ const {id}=await params; const {user}=await supabaseAuth(request); await supabaseAuthed.from("notes").upsert({id:id,t:1}); return Response.json({ok:true}); }` },
});

// ---------- RLS desabilitada ----------
add("F4-10 RLS desabilitada → INSUFFICIENT_RLS_ABSENT (default)", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_ABSENT",
  sql: { "schema.sql": NOTES },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-11 RLS desabilitada + opt-in default grants → VULNERABLE", {
  handler: "VULNERABLE", reason: "VULNERABLE_RLS_DISABLED_DEFAULT_GRANTS",
  assumptionsInclude: ["SUPABASE_DEFAULT_GRANTS"],
  defaultGrants: true,
  sql: { "schema.sql": NOTES },
  files: { "route.ts": AUTH(SEL) },
});

// ---------- UNKNOWN / regressão ----------
add("F4-17 tabela fora do schema parcial → fallback RLS_UNKNOWN", {
  handler: "INSUFFICIENT_EVIDENCE", reason: "INSUFFICIENT_RLS_UNKNOWN",
  sql: { "schema.sql": `create table public.outra ( id uuid primary key );` },
  files: { "route.ts": AUTH(SEL) },
});
add("F4-19 código prova ownership quando policy é unproven", {
  handler: "CONTROLLED", reason: "CONTROLLED_POST_READ_GATE",
  sql: { "schema.sql": NOTES + EN + `create policy notes_open on public.notes for select using (true); create policy notes_upd on public.notes for update using (true);` },
  files: { "route.ts": `export async function POST(request,{params}){ const {id}=await params; const {user}=await supabaseAuth(request); const {data:note}=await supabaseAuthed.from("notes").select("id,user_id").eq("id",id).maybeSingle(); if(note.user_id!==user.id) throw new Error("403"); await supabaseAuthed.from("notes").update({t:1}).eq("id",id); return Response.json({ok:true}); }` },
});
