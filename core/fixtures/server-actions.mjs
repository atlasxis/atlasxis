// Atlasxis — fixtures de certificação de server actions (Next.js "use server").
// Ground truth POR CONSTRUÇÃO: os argumentos de uma action exportada vêm de quem
// chama (Next.js orienta tratá-las como endpoints públicos); a identidade só
// vale se vier do servidor (auth()/supabase.auth.getUser()). NUNCA derivado do motor.
//
// expect: "action" → reason code esperado na decisão do sink (ou do handler).
// mustNot: "action" → status proibido. notAction: o arquivo NÃO pode ser tratado como actions.

const HEAD = `"use server";
import { createSupabaseAdminClient } from "@/lib/supabase-admin";
const supabaseAdmin = createSupabaseAdminClient();
`;
const ME = `const { data: { user } } = await supabase.auth.getUser();`;
const gate = (idExpr = "id") => `const { data: d } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", ${idExpr}).maybeSingle();
  if (!d) throw new Error("404");
  if (d.user_id !== user.id) throw new Error("403");`;
const LIB = { "lib/notes.ts": `export async function ensureOwnsNote(admin, uid, noteId) {
  const { data } = await admin.from("notes").select("id,user_id").eq("id", noteId).maybeSingle();
  if (!data) throw new Error("404");
  if (data.user_id !== uid) throw new Error("403");
  return data;
}` };

export const SERVER_ACTION_CASES = [
  // ---------------- POSITIVOS ----------------
  { id: "SP1-post-read-gate", kind: "positive",
    code: HEAD + `export async function archiveNote(id: string) { ${ME} ${gate()}
  await supabaseAdmin.from("notes").update({ archived: true }).eq("id", id); }`,
    expect: { archiveNote: "CONTROLLED_POST_READ_GATE" } },
  { id: "SP2-helper-ownership", kind: "positive", extra: LIB,
    code: `"use server";
import { ensureOwnsNote } from "@/lib/notes";
import { createSupabaseAdminClient } from "@/lib/supabase-admin";
const supabaseAdmin = createSupabaseAdminClient();
export async function deleteNote(id: string) { ${ME}
  await ensureOwnsNote(supabaseAdmin, user.id, id);
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    expect: { deleteNote: "CONTROLLED_OWNERSHIP_HELPER" } },
  { id: "SP3-self-scope", kind: "positive",
    code: HEAD + `export async function myNotes() { ${ME}
  const { data } = await supabaseAdmin.from("notes").select("*").eq("user_id", user.id); return data; }`,
    expect: { myNotes: "CONTROLLED_SELF_SCOPE" } },
  { id: "SP4-formdata-gate", kind: "positive",
    code: HEAD + `export async function archiveNote(formData: FormData) { ${ME}
  const id = formData.get("id") as string; ${gate()}
  await supabaseAdmin.from("notes").update({ archived: true }).eq("id", id); }`,
    expect: { archiveNote: "CONTROLLED_POST_READ_GATE" } },
  { id: "SP5-destructured-arg", kind: "positive",
    code: HEAD + `export async function renameNote({ id, title }: { id: string; title: string }) { ${ME} ${gate()}
  await supabaseAdmin.from("notes").update({ title }).eq("id", id); }`,
    expect: { renameNote: "CONTROLLED_POST_READ_GATE" } },
  { id: "SV1-idor-arg", kind: "positive",
    code: HEAD + `export async function deleteNote(id: string) {
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    expect: { deleteNote: "VULNERABLE_NO_GATING_SERVICE_ROLE" } },
  { id: "SV2-idor-formdata", kind: "positive",
    code: HEAD + `export async function deleteNote(formData: FormData) {
  const id = String(formData.get("id"));
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    expect: { deleteNote: "VULNERABLE_NO_GATING_SERVICE_ROLE" } },
  { id: "SV3-idor-arg-member", kind: "positive",
    code: HEAD + `export async function deleteNote(input: { id: string }) {
  await supabaseAdmin.from("notes").delete().eq("id", input.id); }`,
    expect: { deleteNote: "VULNERABLE_NO_GATING_SERVICE_ROLE" } },
  { id: "SV4-idor-arrow-export", kind: "positive",
    code: HEAD + `export const deleteNote = async (id: string) => {
  await supabaseAdmin.from("notes").delete().eq("id", id); };`,
    expect: { deleteNote: "VULNERABLE_NO_GATING_SERVICE_ROLE" } },

  // ---------------- NEGATIVOS ----------------
  { id: "SN1-no-exported-action", kind: "negative",
    code: HEAD + `async function helper(id: string) { await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    expect: { "?": "NOT_ANALYZED_NO_HANDLER" } },
  { id: "SN2-only-exported-analyzed", kind: "negative",
    code: HEAD + `async function internal(id: string) { await supabaseAdmin.from("notes").delete().eq("id", id); }
export async function myNotes() { ${ME}
  const { data } = await supabaseAdmin.from("notes").select("*").eq("user_id", user.id); return data; }`,
    expect: { myNotes: "CONTROLLED_SELF_SCOPE" }, onlyActions: ["myNotes"] },
  { id: "SN3-directive-after-import", kind: "negative", notAction: true,
    code: `import { x } from "y";
"use server";
export async function deleteNote(id: string) { await supabaseAdmin.from("notes").delete().eq("id", id); }` },
  { id: "SN4-wrapped-action", kind: "negative",
    code: HEAD + `export const deleteNote = withAuth(async (id: string) => {
  await supabaseAdmin.from("notes").delete().eq("id", id); });`,
    expect: { deleteNote: "NOT_ANALYZED_UNSUPPORTED_SYNTAX" } },
  { id: "SN5-use-client-file", kind: "negative", notAction: true,
    code: `"use client";
export async function deleteNote(id: string) { await supabaseAdmin.from("notes").delete().eq("id", id); }` },

  // ---------------- ADVERSARIAIS ----------------
  { id: "SA1-arg-named-user", kind: "adversarial",
    code: HEAD + `export async function deleteNote(user: { id: string }, id: string) { ${gate()}
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    mustNot: { deleteNote: "CONTROLLED" }, expect: { deleteNote: "INSUFFICIENT_IDENTITY_FROM_CLIENT" } },
  { id: "SA2-destructured-user", kind: "adversarial",
    code: HEAD + `export async function deleteNote({ user, id }) { ${gate()}
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    mustNot: { deleteNote: "CONTROLLED" }, expect: { deleteNote: "INSUFFICIENT_IDENTITY_FROM_CLIENT" } },
  { id: "SA3-session-from-formdata", kind: "adversarial",
    code: HEAD + `export async function deleteNote(formData: FormData) {
  const id = formData.get("id") as string;
  const session = { user: { id: formData.get("uid") } };
  const { data: d } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", id).maybeSingle();
  if (d.user_id !== session.user.id) throw new Error("403");
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    mustNot: { deleteNote: "CONTROLLED" } },
  { id: "SA4-check-a-write-b", kind: "adversarial",
    code: HEAD + `export async function moveNote(id: string, otherId: string) { ${ME} ${gate()}
  await supabaseAdmin.from("notes").delete().eq("id", otherId); }`,
    mustNot: { moveNote: "CONTROLLED" } },
  { id: "SA5-alias-arg", kind: "adversarial",
    code: HEAD + `export async function deleteNote(id: string) { ${ME} const target = id; ${gate()}
  await supabaseAdmin.from("notes").delete().eq("id", target); }`,
    mustNot: { deleteNote: "CONTROLLED" } },
  { id: "SA7-client-ref-insert", kind: "adversarial",
    code: HEAD + `export async function createMap({ name, campaign_id }) { ${ME}
  await supabaseAdmin.from("maps").insert({ name, campaign_id, user_id: user.id }); }`,
    mustNot: { createMap: "CONTROLLED" }, expect: { createMap: "INSUFFICIENT_CROSS_RESOURCE" } },
  { id: "SA8-client-ref-via-read", kind: "adversarial",
    code: HEAD + `export async function join(inviteId: string) { ${ME}
  const { data: invite } = await supabaseAdmin.from("invites").select().eq("id", inviteId).single();
  await supabaseAdmin.from("memberships").insert({ campaign_id: invite.campaign_id, user_id: user.id }); }`,
    mustNot: { join: "CONTROLLED" }, expect: { join: "INSUFFICIENT_CROSS_RESOURCE" } },
  { id: "SA9-mixed-clients-user-action", kind: "adversarial",
    code: `"use server";
export async function updateCampaign({ id, name }) { const supabase = createServerClient();
  await supabase.from("campaigns").update({ name }).eq("id", id); }
export async function createCampaign({ name }) { const supabaseAdmin = createSupabaseAdminClient(); ${ME}
  await supabaseAdmin.from("campaigns").insert({ name, user_id: user.id }); }`,
    mustNot: { updateCampaign: "VULNERABLE" }, expect: { updateCampaign: "INSUFFICIENT_RLS_UNKNOWN", createCampaign: "CONTROLLED_SELF_SCOPE" } },
  { id: "SV5-mixed-clients-admin-action", kind: "positive",
    code: `"use server";
export async function getMine() { const supabase = createServerClient(); ${ME}
  const { data } = await supabase.from("notes").select("*").eq("user_id", user.id); return data; }
export async function purgeNote(id: string) { const supabaseAdmin = createSupabaseAdminClient();
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    expect: { purgeNote: "VULNERABLE_NO_GATING_SERVICE_ROLE", getMine: "CONTROLLED_SELF_SCOPE" } },
  { id: "SA10-spread-overrides-owner", kind: "adversarial",
    code: HEAD + `export async function saveInvoice(invoiceData) { ${ME}
  await supabaseAdmin.from("invoices").insert({ user_id: user.id, ...invoiceData }); }`,
    mustNot: { saveInvoice: "CONTROLLED" }, expect: { saveInvoice: "INSUFFICIENT_OWNER_OVERRIDABLE" } },
  { id: "SA6-flag-not-owner", kind: "adversarial",
    code: HEAD + `export async function deleteNote(id: string) { ${ME}
  const { data: d } = await supabaseAdmin.from("notes").select("id,locked").eq("id", id).maybeSingle();
  if (d.locked) throw new Error("403");
  await supabaseAdmin.from("notes").delete().eq("id", id); }`,
    mustNot: { deleteNote: "CONTROLLED" } },
];

// mutações causais: remover o que sustenta a decisão TEM que derrubar o reason code
export const ACTION_MUTATORS = {
  CONTROLLED_POST_READ_GATE: [{ name: "remove checagem de dono", apply: (c) => c.replace(/if \(d\.user_id !== user\.id\) throw new Error\("403"\);/g, "") }],
  CONTROLLED_OWNERSHIP_HELPER: [{ name: "remove chamada do helper", apply: (c) => c.replace(/await ensureOwnsNote\([^)]*\);/g, "") }],
  CONTROLLED_SELF_SCOPE: [
    { name: "filtro de dono → argumento", apply: (c) => c.replace(/export async function myNotes\(\)/, "export async function myNotes(id: string)").replace(/\.eq\("user_id", user\.id\)/, `.eq("id", id)`) },
    { name: "insert sem dono", apply: (c) => c.replace(/user_id: user\.id/g, `user_id: "fixo"`) },
  ],
  VULNERABLE_NO_GATING_SERVICE_ROLE: [{ name: "adiciona checagem de dono", apply: (c) => c.replace(/await supabaseAdmin\.from\("notes"\)\.delete\(\)\.eq\("id", ([\w.]+)\);/, (m, idv) => `${ME} const { data: d } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", ${idv}).maybeSingle(); if (d.user_id !== user.id) throw new Error("403"); ${m}`) }],
  INSUFFICIENT_RLS_UNKNOWN: [],
};
