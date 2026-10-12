"use server";
// Fixture pública sintética — server actions (Next.js). Os argumentos vêm de
// quem chama a action. Esperado com --server-actions:
//   archiveNote → CONTROLLED (post-read gate)  ·  deleteNote → VULNERABLE (IDOR)
import { createSupabaseAdminClient } from "@/lib/supabase-admin";
import { createClient } from "@/lib/supabase-server";

const supabaseAdmin = createSupabaseAdminClient();

export async function archiveNote(id: string) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  const { data: note } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", id).maybeSingle();
  if (!note) throw new Error("404");
  if (note.user_id !== user.id) throw new Error("403");
  await supabaseAdmin.from("notes").update({ archived: true }).eq("id", id);
}

export async function deleteNote(formData: FormData) {
  const id = formData.get("id") as string;
  await supabaseAdmin.from("notes").delete().eq("id", id);
}
