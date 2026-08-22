// Fixture pública sintética — mecanismo: post-read ownership gate.
// Esperado: CONTROLLED (CONTROLLED_POST_READ_GATE).
// Lê o recurso, compara o dono com o usuário e rejeita antes de escrever.
import { auth } from "@/lib/auth";

export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { user, supabaseAdmin } = await auth(request);
  const { data: note } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", id).maybeSingle();
  if (!note) throw new Error("404");
  if (note.user_id !== user.id) throw new Error("403");
  await supabaseAdmin.from("notes").update({ pinned: true }).eq("id", id);
  return Response.json({ ok: true });
}
