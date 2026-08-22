// Fixture pública sintética — mecanismo: parent-child ownership.
// Esperado: CONTROLLED (dono do recurso-pai modera o recurso-filho).
import { auth } from "@/lib/auth";

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { user, supabaseAdmin } = await auth(request);
  const { data: comment } = await supabaseAdmin.from("note_comments").select("id,note_id").eq("id", id).maybeSingle();
  if (!comment) throw new Error("404");
  const { data: note } = await supabaseAdmin.from("notes").select("id,user_id").eq("id", comment.note_id).maybeSingle();
  if (note?.user_id !== user.id) throw new Error("403");
  await supabaseAdmin.from("note_comments").update({ status: "removed" }).eq("id", id);
  return Response.json({ ok: true });
}
