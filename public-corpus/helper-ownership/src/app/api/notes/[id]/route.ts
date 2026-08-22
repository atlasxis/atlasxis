// Fixture pública sintética — mecanismo: ownership via helper importado.
// Esperado: CONTROLLED (CONTROLLED_OWNERSHIP_HELPER).
import { ensureOwnsNote } from "@/lib/notes";
import { auth } from "@/lib/auth";

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { user, supabaseAdmin } = await auth(request);
  await ensureOwnsNote(supabaseAdmin, user.id, id);
  await supabaseAdmin.from("notes").delete().eq("id", id);
  return Response.json({ ok: true });
}
