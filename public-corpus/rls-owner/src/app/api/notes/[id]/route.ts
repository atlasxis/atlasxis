// Fixture pública sintética — mecanismo: RLS owner-scoped (cliente authenticated).
// Esperado: CONTROLLED (CONTROLLED_RLS_POLICY_OWNER) com o SQL de supabase/.
import { authClient } from "@/lib/auth";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { supabaseAuthed } = await authClient(request);
  const { data } = await supabaseAuthed.from("notes").select("*").eq("id", id);
  return Response.json({ data });
}
