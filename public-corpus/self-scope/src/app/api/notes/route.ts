// Fixture pública sintética — mecanismo: self-scope.
// Esperado: CONTROLLED (CONTROLLED_SELF_SCOPE).
// O sink é delimitado pela identidade do servidor no próprio sink.
import { auth } from "@/lib/auth";

export async function GET(request: Request) {
  const { user, supabaseAdmin } = await auth(request);
  const { data } = await supabaseAdmin.from("notes").select("*").eq("user_id", user.id);
  return Response.json({ data });
}
