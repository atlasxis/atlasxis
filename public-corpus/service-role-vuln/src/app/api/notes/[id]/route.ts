// Fixture pública sintética — mecanismo: IDOR via service_role sem gating.
// Esperado: VULNERABLE (VULNERABLE_NO_GATING_SERVICE_ROLE).
// Evidência POSITIVA: id controlável → sink service_role, sem guard vivo.
import { auth } from "@/lib/auth";

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { supabaseAdmin } = await auth(request);
  await supabaseAdmin.from("notes").delete().eq("id", id);
  return Response.json({ ok: true });
}
