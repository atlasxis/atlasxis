// Fixture pública sintética — mecanismo: role-gate inline de admin.
// Esperado: OUT_OF_SCOPE_PROVEN (autorização por dono não se aplica a admin).
import { auth } from "@/lib/auth";

export async function POST(request: Request, { params }: { params: { id: string } }) {
  const { id } = await params;
  const { user, supabaseAdmin } = await auth(request);
  const { data: profile } = await supabaseAdmin.from("profiles").select("role").eq("id", user.id).single();
  if (!profile || profile.role !== "admin") return Response.json({}, { status: 403 });
  await supabaseAdmin.from("notes").update({ featured: true }).eq("id", id);
  return Response.json({ ok: true });
}
