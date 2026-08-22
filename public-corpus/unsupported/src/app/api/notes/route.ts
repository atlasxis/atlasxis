// Fixture pública sintética — mecanismo: wrapper dinâmico não suportado.
// Esperado: NOT_ANALYZED (abstenção correta; NUNCA CONTROLLED).
import { withAuth } from "@/lib/wrap";

export const GET = withAuth(async (req: Request) => {
  const { supabaseAdmin } = req as any;
  const { data } = await supabaseAdmin.from("notes").select("*");
  return Response.json({ data });
});
