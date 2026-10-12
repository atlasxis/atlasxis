// Fixture pública sintética — app que fala com o Supabase direto do navegador
// (sem rotas de API). Toda a segurança depende do RLS e dos privilégios do banco.
// Esperado: `atlasxis scan` não encontra rotas; `atlasxis rls` audita as tabelas.
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export async function listMessages() {
  return supabase.from("messages").select("*");
}

export async function markDone(id: string) {
  return supabase.from("todos").update({ done: true }).eq("id", id);
}
