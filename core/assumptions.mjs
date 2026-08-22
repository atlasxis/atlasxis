// ORÁCULO CORE — catálogo de assumptions explícitas (REQUISITOS 5 e 6).
// Toda regra semântica que depende de convenção (não de prova estrutural)
// vira uma assumption identificada e registrada na ProofChain da decisão.
// Uma assumption nunca é silenciosamente convertida em fato.

export const ASSUMPTION = Object.freeze({
  SERVER_IDENTITY: {
    id: "SERVER_IDENTITY",
    text: "user.id / session.user.id é identidade autenticada derivada no servidor (não controlável pelo cliente)",
  },
  OWNER_COLUMN_CONVENTION: {
    id: "OWNER_COLUMN_CONVENTION",
    text: "colunas no conjunto declarado (user_id, owner_id, created_by, sender_id, profile_id, author_id, requester_id, reporter_id, blocker_id) representam ownership do registro",
  },
  CONTAINER_COLUMN_CONVENTION: {
    id: "CONTAINER_COLUMN_CONVENTION",
    text: "colunas no conjunto declarado (conversation_id, post_id, comment_id, id) identificam o recurso/container alvo",
  },
  CLIENT_KIND_BY_API_NAME: {
    id: "CLIENT_KIND_BY_API_NAME",
    text: "o tipo do client Supabase é inferido por nomes de API/variável convencionais (service_role, createSupabaseAdminClient, supabaseAdmin, createServerClient, createRouteHandlerClient)",
  },
  SERVICE_ROLE_BYPASSES_RLS: {
    id: "SERVICE_ROLE_BYPASSES_RLS",
    text: "um client service_role bypassa RLS (semântica documentada do Supabase), logo a autorização precisa existir no código da aplicação",
  },
  RLS_DECLARED_BY_CONFIG: {
    id: "RLS_DECLARED_BY_CONFIG",
    text: "o modo RLS da tabela veio de configuração declarada externamente (não de parsing de policies — FASE 4 pendente); a prova é condicional a essa declaração",
  },
  ADMIN_HELPER_NAME_CONVENTION: {
    id: "ADMIN_HELPER_NAME_CONVENTION",
    text: "helpers nomeados requireAdmin* são candidatos a guard administrativo; a prova ainda exige estrutura (consulta role + rejeição antes do sink)",
  },
  OWNERSHIP_GRANTS_ACCESS: {
    id: "OWNERSHIP_GRANTS_ACCESS",
    text: "o dono/participante do recurso está autorizado a operar sobre ele (modelo de autorização da classe analisada)",
  },
  ADMIN_ROLE_GRANTS_ACCESS: {
    id: "ADMIN_ROLE_GRANTS_ACCESS",
    text: "role === 'admin' autoriza a operação (bypass administrativo aceito pelo modelo)",
  },
  MEMBERSHIP_GRANTS_ACCESS: {
    id: "MEMBERSHIP_GRANTS_ACCESS",
    text: "membership provada no recurso relacionado autoriza operar no recurso alvo (autorização relacional)",
  },
  SUPABASE_AUTH_UID_SEMANTICS: {
    id: "SUPABASE_AUTH_UID_SEMANTICS",
    text: "auth.uid() em policies RLS retorna a identidade autenticada do request (semântica documentada do Supabase/PostgREST)",
  },
  SUPABASE_DEFAULT_GRANTS: {
    id: "SUPABASE_DEFAULT_GRANTS",
    text: "OPT-IN explícito: os grants default do Supabase dão acesso total ao role authenticated quando RLS está desabilitada; grants customizados não foram analisados",
  },
  SHARED_SECRET_VERIFIES_CALLER: {
    id: "SHARED_SECRET_VERIFIES_CALLER",
    text: "comparação estrutural de header/assinatura contra segredo de ambiente autentica o caller do webhook (fora do escopo IDOR-usuário)",
  },
});

export const A = Object.freeze(
  Object.fromEntries(Object.keys(ASSUMPTION).map((k) => [k, k]))
);

export function assumptionRefs(ids) {
  return [...new Set(ids)].map((id) => {
    if (!ASSUMPTION[id]) throw new Error("assumption desconhecida: " + id);
    return { id, text: ASSUMPTION[id].text };
  });
}
