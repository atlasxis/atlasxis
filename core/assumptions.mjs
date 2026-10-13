// Atlasxis — catálogo de assumptions explícitas (REQUISITOS 5 e 6).
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
  CLIENT_KIND_BY_IMPORTED_DEFINITION: {
    id: "CLIENT_KIND_BY_IMPORTED_DEFINITION",
    text: "o tipo do client Supabase veio da definição exportada em outro arquivo do projeto (import resolvido sem ambiguidade): chave service_role → service_role; createServerClient/createRouteHandlerClient → authenticated; ambas ou nenhuma → desconhecido",
  },
  EXPRESS_CHAIN_STATIC: {
    id: "EXPRESS_CHAIN_STATIC",
    text: "a cadeia de middleware da rota Express é a registrada estaticamente (app.use/router.use/rota), na ordem do código; middleware adicionado em tempo de execução não é visto",
  },
  WRAPPER_PASSES_THROUGH: {
    id: "WRAPPER_PASSES_THROUGH",
    text: "um wrapper de handler (ex.: asyncHandler(fn)) executa a função recebida com os mesmos req/res, sem alterar a autorização",
  },
  OWNER_FIELD_BOUND_TO_IDENTITY: {
    id: "OWNER_FIELD_BOUND_TO_IDENTITY",
    text: "um campo do filtro Prisma ligado à identidade verificada do principal restringe o acesso aos registros desse principal",
  },
  SCHEMA_RELATION_IS_OWNERSHIP: {
    id: "SCHEMA_RELATION_IS_OWNERSHIP",
    text: "uma relação (chave estrangeira) do modelo para o modelo do principal no schema Prisma indica que o registro pertence a um principal desse tipo",
  },
  PRINCIPAL_MODEL_BY_NAME: {
    id: "PRINCIPAL_MODEL_BY_NAME",
    text: "o modelo Prisma do principal foi inferido pelo nome do campo de identidade (req.professional ↔ Professional), não por uma leitura no middleware",
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
    text: "OPT-IN explícito: o projeto usa os grants padrão antigos do Supabase (select/insert/update/delete para anon e authenticated nas tabelas do schema public). O Supabase desligou esse padrão para projetos novos em 30/05/2026 e para tabelas novas de projetos existentes em 30/10/2026; tabelas antigas mantêm os grants",
  },
  SERVER_ACTION_IS_PUBLIC_ENDPOINT: {
    id: "SERVER_ACTION_IS_PUBLIC_ENDPOINT",
    text: "toda função async exportada de um arquivo \"use server\" pode ser chamada por qualquer cliente, com quaisquer argumentos (o Next.js orienta tratar server actions como endpoints públicos)",
  },
  RLS_CORPUS_COMPLETE: {
    id: "RLS_CORPUS_COMPLETE",
    text: "o SQL analisado (migrações) reflete o banco de produção; RLS, policies ou grants alterados fora dele (por exemplo, pelo dashboard) não foram vistos",
  },
  SCHEMA_DUMP_IS_PRODUCTION: {
    id: "SCHEMA_DUMP_IS_PRODUCTION",
    text: "o arquivo indicado em --schema-dump é um dump completo e atual do schema de produção, com privilégios (pg_dump sem -x / supabase db dump)",
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
