// ORÁCULO CORE — explicações estáveis por reason code (FASE C do produto).
// Dados, não lógica: nada aqui decide status. A decisão vem do engine;
// este mapa apenas traduz (status, reasonCode) para linguagem humana.

export const EXPLANATIONS = Object.freeze({
  // ---- CONTROLLED — evidência suficiente de autorização ----
  CONTROLLED_SELF_SCOPE: {
    status: "CONTROLLED",
    meaning: "O sink opera exclusivamente sobre dados do próprio usuário autenticado.",
    proven: "A identidade do servidor (user.id) delimita o recurso no próprio sink (ex.: .eq('user_id', user.id)).",
    not_proven: "Nada além deste caminho; outros sinks têm decisão própria.",
  },
  CONTROLLED_OWNERSHIP_HELPER: {
    status: "CONTROLLED",
    meaning: "Um helper de ownership verificado (cross-file) prova que o usuário é dono/participante do recurso antes do sink.",
    proven: "Cadeia: identidade do servidor → helper resolvido → verificação de posse sobre o MESMO recurso do sink → rejeição no caminho negativo.",
    not_proven: "Autorização de outros recursos tocados pelo handler.",
  },
  CONTROLLED_OWNERSHIP_INLINE: {
    status: "CONTROLLED",
    meaning: "Verificação de posse/participação feita inline no handler, antes do sink, sobre o mesmo recurso.",
    proven: "Leitura do recurso + comparação com user.id + rejeição no caminho negativo, dominando o sink.",
    not_proven: "Autorização de recursos distintos do verificado.",
  },
  CONTROLLED_POST_READ_GATE: {
    status: "CONTROLLED",
    meaning: "O recurso é lido primeiro e um gate compara o dono ao usuário autenticado antes de qualquer efeito.",
    proven: "Identidade recurso lido = recurso do sink; gate rejeita quando o dono difere.",
    not_proven: "Nada além deste caminho.",
  },
  CONTROLLED_TRANSITIVE_OWNERSHIP: {
    status: "CONTROLLED",
    meaning: "Posse provada transitivamente (ex.: dono do pai autoriza operação no filho) com testemunhas estruturais.",
    proven: "Cadeia pai→filho com identidade de recurso preservada e gate vivo.",
    not_proven: "Relações não modeladas entre outros recursos.",
  },
  CONTROLLED_RLS_DECLARED_OWNER: {
    status: "CONTROLLED",
    meaning: "RLS declarada pelo projeto como owner-scoped cobre o sink (cliente authenticated).",
    proven: "Declaração explícita de RLS por dono para a tabela do sink, cliente sujeito a RLS.",
    not_proven: "A política real do banco em produção (evidência é declarativa).",
  },
  CONTROLLED_RLS_POLICY_OWNER: {
    status: "CONTROLLED",
    meaning: "Política RLS parseada das migrações prova escopo por dono (auth.uid()) para a operação do sink.",
    proven: "ENABLE RLS + política aplicável à operação com predicado de posse; cliente sujeito a RLS.",
    not_proven: "Alterações de política fora do corpus SQL fornecido.",
  },

  // ---- VULNERABLE — evidência positiva de caminho sem autorização ----
  VULNERABLE_NO_GATING_SERVICE_ROLE: {
    status: "VULNERABLE",
    meaning: "Entrada controlável pelo cliente alcança um sink via service_role (bypassa RLS) sem NENHUM gating vivo no caminho.",
    proven: "Fonte controlável → recurso → sink service_role; ausência comprovada de qualquer verificação que rejeite.",
    not_proven: "Exploração em runtime (a prova é estrutural, não um exploit executado).",
  },
  VULNERABLE_RLS_DISABLED_DEFAULT_GRANTS: {
    status: "VULNERABLE",
    meaning: "RLS desabilitada na tabela com grants default do Supabase: qualquer authenticated lê/escreve linhas de terceiros.",
    proven: "Migração com RLS disabled + grants default + sink alcançável com id controlável e sem gate no app.",
    not_proven: "Revogações de grant fora do corpus SQL fornecido.",
  },

  // ---- INSUFFICIENT — não foi possível provar (nunca significa SAFE) ----
  INSUFFICIENT_RLS_UNKNOWN: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Cliente sujeito a RLS, mas nenhuma evidência de política foi fornecida ou encontrada.",
    proven: "Só o caminho até o sink.",
    not_proven: "Existência e conteúdo da política RLS da tabela.",
  },
  INSUFFICIENT_RLS_DECLARED_COMPLEX: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "RLS declarada, porém com semântica complexa demais para prova estrutural.",
    proven: "Que existe declaração de RLS.",
    not_proven: "Que a política restringe ao dono para ESTA operação.",
  },
  INSUFFICIENT_RLS_POLICY_UNPROVEN: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Política RLS parseada, mas o predicado não prova escopo por dono (ex.: USING (true) ou expressão não modelada).",
    proven: "Que a política existe e foi lida.",
    not_proven: "Que ela restringe o acesso ao dono.",
  },
  INSUFFICIENT_RLS_ABSENT: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Corpus SQL fornecido não contém política para a tabela do sink.",
    proven: "Ausência de política NO CORPUS (não no banco).",
    not_proven: "Estado real do banco; pode haver política criada fora das migrações.",
  },
  INSUFFICIENT_RLS_AMBIGUOUS: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Políticas da tabela recriadas com definições conflitantes; ordem de migração incerta.",
    proven: "Que há definições conflitantes.",
    not_proven: "Qual definição vale em produção.",
  },
  INSUFFICIENT_RESOURCE_IDENTITY: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Há verificação de autorização, mas sobre recurso cuja identidade não coincide comprovadamente com a do sink.",
    proven: "Que existe um check e existe um sink.",
    not_proven: "Que o recurso verificado É o recurso escrito/lido.",
  },
  INSUFFICIENT_CROSS_RESOURCE: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Autorização provada para um recurso, mas o sink opera sobre OUTRO recurso.",
    proven: "Autorização do recurso A.",
    not_proven: "Autorização do recurso B (o do sink).",
  },
  INSUFFICIENT_ALIAS_RESOLUTION: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Não foi possível resolver estruturalmente um alias/expressão de id até a fonte.",
    proven: "O caminho sintático até o ponto de perda.",
    not_proven: "Que o id verificado e o id do sink são o mesmo valor.",
  },
  INSUFFICIENT_TRANSITIVE_OWNERSHIP: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Cadeia transitiva de posse (pai→filho) incompleta: falta testemunha estrutural de um elo.",
    proven: "Parte da cadeia.",
    not_proven: "O elo que liga o recurso autorizado ao recurso do sink.",
  },
  INSUFFICIENT_GUARD_UNRESOLVED: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Existe um guard no caminho, mas seu efeito não pôde ser resolvido (ex.: helper não encontrado/ambíguo).",
    proven: "Que um guard é invocado.",
    not_proven: "Que o guard rejeita acesso não autorizado.",
  },
  INSUFFICIENT_CROSS_FILE_EVIDENCE: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "A prova depende de código em arquivo não fornecido ou não resolvido.",
    proven: "O que existe no arquivo analisado.",
    not_proven: "O comportamento do símbolo externo do qual a autorização depende.",
  },
  INSUFFICIENT_UNRESOLVED_GATING: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Há gating vivo no caminho que impede afirmar VULNERABLE, mas ele não prova autorização por dono.",
    proven: "Que ALGO pode rejeitar a requisição.",
    not_proven: "Que esse algo é controle de autorização do recurso do sink.",
  },
  INSUFFICIENT_ADMIN_GUARD_UNPROVEN: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Handler aparenta ser admin, mas o guard de role não foi estruturalmente provado.",
    proven: "Indícios nominais/estruturais parciais.",
    not_proven: "Que apenas admins alcançam o sink.",
  },
  INSUFFICIENT_ANALYSIS_ERROR: {
    status: "INSUFFICIENT_EVIDENCE",
    meaning: "Erro interno durante a análise deste handler; por segurança o resultado é abstenção, nunca SAFE.",
    proven: "Nada.",
    not_proven: "Tudo — trate como não analisado.",
  },

  // ---- NOT_ANALYZED — fora do que o motor modela (nunca significa SAFE) ----
  NOT_ANALYZED_NO_HANDLER: {
    status: "NOT_ANALYZED",
    meaning: "Nenhum handler HTTP exportado reconhecível no arquivo de rota.",
    proven: "—", not_proven: "Qualquer propriedade de autorização.",
  },
  NOT_ANALYZED_NO_SINK: {
    status: "NOT_ANALYZED",
    meaning: "Handler sem sink de dados modelado (nenhuma operação de leitura/escrita reconhecida).",
    proven: "—", not_proven: "Efeitos por mecanismos não modelados (fetch externo, fs, etc.).",
  },
  NOT_ANALYZED_NO_CLIENT_RESOURCE_ID: {
    status: "NOT_ANALYZED",
    meaning: "Sink sem id de recurso controlável rastreável — o modelo exige (cliente, recurso, id) para decidir.",
    proven: "—", not_proven: "Autorização deste sink; revisão humana necessária.",
  },
  NOT_ANALYZED_UNSUPPORTED_SYNTAX: {
    status: "NOT_ANALYZED",
    meaning: "Padrão sintático fora do suportado (ex.: wrappers dinâmicos, metaprogramação).",
    proven: "—", not_proven: "Qualquer propriedade; o código precisa de revisão humana.",
  },
  NOT_ANALYZED_DISCOVERY: {
    status: "NOT_ANALYZED",
    meaning: "Arquivo descoberto mas não classificado pelo pipeline de análise.",
    proven: "—", not_proven: "Qualquer propriedade.",
  },
  NOT_ANALYZED_PARSE_ERROR: {
    status: "NOT_ANALYZED",
    meaning: "O parser não conseguiu processar o arquivo (malformado, encoding, ou crash recuperado).",
    proven: "—", not_proven: "Qualquer propriedade; o arquivo precisa de revisão humana.",
  },

  // ---- OUT_OF_SCOPE ----
  OOS_PROVEN_ADMIN_HELPER: {
    status: "OUT_OF_SCOPE_PROVEN",
    meaning: "Handler provadamente restrito a admin via helper estrutural; autorização por dono não se aplica.",
    proven: "Que só admins alcançam os sinks.",
    not_proven: "Que a operação de admin em si é desejável (política, não prova).",
  },
  OOS_PROVEN_ADMIN_INLINE_ROLE_GATE: {
    status: "OUT_OF_SCOPE_PROVEN",
    meaning: "Role-gate inline provado domina todos os sinks; rota é efetivamente admin-only.",
    proven: "Que o gate de role rejeita não-admins antes de qualquer sink.",
    not_proven: "A adequação da política de admin.",
  },
  OOS_PROVEN_WEBHOOK_SIGNATURE: {
    status: "OUT_OF_SCOPE_PROVEN",
    meaning: "Webhook com verificação de assinatura provada; modelo de autorização por usuário não se aplica.",
    proven: "Que a assinatura é verificada antes dos efeitos.",
    not_proven: "A segurança do segredo compartilhado.",
  },
  OUT_OF_SCOPE_UNVERIFIED_ADMIN: {
    status: "OUT_OF_SCOPE_UNVERIFIED",
    meaning: "Rota aparenta ser admin (path/nome), mas o gate NÃO foi provado — não tratar como segura.",
    proven: "Apenas o indício nominal.",
    not_proven: "Que não-admins são rejeitados.",
  },
  OUT_OF_SCOPE_UNVERIFIED_WEBHOOK: {
    status: "OUT_OF_SCOPE_UNVERIFIED",
    meaning: "Rota aparenta ser webhook, mas a verificação de assinatura NÃO foi provada — não tratar como segura.",
    proven: "Apenas o indício nominal.",
    not_proven: "Que chamadas não assinadas são rejeitadas.",
  },
});
