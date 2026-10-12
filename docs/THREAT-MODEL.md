# Atlasxis — Modelo de ameaça e segurança do próprio motor

## O que o Atlasxis garante e o que NÃO garante

- **Garante**: quando emite `CONTROLLED`, existe uma ProofChain estrutural
  reproduzível (source → resource → authorization → guard → identity → sink)
  cujo componente de identidade prova que o recurso verificado é o recurso que
  chega ao sink. Quando emite `VULNERABLE`, existe um evidence trace de fluxo
  não autorizado alcançável.
- **NÃO garante**: ausência de vulnerabilidades. Tudo que não é `CONTROLLED`
  permanece explicitamente não certificado. `INSUFFICIENT`/`NOT_ANALYZED`/
  `OUT_OF_SCOPE_*` nunca significam seguro.

## Fronteiras de confiança do modelo

1. **Identidade do servidor** (`SERVER_IDENTITY`): assume-se que `user.id`/
   `auth.uid()` são derivados no servidor e não controláveis pelo cliente. Se o
   provedor de auth for comprometido, a premissa cai — declarado na prova.
2. **service_role bypassa RLS** (`SERVICE_ROLE_BYPASSES_RLS`): propriedade
   documentada do Supabase; usada só para exigir autorização na aplicação, nunca
   para provar ownership.
3. **Convenção de coluna owner** (`OWNER_COLUMN_CONVENTION`): um campo comparado
   à identidade autenticada é tratado como ownership APÓS ser lido do recurso —
   nome sozinho nunca prova (ver mutation M06).
4. **RLS declarada** vs **RLS parseada**: a FASE 4 parseia policies reais; o modo
   declarado manual é fallback com assumption `RLS_DECLARED_BY_CONFIG`.

## Ameaças à validade das conclusões

- **Semântica não modelada**: ORMs próprios, RPC, views, triggers, GRANTs de
  tabela → o motor abstém (`NOT_ANALYZED`), nunca inventa.
- **Predicados em lambda** (`.some(r => r.role==='admin')`): não modelados → abstém.
- **Alias por dataflow profundo**: detectado e classificado, nunca vira CONTROLLED.
- **Truth table ≤14 átomos**: condições maiores não são provadas (fail-closed).

## Segurança do próprio Atlasxis

- **Somente leitura**: o motor nunca escreve no código analisado.
- **Sem execução do alvo**: análise estática por AST; não executa o código.
- **Determinístico**: mesma entrada → mesma saída, sem rede, sem estado.
- **Sandboxing de conteúdo**: nomes, comentários e strings do código analisado
  são DADOS, nunca prova nem instrução (corpus adversarial cobre isso).
- **Sem dependência de LLM na decisão**: o núcleo é determinístico; nenhum
  modelo probabilístico participa da prova.
