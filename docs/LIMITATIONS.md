# LIMITATIONS — o que o Atlasxis v1 NÃO prova (reportado explicitamente)

Correção > cobertura. Estas são fronteiras conhecidas onde o motor abstém em vez
de arriscar um false-control. Nenhuma é escondida.

## Semânticas fora do alcance (viram INSUFFICIENT / NOT_ANALYZED)

1. **ORMs não-Supabase** (Prisma, Drizzle, TypeORM): sinks não `.from().op().eq()`
   não são modelados → `NOT_ANALYZED`. Observado em dub, taxonomy, supabase-monorepo.
2. **Predicados em lambda**: `userRoles.some(r => r.role === "admin")` — o gate
   admin dentro de `.some()` não é modelado (corpus-externo `forum/posts/pin` fica INSUFFICIENT).
3. **RLS por EXISTS/subquery**: policies de participação via `exists(select ...)`
   (ex.: `private_messages` do projeto-auditado-privado) não são provadas — é a fronteira que
   a FASE 9 (Evidence Graph) deve fechar.
4. **Alias por dataflow profundo**: `const x = id; sink(x)` é detectado e
   classificado (`INSUFFICIENT_ALIAS_RESOLUTION`), nunca resolvido para CONTROLLED.
5. **Truth table > 14 átomos**: condições booleanas muito grandes não são
   verificadas → fail-closed.
6. **GRANTs de tabela**: RLS desabilitada não vira VULNERABLE por default
   (`INSUFFICIENT_RLS_ABSENT`) — grants não são analisados; VULNERABLE exige o
   opt-in `SUPABASE_DEFAULT_GRANTS`.
7. **auth/session flows, webhooks sem verificação estrutural, views, triggers,
   RPC**: fora do modelo → abstenção.

## Limites de recall (por design)

- **Recall de CONTROLLED**: ~90% no benchmark construído; menor em código real
  com arquiteturas não-Supabase (por exemplo dub, quase tudo NOT_ANALYZED).
- **Recall de VULNERABLE**: não mensurável sem ground truth de RLS por repo. O
  motor não emite VULNERABLE sob incerteza de RLS.

## Limites de processo

- **Validação humana cega ao vivo**: pendente de auditor humano (ver
  `HUMAN-VALIDATION.md`).
- **Discovery**: cobre `function GET/POST/...`, `export const GET = arrow`,
  `params.id` inline e `searchParams.get`. Wrappers `export const GET = hof(...)`
  são reconhecidos como handler mas marcados `NOT_ANALYZED_UNSUPPORTED_SYNTAX`
  (nunca silêncio como seguro).

## O que NÃO é limitação (é design)

Abster-se não é falha. `INSUFFICIENT`, `NOT_ANALYZED` e `OUT_OF_SCOPE_*` são
saídas de primeira classe. A promessa é: quando diz CONTROLLED, há prova; quando
não, não mente.
