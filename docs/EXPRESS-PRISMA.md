# Atlasxis — Express + Prisma (especificação)

Escrita antes do código. Origem: o backend real de um app de saúde (Express + Prisma, ~389 rotas,
~1.117 acessos ao banco, 79 modelos) em que a 1.2.0 cobria 0%. As formas abaixo foram tiradas desse
código; as fixtures as imitam por construção, sem copiar código de terceiros.

## O que muda em relação ao Supabase

Prisma não tem RLS: toda autorização está no código da aplicação. Por isso:

- **CONTROLLED** exige prova na aplicação (filtro de dono no próprio acesso, gate depois de ler o
  registro, helper que rejeita), com a identidade vinda de um middleware de autenticação provado.
- **VULNERABLE** é mais estrito que no Supabase. Exige, todos juntos:
  1. rota autenticada por middleware provado (a identidade existe e é verificada no servidor);
  2. o registro do acesso é escolhido por um id vindo do cliente (params, query ou body);
  3. o **schema Prisma** prova que o modelo pertence a um principal do mesmo tipo da identidade
     (relação/chave estrangeira para o modelo do principal);
  4. nenhum filtro de dono, gate, helper ou papel antes do acesso;
  5. todo o caminho do handler até o acesso foi resolvido (nenhuma chamada desconhecida no meio).
  Faltou qualquer item → INSUFFICIENT, nunca VULNERABLE.
- Rota sem autenticação com id do cliente **não** é VULNERABLE (catálogo público é legítimo):
  abstém com `INSUFFICIENT_UNAUTHENTICATED_ROUTE`.

## Descoberta

- Routers: `Router()` / `express.Router()` / `express()`; rotas `R.<get|post|put|patch|delete>(path, ...mw, handler)`.
- Middleware de router: `R.use(mw)` vale para as rotas registradas **depois**; `R.use(prefix, ...mw, subRouter)`
  monta um router de outro arquivo e aplica `mw` às rotas dele.
- Handler: função inline; identificador local/importado (inclusive `asyncHandler(fn)` — wrapper que repassa
  a função, assumption `WRAPPER_PASSES_THROUGH`); `obj.metodo` / `obj.metodo.bind(obj)` com `obj` singleton
  (`export default new Classe()`, objeto literal). Despacho dinâmico (`handler('list')`, `ctrl[m]`) →
  `NOT_ANALYZED_UNSUPPORTED_SYNTAX`.

## Identidade

Middleware de **autenticação** reconhecido pela forma, não pelo nome: verifica um token
(`jwt.verify`, `verifyIdToken`, `verifyToken`, `passport.authenticate`) e grava `req.<campo> = ...`,
rejeitando quando falta (401/403, `next(erro)`, `throw`). Os campos gravados (`req.user`,
`req.professional`, ...) viram fontes de identidade **só** nas rotas cuja cadeia contém esse middleware.
Middleware que não rejeita sem token (auth opcional) não prova identidade.
O modelo do principal vem do próprio middleware (o `findUnique` que ele faz) ou do nome do campo
(`professional` ↔ `Professional`; assumption `PRINCIPAL_MODEL_BY_NAME`).

Middleware de **papel**: rejeita a menos que o principal tenha papel/permissão (`req.admin`, `.role`,
`.permissions`). Rota cujo único principal é administrativo → `OUT_OF_SCOPE_PROVEN` (admin confiável,
assumption `ADMIN_ROLE_GRANTS_ACCESS`).

## Do handler ao banco

Fluxo entre funções e arquivos (profundidade ≤ 5): argumentos são mapeados para parâmetros carregando o
rótulo `CLIENT(expr)` ou `IDENTITY(campo)`, inclusive em objetos (`{ userId, professionalId }`) e
desestruturação. Chamadas resolvidas: funções importadas, métodos de singleton, `this.metodo()`.
Clients Prisma: identificador importado de um módulo que cria `new PrismaClient`, campos de classe
inicializados com ele (`this.db`, `this.prisma`), e o `tx` de `$transaction(async (tx) => ...)`.
`$queryRaw`/`$executeRaw` → `NOT_ANALYZED_UNSUPPORTED_SYNTAX` para aquele acesso.

## Decisão por acesso (sink)

| Situação | Decisão |
|---|---|
| `where`/`data` liga um campo à identidade do principal (`{ id, professionalId: identidade }`) | CONTROLLED_SELF_SCOPE |
| gate dominante: lê o mesmo modelo pelo mesmo id do cliente e rejeita a menos que `registro.campo === identidade` | CONTROLLED_POST_READ_GATE |
| helper resolvido chamado antes (dominante) com o id e a identidade, cujo corpo faz o gate acima | CONTROLLED_OWNERSHIP_HELPER |
| create/update que grava dono = identidade e também um `*Id` escolhido pelo cliente | INSUFFICIENT_CROSS_RESOURCE |
| todos os 5 itens de VULNERABLE | VULNERABLE_NO_OWNERSHIP_CHECK |
| rota sem middleware de autenticação provado | INSUFFICIENT_UNAUTHENTICATED_ROUTE |
| chamada não resolvida no caminho, gate em ramo condicional, modelo sem ligação provada ao principal | INSUFFICIENT_* (motivo específico) |
| acesso sem id do cliente | NOT_ANALYZED_NO_CLIENT_RESOURCE_ID |

Um gate **depois** do acesso não protege o acesso (não domina). Isso é reportado.

## Certificação

`core/harness/express-suite.mjs`: casos positivos, negativos e adversariais por construção, mutação
causal em todo CONTROLLED/VULNERABLE esperado, determinismo, Proof Integrity. Gates: fail = 0,
false-control = 0, false-vuln = 0, integrity = 0, survivors = 0. Depois: execução no código real com
revisão manual de toda decisão CONTROLLED/VULNERABLE.

## Estado: experimental (1.3.0)

Certificação: 30 casos por construção + 66 ataques de três rodadas de revisão adversarial independente
(`core/fixtures/express-adversarial.mjs`), fail = 0, false-control = 0, false-vuln = 0, mutações 11/11.
Código real (backend de app de saúde, 390 rotas, ~1.200 acessos): 169 CONTROLLED, 0 VULNERABLE, 651
OUT_OF_SCOPE_PROVEN (rotas só de admin), o resto abstém; amostra de 27 CONTROLLED conferida à mão por
revisor independente: 0 falsos.

Por que experimental: cada rodada adversarial ainda achou formas novas (cada vez mais artificiais) de
enganar a análise estática. Regras que valem hoje e que limitam o que o motor afirma:

- Identidade só conta se o valor **deriva do resultado da verificação** do token no middleware; um
  valor guardado inteiro só vale como `id`.
- **Qualquer escrita** num campo de identidade da requisição, em qualquer função do caminho e por
  qualquer apelido, anula toda prova de dono daquela rota.
- Middleware, `router.param`, wrapper ou chamada externa que o motor não modela e que toca banco,
  parâmetros ou identidade **bloqueia VULNERABLE** (abstém).
- Checagem dentro de `try` cujo `catch` não termina com `throw`/`return` só protege acessos no mesmo
  `try`.
- Prefixo de middleware casa por segmento inteiro; `:param` da rota diante de um literal só pode
  acrescentar dúvida, nunca autenticação ou papel.
- Sem suporte: JavaScript puro (só `.ts/.tsx`), `router.route(...)`, despacho dinâmico de handler,
  SQL bruto, re-export em mais de um salto, middleware adicionado em tempo de execução.
