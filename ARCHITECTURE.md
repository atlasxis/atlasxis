# Atlasxis — plano de arquitetura (baseado no código real, 2026-08-20)

Este documento cumpre a primeira tarefa da diretiva: mapear o que existe, apontar
exatamente onde o analyzer6 precisa ser substituído por IR/grafo de prova, e definir
o menor caminho seguro para a FASE 3. Nada aqui é especulação: cada ponto cita a
função real em `rescue/realexp/analyzer6.mjs`.

## 1. Estado real das fases

| Fase | Estado | Evidência |
|---|---|---|
| FASE 1 — congelar baseline | ✅ FEITA (este repo) | `MANIFEST.md`, `SHA256SUMS.baseline`, reprodução 2026-08-20 |
| FASE 2 — dois FNs conhecidos | ✅ FEITA (analyzer6) | `rescue/realexp/VEREDITO-analyzer6.md`: M1 + M2, 68/68, corpus-externo recall 6/6 |
| FASE 3 — IR/grafo de evidência | ✅ FEITA (2026-08-20) | `core/` + `docs/CORE-IR.md`; harness diferencial FAIL=0 BLOCK=0 |
| FASE 4 — RLS como evidência | ✅ FEITA (2026-08-20) | `core/rls.mjs` + `docs/FASE4-DIRECTIVE.md`; 41/41 policies reais parseadas |
| FASE 5 — benchmark grande | ⬜ parcial | 68 fixtures + adversariais (`advbench/`, `fp/`, `causal/`, `rd3/`) |
| FASE 6 — mutation testing | ⬜ | inexistente |
| FASE 7 — validação externa diversa | ⬜ parcial | corpus-externo completo; corpus-externo/corpus-externo/corpus-externo só sondados |
| FASE 8 — validação cega | ⬜ | inexistente |

Nota sobre a FASE 2: o FN "verbo do sink" era um diagnóstico errado — `provePostReadGate`
já era verb-agnóstico. A causa real era sink-fantasma por colisão de chave de
PropertyAssignment no `return` (M1). O FN transitivo virou `proveTransitiveOwnership`
(M2), com cadeia explícita exigida e sem heurística de nome de tabela.

## 2. Mapa do analyzer6 (o que cada função é, na linguagem da spec)

| Função (linha) | Papel | Componente-alvo no CORE |
|---|---|---|
| `parse`, `walk`, `findAll`, `isDead` (4–8) | front-end AST + dead-code | Parser (mantém TS compiler API) |
| `handlers` (9) | route discovery | Discovery |
| `sources` (13) | SOURCE (params/body/searchParams) | IR: nós SOURCE |
| `clientType` (19) | classificação do client Supabase | IR: contexto de execução (evidência, não regex) |
| `queryInfo`+`findAllSinks` (22–62) | normalização de sinks (op, tabela, filtros, campos) | IR: nós SINK normalizados |
| `resolveFn`, `resolveResourceGuard` (12, 63) | resolução cross-file de helpers | Provenance de helpers |
| `proveResourceOwnership` (79) | prova A/B (self-scope, participação) | Proof Engine: prova por mecanismo |
| `resolveAdminGuardProven` (105) | admin estrutural | Proof Engine: OOS_PROVEN |
| `expandBools`, `isAuthorizedDisjunct` (117–128) | De Morgan parcial sobre texto | **Authorization IR** (expressão lógica de verdade) |
| `provePostReadGate` (129) | prova C (post-read, verb-agnóstica) | Proof Engine |
| `proveTransitiveOwnership` (155) | prova E (transitiva multi-salto) | Relational Authorization Proof |
| `analyzeHandler` (183–241) | decision engine + trava anti-FP | Decision Engine por SINK |
| `analyzeFile` (242) | orquestração por arquivo | Pipeline |

## 3. Onde o analyzer6 viola a spec hoje (achados da auditoria)

Estes são os pontos exatos que justificam a reescrita como IR — não são bugs de
resultado (o baseline está limpo), são dívidas estruturais:

1. **Colapso multi-sink** (`analyzeHandler` 235–240): o handler recebe UM veredito
   (primeiro VULNERABLE > all-CONTROLLED > primeiro INSUFFICIENT). A spec exige
   veredito e prova POR SINK (§24–25). Hoje `UPDATE=CONTROLLED, DELETE=INSUFFICIENT`
   colapsaria em INSUFFICIENT sem mostrar os dois.
2. **Prova como string, não como grafo**: `evidence` é array de frases PT. A spec
   exige proof object estruturado (source/resource/authorization/guard/identity/
   sink/assumptions/unknowns) e Proof Integrity verificável automaticamente (§26, §36).
3. **Autorização como texto**: `expandBools` faz De Morgan por manipulação de string
   de condição. A spec exige expressão lógica interna normalizada (§13–14).
4. **Tokens específicos de projeto**: `clientType` e o ramo webhook (linha 192)
   contêm `supabaseAdmin`, `createServerClient`, `asaas-access-token`,
   `billing/asaas/webhook`. Viola o critério 18 ("não existem regras específicas
   por projeto"). No CORE, client e webhook viram evidência resolvida (import do
   client, verificação de assinatura provada), não regex de nomes.
5. **RLS como dict manual**: `rls[table]==="owner"` vem de `rls.json` escrito à mão.
   É assumption não-rastreada; a FASE 4 exige parser de schema/policies com a
   assumption explícita no proof (§17).
6. **Semântica por convenção de nome**: `OWNER`/`CONTAINER` são listas de nomes de
   coluna. Aceitável como assumption DECLARADA no proof; hoje é silenciosa (§18, §21).
7. **Reason como frase, não code**: critérios 15–16 exigem reason codes estáveis
   (`INSUFFICIENT.GUARD_UNRESOLVED`, `NOT_ANALYZED.NO_SINK`, …).
8. **Discovery estreita**: `handlers` só vê `function GET/POST/…` declarados; perde
   `export const GET = async () => …`. E `params.id` inline (não desestruturado) não
   é rastreado como rid — limite conhecido (forum/posts/pin fica NOT_ANALYZED).

## 4. FASE 3 — o menor caminho seguro para o IR

Regra de transição: **o analyzer6 congelado vira Atlasxis-de-referência**. O CORE
novo só é aceito quando o harness diferencial mostrar, nos três corpora (fixtures,
projeto-auditado-privado, corpus-externo), veredito idêntico OU divergência justificada por prova auditada
— nunca um CONTROLLED novo sem proof trace completo.

Etapas (cada uma com fixtures positivas/negativas/adversariais + regressão, §FASE 15):

1. **IR de dados** (sem mudar decisões): tipos `Source`, `ResourceRead`, `AuthzExpr`,
   `Guard`, `Sink`, `ProofChain`, `Assumption`, `ReasonCode`. O analyzer6 é adaptado
   apenas para EMITIR o IR ao lado do veredito atual (adapter, zero mudança de lógica).
2. **Decision Engine por sink**: veredito por cadeia SOURCE→AUTHZ→SINK; o handler
   agrega sem colapsar. Regressão: nos corpora atuais os agregados devem bater com
   o baseline.
3. **Authorization IR**: parser de condição → árvore booleana (AND/OR/NOT,
   comparações tipadas) + normalizador De Morgan. `expandBools`/`isAuthorizedDisjunct`
   morrem. Fixtures adversariais de §32 (alias de ID, helper vácuo, gate parcial…).
4. **Proof Integrity como invariant executável**: nenhum CONTROLLED sem os 6
   componentes; `UNKNOWN → SAFE` impossível por construção (teste automático).
5. **Des-projetização**: client/webhook/OWNER/CONTAINER viram evidência ou
   assumption declarada; remover todo token do projeto-auditado-privado do core.
6. **FASE 4 em diante** conforme SPEC.md (RLS parser, benchmark, mutation, externa, cega).

## 5. Ativos de teste já existentes para reaproveitar

- `rescue/realexp/battery6.mjs` — 68 fixtures com expectativa (base do benchmark).
- `rescue/advbench/`, `rescue/fp/`, `rescue/causal/`, `rescue/rd3/`,
  `rescue/adv-comment/`, `rescue/adv-string/`, `rescue/astcheck/` — sementes
  adversariais das rodadas de 18/ago.
- `rescue/ext/corpus-externo/` + `_result6.json` — corpus externo com ground truth auditado
  byte-exato (5 TRUE_CONTROL documentados no veredito).
- `rescue/ext/{corpus-externo,corpus-externo,corpus-externo}/` — corpora ainda não explorados (FASE 7).

## 6. Invariantes de processo (não negociáveis)

- projeto-auditado-privado: somente leitura, sempre.
- analyzer5 e analyzer6 congelados: patches novos nascem no CORE, nunca neles.
- Toda mudança roda o harness diferencial completo antes de ser aceita.
- CORRETUDE > COBERTURA em qualquer trade-off.
