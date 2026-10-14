# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/). Versões seguem a tag
técnica do engine.

## [1.3.1-public] — 2026-10-14

### Corrigido (falso VULNERABLE)
- **Vínculo ao chamador em forma não modelada.** Uma consulta com `supabaseAdmin` filtrada pelo id do
  cliente e também presa ao usuário por `.filter("col","eq",user.id)`, `.or(\`a.eq.${user.id},…\`)`,
  `.in(col, listaDoUsuário)` ou outro filtro que o motor não modela saía `VULNERABLE_NO_GATING_SERVICE_ROLE`.
  Agora qualquer filtro não modelado na cadeia do acesso (ou junção `!inner`) impede provar a ausência
  de vínculo: `INSUFFICIENT_UNRESOLVED_GATING`.
- **Apelido do id do usuário.** `const me = user.id; … .eq("participant_id", me)` não era reconhecido
  como filtro pela identidade; agora conta como `user.id` (coluna de dono → `CONTROLLED_SELF_SCOPE`,
  outra coluna → abstenção).
- **Gate por consulta prévia.** Uma rota que primeiro lê a própria linha do chamador pelo id do cliente
  (`.eq("id", cid).eq("owner_id", user.id)`) ou chama uma `rpc` com o id do cliente e `user.id`, e sai
  antes (404/throw) quando não há resultado, saía `VULNERABLE`. Agora abstém
  (`INSUFFICIENT_UNRESOLVED_GATING`). Buscar só o perfil do chamador continua não sendo gate.
- Repositório adversarial: casos 39–48 (o IDOR evidente e o "perfil + recurso alheio" seguem `VULNERABLE`).
- **Express: leitura pública por desenho.** `findFirst({ where: { id: req.params.id, published: true } })`
  saía `VULNERABLE_NO_OWNERSHIP_CHECK`. Numa leitura, uma chave além do id do cliente que não é a
  identidade agora abstém (`INSUFFICIENT_UNRESOLVED_GATING`); numa escrita, segue `VULNERABLE`.
  Certificação Express: 98 casos (D01/D02).
  Encontrado pela revisão adversarial do ORÁCULO.

## [1.3.0-public] — 2026-10-13

### Adicionado (experimental)
- **Express + Prisma.** `atlasxis scan` reconhece projetos Express e prova, por acesso Prisma, se há
  autorização: descobre rotas e cadeias de middleware (inclusive montagens entre arquivos), segue o
  handler por controller → service → repositório (`this.db`, `tx` de `$transaction`, singletons de
  classe, `asyncHandler`) e decide com o mesmo IR e as mesmas invariantes do motor Supabase.
  Como Prisma não tem RLS, VULNERABLE (`VULNERABLE_NO_OWNERSHIP_CHECK`) exige rota autenticada por
  middleware provado, id escolhido pelo cliente, posse do modelo provada pelo `schema.prisma` e
  ausência de qualquer checagem no caminho; rota só de admin sai `OOS_PROVEN_ROLE_MIDDLEWARE`; rota
  sem autenticação sai `INSUFFICIENT_UNAUTHENTICATED_ROUTE`. `--no-express` desliga.
- Certificação própria (`core/harness/express-suite.mjs`): 96 casos, incluindo 66 ataques de três
  rodadas de revisão adversarial; 0 falso controle, 0 falso vulnerável. Limites em
  `docs/EXPRESS-PRISMA.md`.
- Em código real (390 rotas): 169 acessos provados CONTROLLED (amostra conferida à mão: 0 falsos),
  0 VULNERABLE, 651 rotas só de admin reconhecidas.

O motor Supabase/Next.js não mudou: benchmark, mutações, RLS e server actions idênticos.

## [1.2.0-public] — 2026-10-13

### Adicionado
- **Client Supabase definido em outro arquivo.** `import { adminDb } from "@/lib/db"`
  e `const supabase = await createClient()` (com `createClient` importado) agora são
  classificados pela definição exportada no próprio projeto: chave `service_role` →
  `service_role`; `createServerClient`/`createRouteHandlerClient` → `authenticated`.
  Import que casa com mais de um arquivo, alvo fora do conjunto analisado ou
  definição que mistura admin e usuário continuam desconhecidos (fail-closed). Toda
  decisão que depende disso declara a nova assumption
  `CLIENT_KIND_BY_IMPORTED_DEFINITION`.
- Efeito: uma IDOR real via client admin importado, que antes saía
  `INSUFFICIENT_RLS_UNKNOWN`, passa a ser provada `VULNERABLE_NO_GATING_SERVICE_ROLE`.

Regressões permanentes: padrões adversariais 33–38. Benchmark de 532 casos,
mutações 130/130, RLS e server actions inalterados; em código real auditado
(87 sinks), nenhuma decisão mudou.

## [1.1.1-public] — 2026-10-12

### Corrigido — falso VULNERABLE (leia se usa 1.0.0 a 1.1.0)
- **Id do cliente + filtro de dono no mesmo acesso.** Um acesso via
  `service_role` como `.eq("conversation_id", id).eq("user_id", user.id)` saía
  `VULNERABLE_NO_GATING_SERVICE_ROLE`: o motor via o id do cliente e ignorava o
  filtro de dono no mesmo acesso. Esse id só estreita linhas que já são do
  usuário. Agora: `CONTROLLED_SELF_SCOPE` quando a coluna segue a convenção de
  dono, e abstenção (`INSUFFICIENT_UNRESOLVED_GATING`) com `user.id` em outra
  coluna. Insert/upsert não mudam.
- O SARIF passa a informar a versão real do pacote (estava fixo em 1.1.0).

Regressões permanentes: padrões adversariais 28–32. Benchmark de 532 casos,
mutações (130/130), RLS e server actions inalterados; em código real auditado
(87 sinks), nenhuma decisão mudou.

## [1.1.0-public] — 2026-10-12

### Corrigido — correções de segurança (leia se usa 1.0.0 a 1.0.3)
Até a 1.0.3, o Atlasxis podia afirmar mais do que provava em quatro situações.
Três foram encontradas ao validar o motor em código real de terceiros, e uma em
revisão adversarial interna. Se você confiou num resultado da 1.0.x nesses
padrões, rode de novo com a 1.1.0.

- **Falso CONTROLLED com identidade vinda do cliente.** Uma rota que lia
  `user`/`session` do corpo, da query, de um cookie cru ou de um objeto montado
  com esses dados saía `CONTROLLED`, mas o atacante escolhia a própria
  identidade. Agora: `INSUFFICIENT_IDENTITY_FROM_CLIENT`.
- **Falso CONTROLLED com spread junto do dono.** `insert({ user_id: user.id,
  ...dados })` saía `CONTROLLED`, mas o spread pode sobrescrever `user_id`.
  Agora: `INSUFFICIENT_OWNER_OVERRIDABLE`.
- **Falso CONTROLLED com referência escolhida pelo cliente.** Um registro do
  usuário gravado com um `*_id` vindo do cliente (ex.: `campaign_id`) saía
  `CONTROLLED`, embora apontasse para um recurso de outro. Agora:
  `INSUFFICIENT_CROSS_RESOURCE`.
- **Falso VULNERABLE em arquivos com vários handlers.** O tipo de cliente
  Supabase era decidido pelo arquivo inteiro: um `supabaseAdmin` num handler
  fazia os outros, que usavam o cliente do usuário, saírem `VULNERABLE`. Agora o
  tipo é decidido por acesso.

Regressões permanentes: padrões adversariais 18–27. Benchmark de 532 casos e
corpus público: byte-idênticos. Em código real auditado (51 rotas, 87 sinks),
só uma decisão mudou, para uma abstenção mais honesta.

### Adicionado
- **`atlasxis rls`**: auditoria de RLS por tabela × papel (`anon`,
  `authenticated`) × operação, direto do SQL (migrações ou `--schema-dump`).
  Cobre apps que chamam o Supabase direto do navegador. Não presume os grants
  padrão do Supabase, que mudaram em 2026; `--assume-default-grants` declara o
  padrão antigo como assumption. Certificado: 46 casos, 0 falso controle,
  0 falso vulnerável, 35/35 mutações; validado em SQL real.
- **Server actions** (arquivos `"use server"`), ligadas por padrão
  (`--no-server-actions` desliga): mesmo motor de provas; argumentos e campos
  de `FormData` são entrada do cliente. Certificado: 25 casos, 0 falso controle,
  0 falso vulnerável, 13/13 mutações; validado em 7 projetos open source reais
  (205 decisões, integridade 0, revisão manual completa).
- 12 reason codes e 3 assumptions novos.
- Fixtures públicas `client-side-rls` e `server-action-idor`.

### Segurança operacional
- A detecção de `"use server"` lê o topo do arquivo em tempo linear. Uma versão
  anterior desta mesma release, nunca publicada, usava uma regex que travava em
  arquivos inteiros de código comentado. Novo teste de regressão (15/15).

## [1.0.3-public] — 2026-10-12

### Mudado
- Repositório movido para a organização `atlasxis`:
  https://github.com/atlasxis/atlasxis. Os endereços antigos redirecionam.
  README, metadados do pacote npm e o link no SARIF apontam para o novo endereço.
- Engine inalterado.

## [1.0.2-public] — 2026-10-12

### Mudado
- **Novo nome: Atlasxis** (antes ORÁCULO CORE). O comando passa a ser
  `atlasxis` (antes `oracle`) e o arquivo de baseline passa a ser
  `.atlasxis-baseline.json`.
- Pacote npm `atlasxis`. O README mandava rodar `npx oracle`, que fora do clone
  baixaria um pacote de outra pessoa (o nome `oracle` no npm é um driver de
  banco de dados). Os comandos agora usam `npx atlasxis`.
- README principal em inglês; versão em português em `README.pt-BR.md`.
- Action renomeada para `.github/actions/atlasxis-scan`; removido o input
  `oracle-ref`, que não era usado.

### Inalterado
- O engine não mudou: as decisões sobre o benchmark, o corpus público e os
  padrões adversariais são idênticas às da 1.0.1. Só mudaram nomes e textos de
  saída (cabeçalho do relatório, nome da ferramenta no SARIF, versão impressa).

## [1.0.1-public] — 2026-10-11

### Corrigido
- `LICENSE` volta ao texto MIT padrão. A nota de escopo anexada impedia o
  GitHub de identificar a licença (aparecia como "Other"). A nota continua no
  README, seção Licença. O engine não mudou.

## [1.0.0-public] — 2026-08-21

Primeira árvore **pública** distribuível do ORÁCULO CORE.

### Adicionado
- Corpus público **sintético** (`public-corpus/`): 8 mini-projetos que exercitam
  self-scope, post-read gate, helper ownership, parent-child, RLS owner,
  service_role IDOR (VULNERABLE), admin role-gate (OOS) e wrapper não suportado.
- Harness de **validação pública** (`core/harness/external-public.mjs`):
  demonstra os mecanismos + Proof Integrity = 0, reprodutível por terceiros.
- **Scanner de publicação** (`core/harness/publication-scan.mjs`) com self-test:
  falha o CI se encontrar segredos, `.env`, caminhos pessoais, nomes de projetos
  privados ou o diretório `rescue/`.
- Modo `--public` do CI (`npm run ci:public`) e `npm test` reprodutíveis em
  clone limpo, sem material privado.
- `LICENSE` (MIT), `CONTRIBUTING.md`, templates de issue, este `CHANGELOG.md`.
- Case library pública (`case-library/cases-public/`) referenciando apenas
  fixtures sintéticas.

### Removido da distribuição pública (por privacidade)
- `rescue/` inteiro: baseline congelado (analyzer5/6) e fixtures derivadas de
  código privado (projeto-auditado-privado) e de projetos de terceiros (não redistribuíveis).
- Relatórios de auditoria privada, `baseline-records/`, o harness diferencial
  (comparação com o baseline congelado) e a validação externa sobre 13 repos
  reais — todos **só-do-mantenedor**.

### Substituído por fixture sintética
- Os corpora projeto-auditado-privado/corpus-externo usados na validação foram substituídos por
  mini-projetos sintéticos equivalentes que preservam os **mecanismos** (posse,
  post-read, RLS, service_role) sem copiar lógica de negócio real. As métricas
  públicas são recalculadas **exclusivamente** sobre o corpus público.

### Inalterado (contrato)
- CORRETUDE > COBERTURA. O ORÁCULO não certifica ausência de vulnerabilidades.
  `INSUFFICIENT`/`NOT_ANALYZED` nunca são `SAFE`; `VULNERABLE` exige evidência
  positiva; `CONTROLLED` exige ProofChain íntegra.

## [1.0.0] — 2026-08-21 (release técnico, mantenedor)

Engine completo: Security IR, ProofChain, decisão por sink, RLS parser, CLI
(`scan`/`report`/`explain`/`--ci`), benchmark 532, mutation 130/130, adversarial
17/17, segurança operacional, case library, knowledge base. Commit `c7cb2e8`,
tag `v1.0.0`. Validação humana cega: PENDING.
