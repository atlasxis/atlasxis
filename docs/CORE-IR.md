# ORÁCULO CORE — Security IR (FASE 3) — documentação técnica

Implementado em 2026-08-20. O CORE novo vive em `core/` e é comparado
diferencialmente contra o analyzer6 congelado (que permanece byte-idêntico —
verificar com `shasum -a 256 -c SHA256SUMS.baseline`).

## Módulos

| Módulo | Responsabilidade |
|---|---|
| `core/reason-codes.mjs` | Status + reason codes estáveis; mapa código→status como invariante |
| `core/assumptions.mjs` | Catálogo de assumptions explícitas (id + texto); nunca silenciosas |
| `core/ir.mjs` | Nós do IR (Source, ResourceRead, Guard, IdentityProof, Sink, Authorization, ProofChain, Decision) + `validateDecision` (Proof Integrity executável) |
| `core/authz.mjs` | Authorization IR: AST booleana, NNF/De Morgan, DNF, verificação semântica por truth table, classificação de literais autorizadores |
| `core/extract.mjs` | Discovery ampliada, sources (incl. `params.id` inline e alias 1–3 saltos), sinks normalizados (porta do findAllSinks com M1) |
| `core/proofs.mjs` | Mecanismos de prova: helper-ownership, inline-ownership/participação, post-read gate (com fecho confiável), transitive ownership, admin helper, admin role-gate inline, webhook shared-secret (cross-file + delegação) |
| `core/engine.mjs` | Decision engine POR SINK + agregação derivada + cascata anti-FP com reason codes |
| `core/harness/differential.mjs` | unit + legacy(68) + fase3(34) + corpus CF + corpus corpus-externo; política de BLOCK; métricas |
| `core/harness/legacy-fixtures.mjs` | Extrai as 68 fixtures do battery6.mjs congelado sem modificá-lo |
| `core/fixtures/fase3.mjs` | 34 fixtures novas (multi-sink, identidade, authz IR, unknown, discovery, admin inline, webhook, fecho confiável, assumptions) |

## Fluxo de decisão

```
arquivo → discoverHandlers (function decl | export const arrow; formas não
          suportadas ⇒ NOT_ANALYZED_UNSUPPORTED_SYNTAX, nunca silêncio)
handler → admin OOS? (helper estrutural | role-gate inline provado | path)
        → webhook? (prova estrutural de segredo/assinatura, cross-file, delegação)
        → sinks (normalizados por recurso; verbo é detalhe)
sink    → clientRids (sources: destructure, params.id inline, alias)
        → cascata: RLS declarada → provas (helper → inline → post-read → transitiva)
          → alias → guard não resolvido → gate user.id sem identidade
          → trava anti-FP (gating vivo ⇒ INSUFFICIENT) → VULNERABLE (service_role)
          → INSUFFICIENT_RLS_UNKNOWN
handler = agregação DERIVADA dos sinks (VULNERABLE domina; CONTROLLED só se
          todos os aplicáveis; senão INSUFFICIENT; senão NOT_ANALYZED)
```

## Authorization IR

`fromTsExpression` constrói AST booleana (`and`/`or`/`not`/`cmp`/`truthy`) com
expansão estrutural de variáveis booleanas (profundidade ≤4). `toNNF` aplica
De Morgan + dupla negação + negação de comparação como transformações de árvore.
`verifiedDNF(e)` só retorna a DNF se `equivalent(e, dnf)` — verificação por
truth table (≤14 átomos; acima disso a transformação é tratada como não
verificável e a prova NÃO acontece).

Um gate `if (C) reject` autoriza R quando TODO disjunto de DNF(¬C) contém um
literal autorizador (ownership de binding no fecho confiável de R, ou admin) e
≥1 disjunto contém ownership. Fecho confiável = reads encadeados por filtros
que referenciam campos de reads já confiáveis (relação vinda do código, ex.:
`.eq("id", comment.post_id)` — nunca inventada).

## Proof Integrity (invariante executável)

`validateDecision` roda sobre TODA decisão (o engine lança na construção; o
harness revalida): CONTROLLED/OOS_PROVEN exigem ProofChain com os 6 componentes
(source, resource, authorization, guard, identity, sink) e zero unknowns;
CONTROLLED exige `IdentityProof.same === true`; VULNERABLE exige evidence
trace; reasonCode deve sustentar o status. `UNKNOWN → SAFE` é impossível por
construção.

## Reason codes (congelados)

CONTROLLED_{SELF_SCOPE, OWNERSHIP_HELPER, OWNERSHIP_INLINE, POST_READ_GATE,
TRANSITIVE_OWNERSHIP, RLS_DECLARED_OWNER} · VULNERABLE_NO_GATING_SERVICE_ROLE ·
INSUFFICIENT_{RLS_UNKNOWN, RLS_DECLARED_COMPLEX, RESOURCE_IDENTITY,
CROSS_RESOURCE, ALIAS_RESOLUTION, TRANSITIVE_OWNERSHIP, GUARD_UNRESOLVED,
UNRESOLVED_GATING, ADMIN_GUARD_UNPROVEN, ANALYSIS_ERROR} ·
NOT_ANALYZED_{NO_HANDLER, NO_SINK, NO_CLIENT_RESOURCE_ID, UNSUPPORTED_SYNTAX,
DISCOVERY} · OOS_PROVEN_{ADMIN_HELPER, ADMIN_INLINE_ROLE_GATE,
WEBHOOK_SIGNATURE} · OUT_OF_SCOPE_UNVERIFIED_{ADMIN, WEBHOOK}

## Assumptions (registradas na ProofChain, nunca convertidas em fato)

SERVER_IDENTITY · OWNER_COLUMN_CONVENTION · CONTAINER_COLUMN_CONVENTION ·
CLIENT_KIND_BY_API_NAME · SERVICE_ROLE_BYPASSES_RLS · RLS_DECLARED_BY_CONFIG ·
ADMIN_HELPER_NAME_CONVENTION · OWNERSHIP_GRANTS_ACCESS ·
ADMIN_ROLE_GRANTS_ACCESS · MEMBERSHIP_GRANTS_ACCESS ·
SHARED_SECRET_VERIFIES_CALLER

## Como rodar

```bash
cd core/harness
node differential.mjs all      # unit + legacy + fase3 + cf + corpus-externo
node differential.mjs legacy   # só as 68 congeladas
node differential.mjs fase3    # só as 34 novas
```

Saída em `core/harness/out/{cf,corpus-externo}-diff.json` (todas as decisões + proofs).
Divergências novas com claim (CONTROLLED/VULNERABLE/OOS_PROVEN) sem entrada em
`divergence-justifications.json` ⇒ BLOCK (exit 1).

## Resultados de aceitação (2026-08-20)

- analyzer6 byte-idêntico ✓ (checksums) · baseline reproduzível ✓
- UNIT 6/6 · LEGACY 68/68 (0 divergência) · FASE3 34/34 ✓
- projeto-auditado-privado: 20/0/2/17/18 — divergência ZERO, agora sem nenhum token de
  projeto (webhooks provados por helper→process.env cross-file e delegação
  por import-alias; comments/[commentId] DELETE pelo fecho confiável) ✓
- corpus-externo: 6 CONTROLLED (idênticos), 0 VULNERABLE, 10 divergências TODAS
  conservadoras e justificadas ✓ — incluindo 2 em que o core CORRIGE o
  baseline: webhooks supabase/user-confirmed liam a assinatura e apenas a
  logavam; o OOS_PROVEN do a6 vinha de regex por presença da palavra
  "signature" (prova falsa). Core: OOS_UNVERIFIED.
- false-control = 0 · false-positive = 0 · identity-proof coverage = 100% dos
  CONTROLLED · nenhum CONTROLLED sem ProofChain (invariante executável)

## FASE 4 — RLS como evidência (2026-08-20)

`core/rls.mjs`: parser estrutural de subset SQL → RLS IR (tabelas, colunas, FKs,
enable/disable RLS, policies com USING/WITH CHECK/roles/cmd, DROP POLICY, DO $$
com guarda de idempotência pg_policies, funções para admin-predicate).
Classificação fail-closed: `owner-eq` (auth.uid() = coluna, ordem livre, casts,
parênteses), disjunções de owner/participação e admin-function resolvida por
CORPO (`exists(select 1 from t where col=auth.uid() and role='x')`); EXISTS/
subquery/true/desconhecido = unproven. Semântica PG: permissivas OR, restritivas
AND, UPDATE herda USING, INSERT usa WITH CHECK; policy só prova com RLS enabled,
cmd e role cobrindo o sink; INSERT/UPSERT com container rid nunca é provado por
owner-policy. RLS desabilitada provada = `INSUFFICIENT_RLS_ABSENT` (VULNERABLE
apenas com opt-in `SUPABASE_DEFAULT_GRANTS`). Diretiva e resultado completos:
`docs/FASE4-DIRECTIVE.md`; exemplo: `docs/exemplo-rls-proofchain.json`.
Novos codes: CONTROLLED_RLS_POLICY_OWNER · INSUFFICIENT_RLS_{POLICY_UNPROVEN,
ABSENT,AMBIGUOUS} · VULNERABLE_RLS_DISABLED_DEFAULT_GRANTS. Harness: partes
`fase4` (21 fixtures) e `cf-rls` (21 .sql reais do projeto-auditado-privado, 41/41 policies).

## Limitações conhecidas (registradas, não corrigidas nesta fase)

1. Role-gate via predicado em lambda (`userRoles?.some(ur=>ur.role==="Admin")`)
   não modelado → corpus-externo pin POST fica INSUFFICIENT (antes: silêncio).
2. Alias de rid: detectado e classificado (INSUFFICIENT_ALIAS_RESOLUTION), mas
   não resolvido por dataflow — nunca vira CONTROLLED.
3. RLS continua evidência DECLARADA (assumption RLS_DECLARED_BY_CONFIG);
   parser real de schema/policies é a FASE 4.
4. Truth table limitada a 14 átomos — condições maiores não provam (fail-closed).
5. Mutation testing: interfaces prontas (fixtures são `files` puros e o engine
   é determinístico e puro), implementação é fase posterior.
