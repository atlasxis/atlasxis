# BENCHMARK-REPORT — FASE 5

Gerador: `core/benchmark/generate.mjs`. Runner: `core/benchmark/run.mjs`.
Ground truth **por construção** (o gerador sabe o padrão que montou), NUNCA
derivado do resultado do Atlasxis.

## Escala e resultado

- **532 casos** (mínimo da diretiva: 500).
- **Correção (expectedDecision == actual): 532/532 (100%)**.
- **FALSE-CONTROL (VULNERABLE visto como CONTROLLED): 0** — gate fatal.
- **FALSE-VULN (SAFE visto como VULNERABLE): 0**.
- **Proof Integrity: 0 falhas** em todas as decisões.
- Coverage (SAFE realmente provados CONTROLLED): 232/256 = 90.6% — reportado
  **separado** da correção (cobertura não é prova de segurança).

## Distinção metodológica central

`groundTruth` = verdade de segurança do código. `expectedDecision` = o que um
certificador conservador CORRETO deve emitir. Um SAFE que o motor não consegue
provar tem `groundTruth=SAFE` mas `expectedDecision=INSUFFICIENT` — e isso é
**correto**, não um erro (CORRETUDE > COBERTURA).

## Categorias (22 famílias)

self-scope · post-read (+ near-miss) · admin-owner · admin-only (OOS) ·
transitive (+ broken) · cross-file-helper · idor-service-role · authed-no-rls ·
rls-owner · rls-admin-or-owner · rls-restrictive · rls-open · rls-none ·
multi-sink (allsafe/mixed) · dead-guard · unsupported · adversarial-nameonly ·
fake-admin-name. Cada família tem positivos, negativos, near-miss e adversariais.

## Bugs reais encontrados pelo benchmark (corrigidos, não mascarados)

1. `created_by === user.id` não reconhecido como ownership (só `*_id`) —
   inconsistência com o resto do motor. Corrigido: qualquer campo lido comparado
   à identidade autenticada, sob assumption declarada.
2. Guard-call importado que faz trabalho real gerava VULNERABLE (falso positivo
   em potencial). Corrigido: só guard **provado vácuo** (`return true`) leva a
   VULNERABLE; guard não analisável → INSUFFICIENT.

Determinismo do benchmark verificado (duas execuções byte-idênticas).
