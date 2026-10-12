# PRODUCT-SPEC — Atlasxis

## Proposta de valor

> "Prove quais operações de acesso do seu sistema estão realmente autorizadas —
> e veja exatamente onde a prova não existe."

Não é "encontramos todas as suas vulnerabilidades". É um **Authorization Proof
Engine**: certificação estrutural, auditável, por sink.

## Pipeline

```
Repository → Discovery → Parser (AST) → Security IR → Dataflow →
Authorization Graph → Proof Engine → Decision Engine → Evidence Engine → Report
```

Implementado em `core/`: `extract.mjs` (discovery+parser+sinks), `authz.mjs`
(Authorization IR), `proofs.mjs` (mecanismos), `rls.mjs` (RLS IR), `engine.mjs`
(decisão por sink), `ir.mjs` (Proof Integrity), `report.mjs` (relatório),
`cli.mjs` (CLI).

## Decisões (por sink; handler é derivado)

`CONTROLLED` (prova estrutural) · `VULNERABLE` (fluxo não autorizado demonstrado)
· `INSUFFICIENT_EVIDENCE` (não certificado) · `NOT_ANALYZED` (não modelado) ·
`OUT_OF_SCOPE_PROVEN` / `OUT_OF_SCOPE_UNVERIFIED`.

## Mecanismos de prova suportados

self-scope · post-read ownership (verb-agnóstico) · participação (helper e
inline) · pai-filho (fecho confiável) · ownership transitivo (membership) ·
admin (helper estrutural e role-gate inline) · RLS por policy (owner, participação,
admin-function resolvida, permissive/restrictive) · webhook shared-secret
(header vs env, HMAC, delegação cross-file).

## Escopo de versão

- **v1**: Next.js (App Router) + TypeScript + Supabase (código + RLS).
- Arquitetura interna geral; validação escopada a Supabase. Prisma/Drizzle/
  Firebase são NOT_ANALYZED honesto até serem modelados (v2+).

## Não-objetivos de v1

UI/SaaS/billing/GitHub App/dashboard — só depois dos gates técnicos (todos
verdes, ver `VALIDATION-REPORT.md`). Nenhum LLM na decisão.
