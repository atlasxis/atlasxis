# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/). Versões seguem a tag
técnica do engine.

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
