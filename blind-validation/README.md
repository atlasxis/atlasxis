# Validação humana cega — HUMAN_VALIDATION = PENDING

Este diretório contém o corpus cego para a FASE 8. **Requer um auditor humano
real.** Nenhuma resposta foi preenchida por máquina — fazê-lo seria fabricar
validação, o oposto do que o Atlasxis representa.

## Arquivos

- `blind-corpus.json` — 42 casos (2 por categoria, 21 categorias). Cada caso tem
  APENAS: `case_id`, `category`, `files` (código), `entry`, `sql`, `context`.
  **Não contém** decisão do Atlasxis, reason code, ProofChain nem expectativa.
- `auditor-form.json` — formulário vazio para o auditor: `case_id`,
  `human_decision`, `human_reason`, `confidence`.
- `SEALED-ground-truth.json` — gabarito por construção (NÃO é a decisão do
  Atlasxis). Não abrir antes da classificação humana.

O protocolo completo e obrigatório está em **[PROCEDURE.md](PROCEDURE.md)**.

## Instruções ao auditor

Para cada caso, responda em `auditor-form.json`:

- `human_decision` ∈ { `CONTROLLED`, `VULNERABLE`, `INSUFFICIENT`, `NOT_ANALYZED` }
- `human_reason` — uma frase
- `confidence` ∈ { `low`, `medium`, `high` }

A pergunta NÃO é "o código é seguro em absoluto". É:

> **"Existe evidência suficiente no material fornecido para PROVAR autorização
> para este sink?"**

- Se você consegue mostrar a cadeia (fonte → recurso → autorização → guard →
  identidade → sink): `CONTROLLED`.
- Se há acesso claramente não autorizado alcançável: `VULNERABLE`.
- Se não dá para provar nem uma coisa nem outra: `INSUFFICIENT`.
- Se o código não é estruturalmente analisável: `NOT_ANALYZED`.

## Depois da classificação

1. Rode `node compare.mjs` (compara humano × Atlasxis × ground truth).
2. Registre discordâncias SEM alterar o ground truth para coincidir com o motor.
3. Atualize `docs/HUMAN-VALIDATION.md` com precisão/recall/false-control/abstention.

Enquanto `auditor-form.json` estiver vazio, o status oficial é
**HUMAN_VALIDATION = PENDING** e o release permanece
`v1.0.0-RC — TECHNICALLY READY; HUMAN VALIDATION PENDING`.
