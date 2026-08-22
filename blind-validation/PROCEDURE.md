# Procedimento de Validação Humana Cega

Status atual: **HUMAN_VALIDATION = PENDING**. Este documento descreve o protocolo
a ser executado quando houver um auditor humano real. Nada aqui pode ser
executado pela máquina em nome do humano.

## Princípio

`CORRETUDE > COBERTURA`. A pergunta da validação **não** é "o sistema é seguro".
É, por caminho:

> "Existe evidência estrutural suficiente para PROVAR autorização?"

- `CONTROLLED` precisa ter prova. `VULNERABLE` precisa ter evidência positiva.
- `INSUFFICIENT` precisa continuar insuficiente. `NOT_ANALYZED` continua não analisado.
- **UNKNOWN nunca pode virar SAFE.**

## Materiais

- `blind-corpus.json` — 42 casos (21 categorias × 2). Cada caso tem **apenas**
  `case_id`, `category`, `files` (código), `entry`, `sql`, `context`. **Não**
  contém a decisão do ORÁCULO, reason code, ProofChain nem expectativa.
- `auditor-form.json` — formulário vazio (42 linhas). O auditor preenche.
- `SEALED-ground-truth.json` — gabarito **por construção** (SAFE/VULNERABLE/
  UNKNOWN). **NÃO abrir antes da classificação humana.** Não é a decisão do ORÁCULO.
- `compare.mjs` — comparador read-only (só roda com o formulário preenchido).

## Protocolo (ordem obrigatória)

1. **Isolamento.** O auditor recebe somente `blind-corpus.json` e
   `auditor-form.json`. Não vê `SEALED-ground-truth.json` nem a saída do ORÁCULO.
2. **Classificação humana.** Para cada caso, o auditor preenche em
   `auditor-form.json`:
   - `human_decision` ∈ { `CONTROLLED`, `VULNERABLE`, `INSUFFICIENT`, `NOT_ANALYZED` };
   - `human_reason` — uma frase justificando;
   - `confidence` ∈ { `low`, `medium`, `high` }.
   Critério: se consegue mostrar a cadeia fonte→recurso→autorização→identidade→
   sink, `CONTROLLED`; se há acesso não autorizado alcançável, `VULNERABLE`; se
   não dá para provar nem uma coisa nem outra, `INSUFFICIENT`; se o código não é
   estruturalmente analisável, `NOT_ANALYZED`.
3. **Execução do ORÁCULO.** Só **depois** de o formulário estar preenchido:
   ```bash
   node blind-validation/compare.mjs
   ```
   O comparador roda o ORÁCULO sobre o mesmo material, abre o gabarito selado e
   emite o relatório. Com o formulário vazio ele recusa (PENDING) — por design.
4. **Registro.** O relatório apresenta, sem alterar o corpus nem o gabarito:
   - **false-control** (ORÁCULO CONTROLLED sobre gt VULNERABLE) — erro grave;
   - **false-vuln** (ORÁCULO VULNERABLE sobre gt SAFE/UNKNOWN);
   - **CONTROLLED sobre UNKNOWN** (afirmou prova sem base) — erro;
   - **control TP/FN** e **vuln TP/FN** (FN = abstenção; coverage, não erro);
   - contagem de **INSUFFICIENT / NOT_ANALYZED / OUT_OF_SCOPE**;
   - **concordância humano × ORÁCULO** e **humano × ground truth**;
   - lista de **divergências** com a justificativa humana.

## Regras invioláveis

- **Não** alterar `blind-corpus.json` nem `SEALED-ground-truth.json` durante a validação.
- **Não** alterar o engine para melhorar artificialmente o resultado.
- **Não** transformar uma divergência em motivo para ajustar fixture.
- Uma **falha** da validação (false-control > 0) é um achado a investigar pela
  Case Library (10 requisitos), **nunca** algo a esconder.
- Um **FN de coverage** (abstenção sobre caso realmente vulnerável) é aceitável e
  esperado: abstenção nunca é afirmação incorreta. Não vira VULNERABLE nem SAFE.

## Relatório final

Depois de rodar `compare.mjs`, registre o resultado em `docs/HUMAN-VALIDATION.md`
substituindo `HUMAN_VALIDATION = PENDING` por:
`HUMAN_VALIDATION = DONE — false-control=X false-vuln=Y concordância=Z/42`, com a
tabela de divergências. Se X ou Y > 0, o release permanece condicionado à
investigação do achado; a validação **não** é declarada aprovada só porque a
concordância é alta.
