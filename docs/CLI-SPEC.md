# CLI — especificação (v1.0.0)

Binário: `atlasxis` (`core/cli.mjs`, via `npm install` → `bin`).
Análise 100% estática: **nenhum código do projeto analisado é executado**.

## Comandos

| Comando | Função |
|---|---|
| `atlasxis scan <path>` | Analisa o projeto e emite o relatório (`--format json\|markdown\|sarif`) |
| `atlasxis scan <path> --ci` | Saída JSON + política de CI (exit 2 se houver VULNERABLE) |
| `atlasxis report <path>` | Proof Report por sink: arquivo, linha, ProofChain completa (`--out <f.md>`) |
| `atlasxis explain <REASON_CODE>` | Explica um reason code: status, significado, o que prova, o que não prova |
| `atlasxis baseline <path>` | Grava `.atlasxis-baseline.json` com as decisões atuais |
| `atlasxis diff <baseline> <path>` | Regressões de autorização vs baseline (exit 1 se houver) |
| `atlasxis version` | Versão do engine |

Flags: `--rls <dir>` (corpus SQL), `--fail-on insufficient` (endurece a política
de CI), `--timeout <s>` (padrão 120 s), `--out <arquivo>` (report).

## Exit codes (estáveis)

| Código | Significado |
|---|---|
| 0 | Sucesso (em `--ci`: nenhum VULNERABLE) |
| 1 | Uso incorreto ou erro interno |
| 2 | Política de CI violada (`--ci` com VULNERABLE; ou `--fail-on insufficient` com VULNERABLE/INSUFFICIENT/UNVERIFIED) |
| 3 | Caminho inexistente ou não-diretório |
| 4 | Limite operacional excedido (timeout, nº de arquivos, bytes) |

## Política de CI (explícita)

- `VULNERABLE` → **falha** (exit 2).
- `INSUFFICIENT_EVIDENCE` / `OUT_OF_SCOPE_UNVERIFIED` → **não falham** por
  padrão, mas são sempre contados e impressos no stderr. **Nunca** são tratados
  como SAFE. `--fail-on insufficient` os torna bloqueantes.
- `NOT_ANALYZED` → nunca falha, nunca é SAFE; aparece no relatório para revisão
  humana.

## Decisões possíveis (contrato)

`CONTROLLED` (PROVEN) · `VULNERABLE` (DEMONSTRATED) · `INSUFFICIENT_EVIDENCE`
(UNPROVEN) · `NOT_ANALYZED` (UNMODELED) · `OUT_OF_SCOPE_PROVEN` ·
`OUT_OF_SCOPE_UNVERIFIED`.

## Robustez e segurança operacional

- Projeto inexistente/não-diretório → erro explícito, exit 3.
- Projeto vazio (0 rotas) → relatório válido com `totalSinks: 0` e nota.
- Arquivo malformado → `NOT_ANALYZED_PARSE_ERROR` naquela rota; scan continua.
- Symlinks **não são seguidos** (arquivo ou diretório) — sem escape do root.
- Limites: 20 000 arquivos, 2 MB/arquivo, 256 MB/projeto, profundidade 12,
  timeout 120 s (configurável). Exceder → exit 4 com mensagem explícita.
- Lifecycle scripts do alvo nunca rodam; `.env` do alvo nunca é lido.
- Saída sanitizada: JWTs, chaves de API e connection strings viram
  `[REDACTED-SECRET]`.
- Determinismo: mesma entrada ⇒ bytes idênticos (sem timestamps/aleatoriedade).

Verificado por `core/harness/operational-security.mjs` (gate 8 do CI).
