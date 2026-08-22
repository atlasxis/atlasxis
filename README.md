# ORÁCULO — Authorization Proof Engine

O ORÁCULO analisa estaticamente rotas de API (Next.js/Supabase) e responde, **por
sink de dados**, uma única pergunta com três respostas possíveis:

> **"Existe evidência estrutural suficiente para provar autorização neste caminho?"**

- **`CONTROLLED`** — evidência suficiente de autorização (cadeia de prova completa);
- **`VULNERABLE`** — evidência positiva de caminho alcançável sem autorização;
- **`INSUFFICIENT_EVIDENCE` / `NOT_ANALYZED` / `OUT_OF_SCOPE_*`** — não foi possível provar.

## O que ele NÃO é

- **Não** é um scanner de vulnerabilidades genérico (XSS, SQLi, secrets, deps).
- **Não** afirma, nunca, "seu sistema está seguro". Ausência de finding não é prova de segurança.
- **Não** converte falta de evidência em veredito: quando não consegue provar, ele **abstém** e diz o porquê.
- **Não** executa o código analisado — a análise é 100 % estática.

Esse contrato (CORRETUDE > COBERTURA) está formalizado em [PRODUCT-CONTRACT.md](PRODUCT-CONTRACT.md).

## Instalação

Requer Node ≥ 20.

```bash
git clone <repo> && cd oracle-core
npm install
npm test        # gates públicos reprodutíveis
```

## Quick start

```bash
npx oracle scan ./meu-projeto                 # relatório markdown
npx oracle scan ./meu-projeto --format json   # machine-readable
npx oracle scan ./meu-projeto --ci            # política de CI (exit 2 se VULNERABLE)
npx oracle report ./meu-projeto --out proof.md # Proof Report por sink (arquivo+linha)
npx oracle explain INSUFFICIENT_RLS_UNKNOWN   # o que um reason code significa
npx oracle version
```

Com evidência RLS: `npx oracle scan ./meu-projeto --rls ./meu-projeto/supabase/migrations`.

## Exemplo de saída

Rode contra uma das fixtures sintéticas do repositório:

```bash
npx oracle report public-corpus/service-role-vuln
```

```
### VULNERABLE — `DELETE public-corpus/service-role-vuln/src/app/api/notes/[id]/route.ts`
- Sink: delete `notes` (cliente: service_role)
- Reason code: VULNERABLE_NO_GATING_SERVICE_ROLE
- ProofChain:
    SOURCE        id                      (controlável pelo cliente)
    RESOURCE      notes id=id
    GUARD         (nenhum guard vivo encontrado)
    IDENTITY      same=false
    SINK          delete notes            (service_role — bypassa RLS)
```

Cada decisão carrega um **reason code estável** e, quando há prova, uma
**ProofChain**: fonte → recurso → autorização → guard → identidade → sink, com
testemunhas estruturais e assumptions explícitas. `VULNERABLE` exige evidência
**positiva** (entrada controlável + sink alcançável + ausência comprovada de
gating); nunca é declarado só porque "não achou ownership".

## Como ler os vereditos

| Veredito | Significa | NÃO significa |
|---|---|---|
| `CONTROLLED` | ProofChain íntegra: há evidência estrutural de autorização para este caminho | que o resto do sistema é seguro |
| `VULNERABLE` | evidência **positiva** de acesso não autorizado alcançável | (só é emitido com prova positiva, nunca por ausência) |
| `INSUFFICIENT_EVIDENCE` | não foi possível provar nem autorização nem vulnerabilidade | **NÃO é `SAFE`** — precisa de revisão humana |
| `NOT_ANALYZED` | fora do que o motor modela (sintaxe/framework/sink não suportado) | **NÃO é `SAFE`** — precisa de revisão humana |
| `OUT_OF_SCOPE_PROVEN` | rota provadamente admin/webhook: o modelo de posse não se aplica | que a operação de admin é desejável (é política, não prova) |

`oracle explain <REASON_CODE>` detalha qualquer um dos 35 reason codes: o que
prova e o que **não** prova. **Ausência de prova não é prova de ausência.**

## Como criar uma fixture

```bash
# 1. um mini-projeto sintético (domínio genérico, sem lógica de negócio real)
mkdir -p minha-fixture/src/app/api/coisa
$EDITOR minha-fixture/src/app/api/coisa/route.ts
# 2. veja o veredito e a prova
npx oracle scan minha-fixture --format json
npx oracle report minha-fixture
```

Os exemplos em [`public-corpus/`](public-corpus/) cobrem cada mecanismo
suportado. Ver [CONTRIBUTING.md](CONTRIBUTING.md) para submeter casos.

## Limitações (leia antes de confiar)

Escopo atual: Next.js App/Pages Router + Supabase (JS client), RLS via corpus
SQL de migrações. Fora disso → `NOT_ANALYZED`, jamais um veredito. A lista
completa e honesta está em [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
**Validação humana independente: PENDING** — ver [docs/HUMAN-VALIDATION.md](docs/HUMAN-VALIDATION.md).

## Validação (corpus público)

Todos os números abaixo são reproduzíveis com `npm test` neste repositório e
derivam **exclusivamente do corpus público**. Detalhes em
[docs/PUBLIC-METRICS.md](docs/PUBLIC-METRICS.md).

- **532 casos** sintéticos rotulados por construção: 0 false-control, 0 false-vuln ([docs/BENCHMARK-REPORT.md](docs/BENCHMARK-REPORT.md));
- **Mutation testing** sobre fixtures CONTROLLED: 0 survivors ([docs/MUTATION-REPORT.md](docs/MUTATION-REPORT.md));
- **17 padrões adversariais** projetados para induzir falso CONTROLLED — abstenção correta em todos;
- **8 mini-projetos sintéticos** ([`public-corpus/`](public-corpus/)) que demonstram cada mecanismo, com Proof Integrity = 0;
- **Corpus cego** de 42 casos aguardando auditor humano ([blind-validation/](blind-validation/)).

> **Honestidade metodológica**: os recalls valem *no corpus sintético que este
> repositório contém* — medem se o motor prova o que o corpus contém, não o que
> existe no mundo real. **Não há métrica de recall do mundo real nesta
> distribuição pública** (exigiria ground truth sobre código real, não
> redistribuível). Validação humana independente: **PENDING**.

## Modelo de confiança

- O ORÁCULO **prova** propriedades estruturais; ele não executa o código nem
  observa runtime. Uma prova `CONTROLLED` é tão boa quanto suas *assumptions*
  (listadas em cada finding e em `oracle explain`).
- A política de **false-control = 0** é o eixo do produto: preferimos abster
  (`INSUFFICIENT`) a arriscar um `CONTROLLED` incorreto. Por isso a cobertura é
  deliberadamente conservadora.
- **VULNERABLE** exige evidência positiva; nunca é inferido de ausência.
- Uma capacidade nova só entra no motor pelo processo de certificação de 10
  requisitos (ver abaixo) — nunca por heurística ad-hoc ou "aprendizado" automático.

## Segurança operacional

Analisar código de terceiros é tratado como operação hostil: symlinks não são
seguidos, lifecycle scripts do alvo nunca rodam, `.env` do alvo nunca é lido,
limites de arquivos/bytes/tempo são impostos e a saída é sanitizada contra
vazamento de segredos. Ver [SECURITY.md](SECURITY.md) e
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md); verificado pelo gate 8 do CI
(`core/harness/operational-security.mjs`).

## Arquitetura

Security IR → extração estrutural (TypeScript AST) → provas por mecanismo
(ownership helper/inline, post-read gate, transitivo, RLS, role-gate, webhook)
→ decisão por sink `(status, reasonCode)` → relatórios (markdown/JSON/SARIF).
Ver [ARCHITECTURE.md](ARCHITECTURE.md) e [docs/CORE-IR.md](docs/CORE-IR.md).

## CI / GitHub Action

Action oficial em [.github/actions/oracle-scan](.github/actions/oracle-scan);
workflow de exemplo em [.github/workflows/oracle.yml](.github/workflows/oracle.yml).
Política explícita: **só `VULNERABLE` falha o build** (endurecível com
`fail-on: insufficient`). `INSUFFICIENT` e `NOT_ANALYZED` **nunca** são tratados
como SAFE — são sempre reportados.

## Contribuição

Novas capacidades só entram no core pelo processo de certificação da Case
Library (caso real → ground truth → fixtures positiva/negativa/adversarial →
regressão → mutation → benchmark → validação externa → sem aumento de
false-control). Ver [case-library/README.md](case-library/README.md).

## Licença

[MIT](LICENSE). A licença cobre o engine, a CLI, a documentação e as fixtures
sintéticas de `public-corpus/` — nenhum código de terceiros é redistribuído.

---

Mudanças e o que foi removido/substituído por privacidade na distribuição
pública: ver [CHANGELOG.md](CHANGELOG.md).
