# Atlasxis — Authorization Proof Engine

[English](README.md)

O Atlasxis analisa estaticamente rotas de API (Next.js + Supabase) e responde,
**por sink de dados**, uma única pergunta com três respostas possíveis:

> **"Existe evidência estrutural suficiente para provar autorização neste caminho?"**

- **`CONTROLLED`** — evidência suficiente de autorização (cadeia de prova completa);
- **`VULNERABLE`** — evidência positiva de caminho alcançável sem autorização;
- **`INSUFFICIENT_EVIDENCE` / `NOT_ANALYZED` / `OUT_OF_SCOPE_*`** — não foi possível provar.

## Por que existe

Falha de autorização por objeto (IDOR/BOLA) é o principal risco de segurança
em APIs, e é a mais difícil de pegar com scanners baseados em padrão: o bug é
uma verificação que *falta*, não um código malicioso. Verificar que uma tabela
do Supabase *tem* Row Level Security não é o mesmo que verificar que a regra
realmente restringe as linhas ao dono. O Atlasxis tenta **provar** a cadeia de
autorização e se recusa a chutar quando não consegue.

## O que ele NÃO é

- **Não** é um scanner de vulnerabilidades genérico (XSS, SQLi, segredos, dependências).
- **Nunca** afirma "seu sistema está seguro". Ausência de achado não é prova de segurança.
- **Nunca** converte falta de evidência em veredito: quando não consegue provar, ele **abstém** e diz o porquê.
- **Nunca** executa o código analisado. A análise é 100% estática.

Esse contrato (CORRETUDE > COBERTURA) está em [PRODUCT-CONTRACT.md](PRODUCT-CONTRACT.md).

## Instalação

Requer Node ≥ 20.

```bash
npm install --save-dev atlasxis
```

Ou rode uma vez sem instalar:

```bash
npx atlasxis scan .
```

## Uso

```bash
npx atlasxis scan .                        # relatório markdown
npx atlasxis scan . --format json          # machine-readable
npx atlasxis scan . --format sarif         # para ferramentas de code scanning
npx atlasxis scan . --ci                   # política de CI (exit 2 se VULNERABLE)
npx atlasxis report . --out prova.md       # Proof Report por sink (arquivo + linha)
npx atlasxis explain INSUFFICIENT_RLS_UNKNOWN
npx atlasxis version
```

Com evidência de RLS das suas migrações:

```bash
npx atlasxis scan . --rls ./supabase/migrations
```

## Exemplo de saída

Rode contra uma das fixtures sintéticas do repositório:

```bash
git clone https://github.com/atlasxis/atlasxis.git && cd atlasxis
npm install
npx atlasxis report public-corpus/service-role-vuln
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
gating). Nunca é declarado só porque "não achou verificação de dono".

## Como ler os vereditos

| Veredito | Significa | NÃO significa |
|---|---|---|
| `CONTROLLED` | ProofChain íntegra: há evidência estrutural de autorização neste caminho | que o resto do sistema é seguro |
| `VULNERABLE` | evidência **positiva** de acesso não autorizado alcançável | (só sai com prova positiva, nunca por ausência) |
| `INSUFFICIENT_EVIDENCE` | não foi possível provar autorização nem vulnerabilidade | **NÃO é `SAFE`**: precisa de revisão humana |
| `NOT_ANALYZED` | fora do que o motor modela (sintaxe/framework/sink) | **NÃO é `SAFE`**: precisa de revisão humana |
| `OUT_OF_SCOPE_PROVEN` | rota provadamente admin ou webhook: o modelo de posse não se aplica | que a operação de admin é desejável (é política, não prova) |

`atlasxis explain <REASON_CODE>` detalha qualquer um dos 35 reason codes: o que
prova e o que **não** prova. **Ausência de prova não é prova de ausência.**

## CI

O jeito mais simples é usar o pacote npm:

```yaml
# .github/workflows/atlasxis.yml
name: atlasxis
on: [pull_request]
jobs:
  authz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx --yes atlasxis scan . --ci
```

Política explícita: **só `VULNERABLE` falha o build** (`--fail-on insufficient`
deixa mais rígido). `INSUFFICIENT` e `NOT_ANALYZED` **nunca** são tratados como
seguros; são sempre reportados.

Também há uma action composta em
[.github/actions/atlasxis-scan](.github/actions/atlasxis-scan).

## Limitações (leia antes de confiar)

Escopo atual: **rotas de API** do Next.js (App/Pages Router) + cliente JS do
Supabase, com RLS lida das migrações SQL. Server actions, chamadas ao Supabase
feitas no navegador, Prisma/Drizzle e outros frameworks ficam fora do modelo:
saem como `NOT_ANALYZED` ou nem são descobertos, nunca como veredito. Lista
completa em [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
**Validação humana independente: PENDENTE.**

## Validação (corpus público)

Todos os números abaixo são reproduzíveis com `npm test` neste repositório e
vêm **só do corpus público**. Detalhes em [docs/PUBLIC-METRICS.md](docs/PUBLIC-METRICS.md).

- **532 casos sintéticos** rotulados por construção: 0 false-control, 0 false-vuln;
- **Mutation testing** sobre fixtures CONTROLLED: 0 survivors;
- **17 padrões adversariais** feitos para induzir um `CONTROLLED` falso: abstenção correta em todos;
- **8 mini-projetos sintéticos** ([`public-corpus/`](public-corpus/)) demonstrando cada mecanismo, Proof Integrity = 0;
- **Corpus cego** de 42 casos aguardando auditor humano ([blind-validation/](blind-validation/)).

> **Honestidade metodológica**: esses recalls valem *no corpus sintético deste
> repositório*. Medem se o motor prova o que o corpus contém, não o que existe
> no mundo real. **Não há métrica de recall do mundo real nesta distribuição pública.**

## Modelo de confiança

- O Atlasxis **prova** propriedades estruturais. Ele não executa código nem
  observa runtime. Uma prova `CONTROLLED` vale o que valem suas *assumptions*,
  listadas em cada achado e em `atlasxis explain`.
- **False-control = 0** é o eixo do produto: ele prefere abster a arriscar um
  `CONTROLLED` errado. A cobertura é deliberadamente conservadora.
- **`VULNERABLE` exige evidência positiva**; nunca é inferido de ausência.
- Capacidade nova só entra no motor pelo processo de certificação de 10
  requisitos, nunca por heurística improvisada ou "aprendizado" automático.

## Segurança operacional

Analisar código de terceiros é tratado como operação hostil: symlinks não são
seguidos, scripts de instalação do alvo nunca rodam, o `.env` do alvo nunca é
lido, há limites de arquivos/bytes/tempo, e a saída é sanitizada contra
vazamento de segredos. Ver [SECURITY.md](SECURITY.md) e
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Arquitetura

Security IR → extração estrutural (AST TypeScript) → provas por mecanismo
(ownership helper/inline, post-read gate, transitivo, RLS, role gate, webhook)
→ decisão por sink `(status, reasonCode)` → relatórios (markdown/JSON/SARIF).
Ver [ARCHITECTURE.md](ARCHITECTURE.md) e [docs/CORE-IR.md](docs/CORE-IR.md).

## Contribuição

Reporte casos com **código sintético mínimo** (nunca código privado ou de
terceiros) usando os templates de issue. Capacidades novas seguem o processo de
certificação em [case-library/README.md](case-library/README.md). Ver
[CONTRIBUTING.md](CONTRIBUTING.md). Rode `npm test` antes de abrir um PR.

## Licença

[MIT](LICENSE). Cobre o engine, a CLI, a documentação e as fixtures sintéticas
de `public-corpus/`. Nenhum código de terceiros é redistribuído.

Mudanças, e o que foi removido ou substituído por privacidade na distribuição
pública: [CHANGELOG.md](CHANGELOG.md). O Atlasxis foi publicado antes com o
nome ORÁCULO CORE.
