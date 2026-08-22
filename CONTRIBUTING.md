# Contribuindo com o ORÁCULO

O ORÁCULO evolui por **evidência**, não por opinião. O princípio é
`CORRETUDE > COBERTURA > CONVENIÊNCIA`. Uma capacidade nova só entra no engine
depois de provar que não introduz false-control.

## Como reportar um caso

Abra uma issue usando um dos templates em `.github/ISSUE_TEMPLATE`:

- **false-control** — o ORÁCULO disse `CONTROLLED` mas o acesso não está
  autorizado (o erro mais grave);
- **false-vulnerable** — disse `VULNERABLE` sem evidência positiva real;
- **missed-case** — um padrão legítimo que deveria ser provável ficou
  `INSUFFICIENT`/`NOT_ANALYZED`;
- **unsupported-pattern** — sintaxe/framework fora do escopo atual;
- **parser-bug** / **security-issue** (ver `SECURITY.md` para divulgação).

Inclua **código sintético mínimo** que reproduza o comportamento. **Não cole
código privado ou de terceiros** — reduza a um exemplo autocontido. O scanner de
publicação (`node core/harness/publication-scan.mjs`) roda no CI e rejeita
segredos, `.env`, caminhos pessoais e nomes de projetos privados.

## Como adicionar uma fixture

1. Crie um mini-projeto sintético em `public-corpus/<mecanismo>/` (veja os
   existentes: `route.ts`, opcional `src/lib/*.ts`, opcional `supabase/*.sql`).
2. Domínio genérico (notes/widgets/teams). **Sem lógica de negócio real, sem
   tabelas/rotas de projetos reais.**
3. Rode `node core/cli.mjs scan public-corpus/<mecanismo> --format json` e
   confirme o veredito.
4. Se for um mecanismo novo demonstrado, registre um caso em
   `case-library/cases-public/` seguindo `case-library/schema.json`.

## O processo de certificação (10 requisitos)

Uma capacidade nova só é `CERTIFIED` (e só então entra no core) com **todos**:

1. caso real; 2. ground truth independente (humano ou por construção —
**nunca** derivado do próprio ORÁCULO); 3. fixture positiva; 4. negativa;
5. adversarial; 6. regressão verde; 7. mutation verde; 8. benchmark verde;
9. validação verde; 10. false-control permanece 0.

Um GAP observado fica `OBSERVED` — nunca é promovido a funcionalidade sem passar
por isso. Ver `case-library/README.md`.

## Antes de abrir um PR

```bash
npm test        # = node core/ci.mjs --public (gates reprodutíveis)
```

Todos os gates públicos devem passar, incluindo o scanner de publicação. Não
altere o contrato do produto (`PRODUCT-CONTRACT.md`): o ORÁCULO nunca afirma
"seguro", `INSUFFICIENT`/`NOT_ANALYZED` nunca são `SAFE`, e `VULNERABLE` exige
evidência positiva.
