# PRODUCT-CONTRACT — Atlasxis v1

Este contrato define exatamente o que o produto promete e o que NÃO promete.
É vinculante: qualquer afirmação fora dele é bug de comunicação.

## O Atlasxis É

- Um **Authorization Proof Engine**: prova, por sink, evidência estrutural de
  autorização.
- **Conservador**: prefere abster-se a afirmar sem prova.
- **Evidence-first**: toda decisão CONTROLLED carrega uma ProofChain rastreável
  ao código (source, resource, authorization, guard, identity, sink, assumptions).
- **Determinístico**: mesma entrada → mesma decisão e mesma prova.
- **Abstenção explícita**: `INSUFFICIENT` / `NOT_ANALYZED` são resultados de
  primeira classe, não falhas.

## O Atlasxis NÃO

- não substitui pentest;
- não substitui revisão humana;
- não garante ausência de IDOR;
- não garante segurança completa;
- não entende qualquer framework (v1 = Next.js App Router + Supabase);
- não entende qualquer SQL (parseia um subset explícito);
- não prova qualquer RLS automaticamente (só semânticas demonstradas);
- não afirma segurança quando a evidência é insuficiente;
- **nunca afirma "não há vulnerabilidade".**

## Significado das decisões

| Decisão | Significado exato |
|---|---|
| `CONTROLLED` | evidência estrutural suficiente de autorização para ESTE sink |
| `VULNERABLE` | fluxo não autorizado estruturalmente demonstrado e alcançável (evidência positiva, não mera ausência) |
| `INSUFFICIENT_EVIDENCE` | não foi possível provar autorização nem vulnerabilidade |
| `NOT_ANALYZED` | sintaxe/caso fora da capacidade estrutural atual |
| `OUT_OF_SCOPE_PROVEN` | fora do modelo de segurança, com condição comprovada |
| `OUT_OF_SCOPE_UNVERIFIED` | provável fora do modelo, sem prova |

## Garantias de soundness (verificadas)

- CONTROLLED exige ProofChain completa + `identity.same === true` + guard que
  rejeita e domina o sink (invariante executável `validateDecision`).
- UNKNOWN nunca vira CONTROLLED; erro de parser nunca vira CONTROLLED;
  ambiguidade nunca vira CONTROLLED.
- Nome (coluna/função/variável/"admin"), comentário e string nunca são prova.
- service_role não é tratado como protegido por RLS.
- Identidade verificada == identidade do sink (salvo pai-filho provado).

Todas exercitadas por benchmark (532), mutation (130/130), repositório
adversarial (17 padrões) e auditoria byte-exato dos CONTROLLED reais.

## Limites declarados

ORMs não-Supabase, RLS por EXISTS/subquery, predicados em lambda, alias por
dataflow profundo, truth table > 14 átomos, GRANTs de tabela, RPC/views/
triggers → abstenção. Ver `docs/LIMITATIONS.md`.

## Compromisso epistemológico

Toda conclusão do produto distingue **FATO** (o que o código mostra),
**INFERÊNCIA** (o que se deduz sob assumptions declaradas) e **LIMITAÇÃO** (o
que permanece não provado). O produto vende prova auditável — não veredito cego.
