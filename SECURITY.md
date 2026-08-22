# SECURITY — política e modelo de segurança do ORÁCULO

## O que uma decisão significa

- `CONTROLLED` = **evidência estrutural suficiente de autorização para este sink**.
  Nada além disso. Não é "seguro em absoluto".
- `VULNERABLE` = fluxo não autorizado estruturalmente demonstrado e alcançável.
- `INSUFFICIENT_EVIDENCE` = não certificado (nem seguro, nem vulnerável provado).
- `NOT_ANALYZED` = não modelável estruturalmente.
- `OUT_OF_SCOPE_PROVEN` / `OUT_OF_SCOPE_UNVERIFIED` = fora do modelo de segurança
  (com/sem prova).

**O ORÁCULO nunca afirma ausência de vulnerabilidades.**

## Invariantes constitucionais (não relaxáveis)

1. CONTROLLED exige ProofChain completa.
2. CONTROLLED exige identidade verificada == identidade do sink (salvo pai-filho
   provado).
3. UNKNOWN nunca vira CONTROLLED.
4. Assumption perigosa nunca sustenta CONTROLLED (`SUPABASE_DEFAULT_GRANTS` é
   bloqueada por `validateDecision`).
5–8. Nome de coluna / função / variável / "admin" nunca é prova sozinho.
9. "published"/"public"/"visible" não são semântica pública sem evidência.
10. RLS só como evidência parseada/provada ou assumption explícita.
11. service_role não é tratado como protegido por RLS.
12. RLS não prova proteção de código que a bypassa.
13. Check em recurso A não prova autorização para sink em recurso B.
14. Guard que não domina o sink não prova autorização.
15. Dead code não prova autorização.
16. Erro de parsing não produz CONTROLLED.
17. Ambiguidade não produz CONTROLLED.
18. Código não suportado → INSUFFICIENT/NOT_ANALYZED.
19. O ORÁCULO nunca afirma ausência de vulnerabilidade.
20. CONTROLLED = evidência estrutural suficiente de autorização para o sink.

Cada invariante é exercitado por fixtures e/ou pelo `validateDecision` executável
e pelo repositório adversarial (`core/harness/adversarial-repo.mjs`).

## Segurança operacional do motor

- Somente leitura; nunca escreve no alvo.
- Não executa o código analisado (análise estática por AST).
- Determinístico, sem rede, sem estado oculto.
- Conteúdo do código (nomes, comentários, strings) é DADO, nunca prova.
- Sem LLM na decisão.

## Reporte de problemas

Divergência de checksum de baseline, false-control, ou quebra de Proof Integrity
são incidentes de máxima severidade: reproduza com `node core/ci.mjs` e registre
o caso mínimo. Correção > cobertura sempre.
