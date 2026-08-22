# RELEASE-CHECKLIST — oracle-core v1.0.0-rc1

- [x] baseline preservado (checksums 6/6 OK)
- [x] rescue/ preservado
- [x] analyzer5 preservado (byte-idêntico)
- [x] analyzer6 preservado (byte-idêntico)
- [x] benchmark ≥ 500 (532 casos)
- [x] mutation testing executado (130/130, 0 survivors)
- [x] Proof Integrity validado (invariante executável, 0 falhas)
- [x] multi-sink validado (decisão por sink, agregação derivada)
- [x] post-read validado (verb-agnóstico, identidade obrigatória)
- [x] transitive evidence validado (membership+fk; limites em EXISTS documentados)
- [x] RLS validado (41/41 policies reais parseadas + 23 fixtures)
- [x] cross-file validado (import-scoped, ambiguidade fail-closed)
- [x] discovery validado (function/arrow/params.id/searchParams)
- [x] adversarial corpus validado (nome/comentário/string nunca é prova)
- [x] ≥10 repos externos analisados (13 repos, 552 sinks, 0 integridade quebrada)
- [~] blind validation — corpus preparado; classificação humana ao vivo PENDENTE (LIMITATIONS.md)
- [x] 0 false-control nos testes validados
- [x] 0 regressão
- [x] determinismo validado
- [x] todas as divergências explicadas (divergence-justifications.json)
- [x] todas as limitações documentadas (LIMITATIONS.md)
- [x] CLI funcionando (scan/baseline/diff)
- [x] relatório por sink funcionando
- [x] JSON funcionando
- [x] Markdown funcionando
- [x] SARIF funcionando
- [x] CI funcionando (core/ci.mjs, 7/7 gates: + repositório adversarial)
- [x] docs de produto escritos
- [x] instalação limpa (npm install + oracle scan em dir isolado, sem paths de dev)
- [x] repositório adversarial 17 padrões (abstenção correta, 0 false-control)
- [x] determinismo byte-a-byte dos relatórios (json/markdown/sarif)
- [x] schema JSON e SARIF 2.1.0 validados
- [x] RELEASE-NOTES.md, SECURITY.md escritos
- [x] package.json com bin `oracle` e dependência typescript
- [x] corpus de validação cega preparado (blind-validation/, HUMAN_VALIDATION=PENDING)

Único item não 100%: **validação humana cega ao vivo**, que requer um auditor
humano e não pode ser cumprida por execução autônoma. Reportado como limitação
explícita, não fabricado. Todos os gates TÉCNICOS (A–J) passam.

Tag local: `v1.0.0-rc1` (sem push, sem publish).
