# Atlasxis — Métricas públicas (corpus público apenas)

_Gerado por `node release/public-metrics.mjs`. Fontes: benchmark sintético, mutation, corpus público sintético. **Nenhum número vem de corpora privados ou de terceiros.** Cada métrica declara seu ground truth._

| Métrica | Valor | Ground truth |
|---|---|---|
| Correção (benchmark sintético) | 532/532 | 532 casos rotulados **por construção** (21 categorias) |
| False-control | 0 | benchmark — NÃO-CONTROLLED declarado CONTROLLED |
| False-vuln | 0 | benchmark — NÃO-VULNERABLE declarado VULNERABLE |
| Recall CONTROLLED (sintético) | 232/232 | **só no corpus sintético**; não é recall do mundo real |
| Recall VULNERABLE (sintético) | 143/143 | idem |
| Abstenção correta (sintético) | 133/133 | casos onde abster É a resposta certa |
| Mutation score | 62/62 (0 survivors) | mutações causais em fixtures CONTROLLED públicas |
| Validação pública (mecanismos) | 8/8 | 8 mini-projetos sintéticos, ground truth por construção |
| Proof Integrity (público) | 0 falhas | invariante executável em toda decisão |
| Adversarial | fail=0 fc=0 fv=0 | 38 padrões projetados para induzir false-control |
| Auditoria de RLS (`atlasxis rls`) | 46 casos, fail=0 fc=0 fv=0, mutações 35/35 | positivos, negativos e armadilhas por construção (semântica do PostgreSQL) |
| Server actions | 25 casos, fail=0 fc=0 fv=0, mutações 13/13 | fixtures por construção + validação em 7 projetos open source reais (integridade 0) |
| Segurança operacional | 15/15 | projeto malicioso não compromete o analisador |
| Determinismo | verificado | 2 execuções byte-idênticas |
| **Human agreement** | **PENDING** | corpus cego de 42 casos em blind-validation/; nenhum auditor humano — não fabricado |

Distribuição da validação pública: CONTROLLED=5 NOT_ANALYZED=1 OUT_OF_SCOPE_PROVEN=1 VULNERABLE=1

## Leitura honesta

- Os recalls acima valem **exclusivamente no corpus sintético que este repositório contém**. Medem se o motor prova o que o corpus contém — não o que existe no mundo real.
- **Não há métrica de recall do mundo real neste repositório público**: isso exigiria ground truth sobre código real, que não é redistribuível. O mantenedor mantém essa validação separadamente sobre corpora privados.
- Abstenção não é defeito: sem evidência suficiente, `INSUFFICIENT`/`NOT_ANALYZED` são a resposta correta e **nunca** significam `SAFE`.
- `VULNERABLE` no benchmark exige evidência positiva (fonte controlável + sink alcançável + ausência de gating).
