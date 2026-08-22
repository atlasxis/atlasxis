---
name: Missed case / unsupported pattern
about: Padrão legítimo ficou INSUFFICIENT/NOT_ANALYZED (abstenção que poderia ser prova)
title: "[missed-case] "
labels: missed-case
---

<!-- Abstenção NÃO é um bug de corretude — é conservadorismo. Mas um padrão
legítimo e comum que poderia ser provado estruturalmente é um GAP útil.
NÃO é pedido para "assumir" autorização: só para provar o que é provável. -->

## Mecanismo de autorização
<!-- self-scope, post-read, helper, parent-child, RLS, ... -->

## Código sintético mínimo
```ts
```

## O que o ORÁCULO disse
- Decisão: `INSUFFICIENT_EVIDENCE` / `NOT_ANALYZED`
- Reason code:

## Por que é estruturalmente provável (sem assumir nada)
<!-- Mostre a cadeia fonte → recurso → autorização → identidade → sink. -->
