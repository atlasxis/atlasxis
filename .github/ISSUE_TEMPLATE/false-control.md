---
name: False control (CRÍTICO)
about: O ORÁCULO disse CONTROLLED, mas o acesso NÃO está autorizado
title: "[false-control] "
labels: false-control
---

<!-- False-control é o erro mais grave: o ORÁCULO afirmou evidência de
autorização que não existe. NÃO cole código privado ou de terceiros —
reduza a um exemplo SINTÉTICO mínimo. -->

## Código sintético mínimo que reproduz
```ts
// route.ts (+ lib/sql se necessário)
```

## O que o ORÁCULO disse
- Decisão: `CONTROLLED`
- Reason code:
- Saída de `node core/cli.mjs report <path>`:

## Por que o acesso NÃO está autorizado
<!-- Descreva o caminho de acesso não autorizado alcançável. -->

## Ground truth
- Correto seria: `VULNERABLE` / `INSUFFICIENT` / `NOT_ANALYZED`
- Justificativa:
