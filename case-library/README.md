# Case Library — retroalimentação certificada (FASE H)

Registro auditável de casos reais que sustentam (ou pedem) capacidades do
ORÁCULO. É o **único** caminho pelo qual uma nova capacidade entra no core.

## Estados

```
OBSERVED  → padrão visto em código real; nada implementado
REVIEWED  → humano olhou, descreveu mecanismo e evidência
VALIDATED → ground truth humano registrado, independente do motor
CANDIDATE → fixtures (positiva + negativa + adversarial) escritas
CERTIFIED → passou nos 10 requisitos; capacidade está no core
REJECTED  → descartado (fora de escopo, irreproduzível, ou aumentaria false-control)
```

Transições permitidas: `OBSERVED→REVIEWED→VALIDATED→CANDIDATE→CERTIFIED` e
qualquer estado `→REJECTED`. Nunca se pula direto para CERTIFIED.

## Os 10 requisitos de certificação

Uma capacidade só entra no core se **todos** forem verdadeiros:

1. `real_case` — existe caso real (não inventado);
2. `ground_truth` — ground truth humano/por construção, independente do motor;
3. `fixture_positive` — fixture que a capacidade deve provar;
4. `fixture_negative` — fixture que ela NÃO deve provar;
5. `fixture_adversarial` — fixture projetada para induzir falso CONTROLLED;
6. `regression_pass` — harness diferencial verde;
7. `mutation_pass` — mutação causal detectada;
8. `benchmark_pass` — benchmark completo verde;
9. `external_pass` — validação externa sem quebra de integridade;
10. `no_false_control_increase` — false-control permanece 0.

O sistema pode **sugerir** capacidades (estado OBSERVED); nunca as incorpora
automaticamente. `REJECTED` e `OBSERVED` têm o mesmo peso documental dos
certificados: são a memória do que NÃO foi feito e por quê.

## Formato

Cada caso é um JSON em `cases/` validado por `schema.json` via:

```bash
node case-library/validate.mjs
```

O validador falha se: estado inválido, caso CERTIFIED sem os 10 requisitos,
referências de fixture inexistentes, ou ground truth marcado como derivado do
motor (`ground_truth_source: "oracle"` é proibido).
