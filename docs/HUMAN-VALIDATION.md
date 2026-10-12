# HUMAN-VALIDATION — FASE 8 (validação humana cega)

## Estado: corpus preparado; classificação humana ao vivo é a etapa que exige uma pessoa

A validação cega exige um auditor humano que classifique handlers SEM ver a saída
do Atlasxis. Operando de forma autônoma, o motor NÃO pode fabricar um humano —
declarar "validação humana concluída" sem um humano seria exatamente a mentira
que o Atlasxis existe para evitar. Portanto:

### O que foi entregue (executável, sem humano)

O **equivalente cego automatizável**: o benchmark de 532 casos tem ground truth
atribuído POR CONSTRUÇÃO, antes de o Atlasxis rodar, e o ground truth NUNCA é
alterado para coincidir com o motor. Isso satisfaz "ground truth independente" e
"não alterar ground truth para coincidir com Atlasxis". Resultado: 100% de
correção, 0 false-control. Ver `BENCHMARK-REPORT.md`.

Além disso, amostras CONTROLLED de código real (projeto-auditado-privado, corpus-externo, corpus-externo,
corpus-externo) foram auditadas byte-exato = TRUE_CONTROL (ver `EXTERNAL-VALIDATION.md`).

### O que falta (requer uma pessoa) — honestamente em aberto

O corpus cego para humano está preparado em `core/benchmark/` (código + ground
truth independente, com a decisão do Atlasxis omitível). O protocolo:

1. Dar ao auditor apenas o código + contexto, sem a decisão do Atlasxis.
2. Auditor classifica CONTROLLED / VULNERABLE / INSUFFICIENT.
3. Comparar humano × Atlasxis; medir precisão, recall, false-control, abstention.
4. Registrar discordâncias SEM ajustar ground truth ao motor.

**Esta etapa permanece pendente de um auditor humano.** É a única exigência da
diretiva que uma execução autônoma não pode cumprir sozinha — e é reportada como
limitação explícita, não como sucesso fabricado.
