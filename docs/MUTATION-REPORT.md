# MUTATION-REPORT — FASE 6

Engine: `core/harness/mutation.mjs`. Parte de fixtures CONTROLLED conhecidas e
aplica mutações que REMOVEM a causa da autorização. Sobrevivente = mutante que
segue CONTROLLED — reportado, nunca mascarado.

## Resultado

- **130 mutações aplicadas** sobre as fixtures CONTROLLED (legadas + FASE 3).
- **130 detectadas — 100%. 0 survivors.**

## Catálogo de mutações (35 tipos; 14 aplicáveis geram os 130 casos)

Troca owner por outro usuário · troca id do sink · troca id do read · remove
guard · inverte guard · inverte comparação (`===`↔`!==`) · troca coluna owner ·
`&&`↔`||` · move guard para depois do sink · guard em dead-code · troca objeto
verificado · troca tabela verificada · quebra membership transitivo (user) ·
quebra fk transitivo · remove disjunto admin (deve SEGUIR CONTROLLED) · remove
disjunto owner.

## Bugs de soundness que o mutation testing revelou (corrigidos)

Na primeira execução, **26 survivors** em duas classes — ambas bugs reais:

1. **M06 (coluna owner)**: `note.other_id !== user.id` provava CONTROLLED mesmo
   com `other_id` NUNCA lido — aceitávamos a coluna por convenção de nome.
   **Correção**: o campo owner precisa estar entre as colunas realmente lidas do
   recurso (`select("id,user_id")`).
2. **M12 (objeto verificado)**: o read verificava ownership numa TABELA diferente
   da que o sink escreve. **Correção**: a tabela verificada precisa == tabela do
   sink quando o rid chega pela PK `id` (padrão pai-filho via coluna-container
   permanece válido e preservado — auditado em `posts/[postId]` do projeto-auditado-privado).

Após as correções: 26 → 0 survivors. Isto é a evidência de que o ORÁCULO
raciocina sobre causalidade, não reconhece padrões — o teste central da diretiva.

## Classificação de cada resultado

Todo resultado em `core/harness/out/mutation-results.json`: fixture, mutação,
esperado, obtido, detectado (bool). As duas classes acima foram classificadas
como **capacidade do analyzer** (bug real), não defeito de teste, e corrigidas.
