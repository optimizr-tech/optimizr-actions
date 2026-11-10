# Seção `## Quality gate` no corpo do PR

Padrão da organização (decisão do dono, 2026-11-07): o quality gate é rodado
**localmente** e a tabela resultante é colada no corpo do PR sob `## Quality
gate`. O job de CI `Quality gate metrics` continua existindo e, quando roda,
é a evidência hospedada; a seção local não o substitui nem altera.

Esta página descreve o comando `python -m scripts.quality_gate.local`, os
níveis de custo, a regra de pilha, a origem do baseline e o que não fazer.
Nada aqui altera `scripts.quality_gate.run`, os workflows `_quality-gate-*.yml`
ou `_pr-metadata.yml` (mudança aditiva, compatível com `v1`).

## Seção obrigatória (por convenção)

```markdown
## Quality gate

<saída de python -m scripts.quality_gate.local, sem edição manual>
```

A saída contém, nesta ordem: veredito geral e tabela (mesmo renderizador do
comentário de CI), aviso de veredito parcial, head SHA, nível executado,
baseline usado (origem, SHA, data), o comando executado e a lista
`Não coletado (unknown / não coletado)`. Não edite números à mão: rode de novo.

## Níveis de custo

| Nível | Quando | O que | Custo |
|---|---|---|---|
| 1 | Sempre | ruff, cobertura pytest já existente, bandit, pip-audit, pnpm-audit | barato |
| 2 | Só se o PR muda código da área | jscpd e bundle | moderado |
| 3 | **Nunca local** | builds Next completos, E2E Docker, Trivy de imagem, suítes opt-in Postgres/mTLS reais | pesado |

O nível 3 aparece sempre como `unknown / depende do CI`. O comando não executa
nenhuma ferramenta: o `ci-local` do serviço gera os JSON em `--artifacts-dir` e
o comando compara e relata. Limites atuais do mecanismo, listados na saída como
não coletados: `ruff` não tem coletor em `scripts/quality_gate` (rode no
`ci-local` e registre à parte) e o bundle Next não tem coletor JSON em `run.py`
(exige build Next, portanto depende do CI). `--tier 2` passa a exigir o JSON do
jscpd; sem ele, o item é listado como não coletado.

## Pilha de PRs

Em pilha de PRs, rode **uma vez, no PR do topo**, e referencie nos demais
(`Quality gate: ver #<topo>`). Rode de novo se o topo mudar de SHA.

## Origem do baseline

1. Preferido: `--baseline-from-main <owner/repo>` baixa o artefato
   `quality-gate-baseline` da última execução verde da `main` do **mesmo**
   repositório (`gh run list` + `gh run download`; exige `gh` autenticado).
   Opcional `--baseline-workflow <arquivo>` restringe o workflow.
2. Alternativa explícita: `--baseline <arquivo>` (formato do `emit-baseline`).
3. Fallback: `--fallback-baseline <arquivo>` (baseline versionado mais recente)
   usado só se o passo 1 falhar. A saída marca **baseline aproximado** e informa
   SHA e data (data do commit do SHA via git; se não resolvível, mtime do
   arquivo, dito explicitamente).
4. Sem nenhum baseline: métricas ficam `unknown` (exit 3). Nunca se omite nem
   se inventa número.

Falhas do `gh` aparecem como `nota:` na saída.

## Códigos de saída

Iguais aos de `run.py`: green 0, yellow 1, red 2, unknown 3. Erros de uso
(argumento inválido, diretório ou baseline inexistente, SHA indeterminável)
saem com **64** para não colidir com o veredito e escrevem em stderr.

## Exemplo renderizado

```markdown
### Quality gate — :large_green_circle: green

| Metric | Scope | PR | main | Δ | Severity |
|---|---|---:|---:|---:|---|
| coverage.lines:pytest | backend | 89.00% | 89.00% | +0.00pp | :large_green_circle: green |
| coverage.branches:pytest | backend | 75.00% | 75.00% | +0.00pp | :large_green_circle: green |
| security.findings:bandit | backend | 1 | 1 | +0 | :large_green_circle: green |

> Veredito parcial: 6 item(ns) não coletado(s) abaixo; ausência de dado não significa green.

- **Head SHA:** `<40 hex>`
- **Nível executado:** 1
- **Baseline (baseline aproximado):** baseline versionado (--fallback-baseline)
  - SHA: `<40 hex>`
  - Data: 2026-11-01T10:00:00+00:00
  - Aproximado: não é o artefato da última execução verde da main; comparação pode divergir do CI.
  - nota: gh run list falhou: <motivo>
- **Comando:** `python -m scripts.quality_gate.local --artifacts-dir .quality-gate/artifacts ...`

#### Não coletado (unknown / não coletado)

- pip-audit: artefato não encontrado em --artifacts-dir
- pnpm-audit: artefato não encontrado em --artifacts-dir
- jscpd (duplicação): nível 2 não solicitado (--tier 2)
- ruff (lint): sem coletor no quality_gate; rode no ci-local do serviço e registre o resultado à parte
- bundle Next (nível 2): sem coletor JSON em run.py (requer build Next); unknown / depende do CI
- build Next completo (nível 3): unknown / depende do CI
- E2E Docker (nível 3): unknown / depende do CI
- Trivy de imagem (nível 3): unknown / depende do CI
- suítes opt-in Postgres/mTLS reais (nível 3): unknown / depende do CI
```

## Como cada serviço chama no seu `ci-local`

O serviço gera os JSON (nomes que o `collect_metrics` reconhece: `*coverage*`,
`*bandit*`, `*pip-audit*`, `*pnpm-audit*`, `*jscpd*`) e depois chama:

```bash
# PYTHONPATH aponta para um checkout de optimizr-actions (ref conhecida)
PYTHONPATH=<optimizr-actions> python -m scripts.quality_gate.local \
  --repo-root . \
  --tier 1 \
  --artifacts-dir .quality-gate/artifacts \
  --baseline-from-main optimizr-tech/<repo> \
  --fallback-baseline docs/quality-gate-baseline.json \
  --output .quality-gate/section.md
```

Cole `section.md` sob `## Quality gate` e crie o PR com `--body-file`.

## O que NÃO fazer

- Não rodar nível 3 localmente nem preencher seus itens com palpite.
- Não editar a tabela, omitir linhas `unknown` ou trocar `unknown` por green.
- Não usar baseline de outro repositório ou de branch que não seja a `main`.
- Não repetir a execução em cada PR de uma pilha.
- Não colar credenciais, URLs assinadas ou caminhos de host nos JSON/saída.
- Não tratar a seção como substituta do job de CI nem como gate de merge.

## Proposta futura (não implementada; exige aprovação humana)

Validar a presença da seção `## Quality gate` em `_pr-metadata.yml`.
**Impacto:** muda o gate de todos os PRs de todos os consumidores do `v1`
(PRs existentes sem seção passariam a falhar). **Rollback:** reverter a
mudança no workflow e republicar o `v1` por validação normal. Faseamento
sugerido: modo aviso (não bloqueante) por um ciclo antes de bloquear.
