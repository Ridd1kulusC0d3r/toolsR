# Engenharia reversa: OpenOSINT/OpenOSINT

**Analista:** Deivison Lourenço (DEIVOSINT) · **Data:** 2026-10-15
**Método:** análise de repositório-fonte completo (clone `main`, 229 arquivos `.py`, ~22.000 linhas no pacote `openosint/`, 100 módulos), leitura de arquitetura camada a camada, inventário de dependências, política de ferramentas e modelo de dados.
**Objetivo:** entender o mecanismo real, mapear lacunas e projetar uma ferramenta nova (GARIMPO) que mantenha os acertos e corrija as falhas.

---

## 1. Visão geral do alvo

O OpenOSINT é um **agente OSINT guiado por LLM**: 21+ ferramentas de investigação atrás de uma interface em linguagem natural, exposto como REPL, CLI, servidor MCP e Web UI. Modelo comercial open-core: núcleo MIT + versão hospedada ("Monitor") + patrocinadores (IP2Location, Bright Data) integrados como fontes.

## 2. Anatomia por camadas

```
Entradas            cli.py · repl.py · web_server.py · mcp_server.py
                         │
Orquestração        agent.py  ← loop agêntico (Anthropic nativo / Ollama / OpenAI-compat)
                         │     modelo decide a ferramenta; execução real; resultado volta ao modelo
Política            tool_policy.py  ← PASSIVO POR PADRÃO + ToolBudget (teto de chamadas)
                         │     ferramentas "noisy/touches target" nem aparecem no tools/list
Ferramentas         tools/search_*.py (21+)  ← wrappers de APIs (HIBP, Shodan, Censys,
                         │     VirusTotal, GitHub, RDAP, GDELT, Bright Data…) e binários
                         │     externos (holehe, sherlock, sublist3r, phoneinfoga)
Extração            extractors.py  ← regex sobre o TEXTO de saída de cada ferramenta
                         │     → Entity + Relationship com confiança heurística ordinal
Pivô                pivot.py  ← BFS por camadas, concorrente, com orçamento
                         │     (profundidade, nº de entidades, nº de chamadas)
Grafo persistente   graph/  ← modelo FollowTheMoney (FtM), SQLite append-only,
                         │     provenance.py (sidecar por statement: confiança, extractor,
                         │     run_id), dedup/ (candidatos + scoring via nomenklatura),
                         │     review humano de pares same_as, denylist, tombstones
Saídas              pdf_report.py (reportlab) · render_html (EN/IT) · web_view (globo 3D)
Paralelo            exposure/  ← produto separado de "exposição externa" de domínio
                         (SPF/DKIM/DMARC, TLS, headers, lookalikes) com scoring e catálogo EN/IT
```

### Decisões de projeto dignas de nota (acertos)

1. **Passivo por padrão com tabela de ruído gerada do código** (`python -m openosint.tool_policy` gera a tabela do README). Ferramenta desabilitada não é "recusada": ela **não é oferecida** ao modelo. Honestidade rara: "Passive is not private".
2. **Orçamento não negociável** (`OPENOSINT_MAX_TOOL_CALLS`, padrão 15; multi-alvo 30) — evita custo/latência fugitivos do loop agêntico.
3. **Proveniência como sidecar** (`graph/provenance.py`): reutiliza os campos do Statement FtM (dataset, origin, first/last_seen) e adiciona só o que falta (confiança, extractor, run_id), um registro por observação, append-only. O docstring distingue explicitamente **confiança heurística ordinal** (extractors) de **probabilidade calibrada de match** (nomenklatura) e proíbe misturá-las — maturidade epistemológica incomum.
4. **Dois caminhos de execução**: agêntico (LLM escolhe) e direto (`openosint email X` sem IA) — mas o produto inteiro é vendido pelo primeiro.
5. **Review humano de deduplicação**: pares `same_as` candidatos com score viram cartões de revisão aceitar/rejeitar — IA propõe, humano decide.

## 3. Inventário de dependências (custo de adoção)

Obrigatórias (~20): `mcp`, `anthropic`, `requests`, `python-whois`, `rich`, `prompt_toolkit`, `python-dotenv`, `aiohttp`, `dnspython`, `fastapi`, `uvicorn`, `sse-starlette`, `httpx`, `asyncpg`, `cryptography`, `tldextract`, `pyyaml`, `reportlab`, `authlib`, `itsdangerous`. Opcionais: `shodan`, `censys`, `ollama`, `openai`, `followthemoney`, `nomenklatura`, `playwright`…
Ferramentas noisy dependem de **binários de terceiros não auditados** (holehe, sherlock, sublist3r, phoneinfoga) — o próprio README admite: "não é garantia sobre o que um binário de terceiros faz com a requisição".

## 4. Lacunas encontradas (e o que cada uma custa)

| # | Lacuna | Evidência no código | Custo para o analista |
|---|---|---|---|
| L1 | **Zero fontes brasileiras** | nenhum módulo toca registro.br, Receita/CNPJ, BrasilAPI; `regexes.py` não conhece CPF/CNPJ | investigações BR começam do zero; um CNPJ é classificado como "phone" ou "hash" |
| L2 | **Fluxo principal refém de LLM + chave** | `agent.py` importa `anthropic` no topo; REPL/Web/investigate exigem provider | custo por consulta, dependência de nuvem, não auditável em ambiente fechado |
| L3 | **Extração frágil por regex em texto livre** | `extractors.py`: parse de linhas como `"Emails found in commits:"` da saída formatada | qualquer mudança cosmética na saída quebra o pivô silenciosamente |
| L4 | **Proveniência sem forense** | `provenance.py` guarda metadados, mas a **resposta bruta** não é preservada nem hasheada; nada encadeia registros | evidência não resiste a contestação; impossível provar não-adulteração |
| L5 | **Instalação pesada** | 20 deps obrigatórias p/ rodar `openosint email x` | fricção em máquina perícial/air-gapped; superfície de supply chain |
| L6 | **Fontes keyless ignoradas** | sem InternetDB (Shodan sem chave), sem crt.sh, Wayback só ausente do pivô | portas/CVEs e subdomínios keyless ficam na mesa; empurra o usuário para chaves pagas |
| L7 | **Relatórios EN/IT apenas** | `exposure/report/catalog_en.py`, `catalog_it.py`; nada pt | inviável entregar a cliente/delegacia BR sem retrabalho |
| L8 | **CPF/telefone BR inexistentes como tipos** | `detect_entity_kind` → email/url/ip/hash/phone/domain/username/person | identificadores centrais de investigação BR não são cidadãos de primeira classe |
| L9 | **`search_phone` com comportamento de rede não verificado** | marcado `unverified` na própria tabela | o projeto reconhece; segue embarcado |

## 5. O que o GARIMPO faz com cada lacuna

| Lacuna | Resposta do GARIMPO |
|---|---|
| L1, L8 | Tipos `cnpj`/`cpf`/`telefone` nativos com validação de DV **offline**; RDAP do registro.br para `.br`; BrasilAPI (Receita) com razão social, QSA → pivô para sócios |
| L2 | Pivô **determinístico** sem IA: detecção → roteamento por tipo → BFS com orçamento. Zero chave obrigatória |
| L3 | Cada fonte devolve **entidades estruturadas** (`(tipo, valor, relação, confiança)`) extraídas do **JSON da API**, nunca do texto renderizado |
| L4 | **Cadeia de custódia**: bytes brutos de cada resposta salvos em `evidencias/`, SHA-256 por evidência, ledger JSONL **hash-encadeado** (hash do registro anterior entra no hash do próximo), verificável offline (`verificar`) |
| L5 | **Python stdlib pura**, 1 arquivo, 3.9+ |
| L6 | InternetDB, crt.sh e Wayback CDX nativos e keyless |
| L7 | Dossiê HTML **pt-BR standalone** com grafo SVG, abre offline |
| L9 | Telefone: análise **somente offline** (+55/DDD/celular); decisão documentada |

O que foi **deliberadamente mantido** do OpenOSINT: passivo por padrão (no GARIMPO, passivo **sempre** — não há modo ativo), tabela de ruído honesta impressa pela própria ferramenta, orçamento rígido de requisições, fato sempre acompanhado da fonte, "achados são pistas, não prova".

O que foi **deliberadamente deixado de fora** (escopo): loop agêntico com LLM, dedup FtM/nomenklatura, Web UI, MCP server — candidatos a versões futuras, sem comprometer o núcleo stdlib.

## 6. Limitações desta análise

- Análise **estática de código-fonte**; nenhum binário foi decompilado e o comportamento de rede dos binários de terceiros (holehe etc.) não foi capturado em tráfego — mesmo limite que o projeto declara sobre si.
- A versão analisada é o `main` em 2026-10-15; números de linhas/módulos variam por release.

---

*Documento produzido para o repositório [Ridd1kulusC0d3r/toolsR](https://github.com/Ridd1kulusC0d3r/toolsR).*
