# ⛏️ GARIMPO 2.0

> **Motor de pivô OSINT passivo · 100% Python stdlib · keyless · cadeia de custódia forense · painel web · servidor MCP · STIX 2.1 · monitoramento**
> Família **DEIVOSINT** · irmão do [Mineiro](https://github.com/Ridd1kulusC0d3r/Mineiro-OSINT-Extractor): o Mineiro extrai, o GARIMPO garimpa os vínculos.

```bash
python3 garimpo.py painel                    # painel no navegador (o jeito mais fácil)
python3 garimpo.py investigar alvo.com.br    # ou direto no terminal
```

Sem `pip install`. Sem API key. Sem LLM. Python 3.9+.

## O que ele faz

Você entrega **um seed** — domínio, IP, e-mail, username, CNPJ, CEP, ASN, URL, hash, telefone (`(31) 99999-8888`) ou CPF — e o GARIMPO:

1. **detecta o tipo** (CPF/CNPJ com dígito verificador offline; formato de CPF/CNPJ com DV errado vira `documento_invalido` e nunca é consultado);
2. **consulta 28 fontes passivas e keyless** em paralelo, com cortesia por site e cache — nenhuma requisição toca a infraestrutura do alvo;
3. **pivota em BFS com orçamento** (profundidade, entidades, requisições) e mostra a **fronteira**: o que foi achado mas ainda não consultado;
4. **lacra cada resposta bruta** num ledger SHA-256 hash-encadeado e **amarra cada fato à evidência** que o sustenta (`#seq`);
5. entrega **dossiê HTML pt-BR**, **exportações** (STIX 2.1, GraphML, CSV, JSON) e, se você repetir a coleta, **o que mudou**.

### O pulo do gato brasileiro

`domínio .br` → **RDAP do registro.br publica o CNPJ do titular** → BrasilAPI (Receita) → **razão social, sócios (QSA), e-mail e telefone cadastrais, CEP** → logradouro e coordenadas. Tudo keyless.

## As quatro portas de entrada

| Porta | Comando | Para quem |
|---|---|---|
| **Painel web** | `python3 garimpo.py painel` | quem não quer terminal: investigar, explorar o grafo arrastando nós, abrir evidências, exportar, comparar |
| **CLI** | `python3 garimpo.py investigar ALVO` | scripts, automação, servidores |
| **Servidor MCP** | `python3 garimpo.py mcp` | Claude Desktop, Claude Code e outros clientes MCP |
| **Demo** | `python3 garimpo.py demo` | conhecer tudo em 10 s, offline (duas coletas fictícias + diff) |

## Comandos

```bash
python3 garimpo.py investigar ALVO [--profundidade 1] [--max-entidades 12] [--max-requisicoes 40] [--paralelo 4] [--exportar stix,graphml,csv]
python3 garimpo.py monitorar ALVO --contra casos/CASO_ANTERIOR     # coleta de novo e mostra o que mudou
python3 garimpo.py diff CASO_ANTES CASO_DEPOIS [--json]
python3 garimpo.py exportar CASO stix graphml csv json
python3 garimpo.py painel [--porta 8765] [--casos casos]
python3 garimpo.py mcp [--casos casos]
python3 garimpo.py fontes | detectar VALOR | verificar CASO | demo | versao
python3 -m unittest discover -s testes -v                          # 48 testes, offline
```

## Fontes (todas keyless, todas passivas)

| Tipo | Fontes |
|---|---|
| domínio | RDAP (**registro.br** para `.br`, com CNPJ do titular), DNS completo via DoH (A/AAAA/MX/NS/TXT/SOA/CAA/DMARC, SPF), crt.sh, Certspotter, Wayback CDX, urlscan.io (só lê varreduras existentes) |
| IP / ASN | RDAP, InternetDB (Shodan keyless, sem scan novo), PTR, RIPEstat (prefixo e ASN de origem; titular e prefixos do ASN), lista oficial de saídas Tor |
| e-mail | domínio + parte local, Gravatar, **keys.openpgp.org** (parser OpenPGP próprio: UIDs da chave → outros e-mails e nomes) |
| username | GitHub (perfil + **e-mails de commits públicos**), **Keybase** (contas e domínios provados criptograficamente), Hacker News |
| Brasil | **BrasilAPI CNPJ** (QSA, CNAE, Simples/MEI, endereço, contatos), **BrasilAPI CEP**, CPF **só offline**, telefone **só offline** (DDD → UF) |
| artefatos | URL → host + Wayback; hash → **CIRCL hashlookup** (software conhecido) |

`python3 garimpo.py fontes` imprime a tabela de ruído completa — **gerada do código**: cada fonte declara nível e destino real dos bytes. **Passivo ≠ anônimo**: cada serviço vê o que você pesquisou.

**Decisões éticas no código:** CPF nunca é consultado, pivotado nem exportado; o CPF de titular de domínio `.br` é descartado na coleta.

## Usar com o Claude (MCP)

```json
{"mcpServers": {"garimpo": {"command": "python3",
  "args": ["/caminho/para/toolsR/garimpo.py", "mcp", "--casos", "/caminho/para/toolsR/casos"]}}}
```

Claude Code: `claude mcp add garimpo -- python3 /caminho/para/toolsR/garimpo.py mcp --casos /caminho/para/toolsR/casos`

Ferramentas: `garimpo_investigar`, `garimpo_caso`, `garimpo_comparar`, `garimpo_verificar`, `garimpo_exportar`, `garimpo_casos`, `garimpo_detectar`, `garimpo_fontes`. Casos só dentro de `--casos`; teto de 200 requisições por chamada.

## Um caso por pasta

```
casos/2026-10-17_090000_alvo/
├── caso.json        # grafo: fato → fonte → evidência #seq; fronteira; vínculos
├── dossie.html      # dossiê standalone (offline, pt-BR)
├── ledger.jsonl     # cadeia de custódia hash-encadeada
├── evidencias/      # resposta bruta de cada requisição
├── diff.json        # (monitorar) o que mudou
└── exportacoes/     # (exportar) STIX 2.1, GraphML, CSV, JSON
```

## Estrutura do repositório

```
garimpo.py                 # porta de entrada (CLI) — re-exporta a API
jazida/                    # o núcleo (a jazida do garimpo), stdlib pura
  deteccao.py custodia.py rede.py motor.py dossie.py exportar.py monitor.py demo.py
  mcp.py painel.py painel.html cli.py
  fontes/                  # plugins: dominio, ip, pessoais, brasil, artefatos
COMECE-AQUI.md             # uma ação por vez
manual/manual.html         # manual ilustrado (+ figura isométrica e capturas anotadas)
lancadores/                # dois cliques: Painel / Demo / Investigar × Windows, macOS, Linux
demo/                      # as duas coletas de demonstração (com diff)
testes/                    # 48 testes + relatório
docs/ENGENHARIA-REVERSA-OPENOSINT.md
```

## Origem

Nasceu da engenharia reversa do [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT). A 1.x corrigiu as lacunas do núcleo (Brasil, dependências, LLM obrigatório, extração frágil, proveniência sem forense). A 2.0 alcança o que o OpenOSINT tinha e o GARIMPO não — **servidor MCP, interface web, fan-out paralelo** — sem abrir mão de stdlib pura, e vai além (custódia por fato, STIX, diff, fontes BR). Detalhes em [`docs/ENGENHARIA-REVERSA-OPENOSINT.md`](docs/ENGENHARIA-REVERSA-OPENOSINT.md).

## Licença e aviso legal

MIT. **Uso legal e autorizado apenas.** Fatos vêm de execuções reais das fontes listadas — são pistas a confirmar, não prova.

---

*GARIMPO · DEIVOSINT · Deivison Lourenço ([@Ridd1kulusC0d3r](https://github.com/Ridd1kulusC0d3r))*
