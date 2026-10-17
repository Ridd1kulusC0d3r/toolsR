# Relatório de testes em nuvem — GARIMPO 2.0.0

**Ambiente:** sandbox Linux (Anthropic cloud), Chromium headless, 2026-10-17 (America/Sao_Paulo).
**Pythons testados:** 3.9.25, 3.11, 3.12, 3.13.16.
**Limitação do ambiente:** a sandbox tem allowlist de rede; todas as fontes OSINT reais respondem `403 Forbidden` do proxy. Os parsers foram testados contra **fixtures no formato documentado** de cada API; a validação ao vivo fica para a máquina local (seção 5).

## 1. Suíte automatizada — `testes/test_garimpo.py` ✅ 48/48 (em cada versão de Python)

```bash
python3 -m unittest discover -s testes -v      # ~3 s, offline, só stdlib
```

| Grupo | Testes | O que prova |
|---|---|---|
| Detecção | 4 | Matriz de 24 valores (CPF/CNPJ válidos e inválidos, telefones BR formatados, **CEP**, **ASN**, IPv4/IPv6, hash, domínio, pessoa, username); CPF nunca casa como domínio; validadores; **normalização deduplica** grafias (CNPJ com/sem máscara, domínio com maiúsculas e ponto final). |
| Custódia | 6 | Íntegra; evidência adulterada; ledger forjado; registro removido; caso retomado; **40 gravações concorrentes** mantêm a corrente. |
| Rede | 3 | Teto duro; **cache por URL** (2 URLs → 2 buscas, 3 pedidos); **rastreio fato→evidência**; erro de rede vira registro de custódia com status 0. |
| Fontes | 21 | RDAP `.br` com `publicIds` → pivô de **CNPJ**, **CPF descartado** (nem nos fatos); RDAP genérico; DNS completo (AAAA, MX, SPF include, CAA, DMARC); crt.sh e Certspotter; urlscan (IP não pivota); InternetDB com e sem dados; RIPEstat IP e ASN; Tor; **parser OpenPGP** (UIDs de pacotes tag 13); PGP → outros e-mails; GitHub + **commits** (noreply filtrado); Keybase (provas → username e domínio); Hacker News (e-mail em `about` com entidade HTML); e-mail local; Gravatar; CNPJ completo (organização, sócio, CEP, e-mail, Simples); CEP; CPF e telefone offline (DDD → UF); CIRCL hashlookup conhecido/desconhecido; registro de fontes sem nomes duplicados e com destino declarado. |
| Motor e dossiê | 4 | BFS: profundidade, confiança < 0,6 e **fronteira**; **fonte que levanta exceção não derruba** a investigação; **migração de casos 1.x**; dossiê escapa HTML. |
| Demo | 1 | Gerada pelo **motor real** com fixtures; idempotente; pivô RDAP → CNPJ; ASN alcançado; `diff.json` com subdomínio e sócio novos; **todo fato aponta para evidência que existe no ledger**. |
| Exportações e diff | 4 | STIX 2.1: tipos esperados, IDs válidos e **determinísticos**, toda relationship aponta para objeto existente; **CPF nunca exportado** (STIX e GraphML); GraphML válido (parse XML, contagem de nós); CSV; diff vazio. |
| MCP | 2 | **Subprocesso stdio real:** initialize, notificação sem resposta, tools/list, verificar, **path traversal recusado**, comparar, método inexistente (−32601), JSON inválido (−32700); **stdout só contém JSON-RPC**; truncamento do resumo. |
| Painel | 3 | **Servidor HTTP real:** página com CSP, lista de casos, caso com diff e ledger, verificação, exportação zip, dossiê com links reescritos, evidência; **defesas**: Host forjado (403), POST sem `X-Garimpo` (403), formulário HTML simples (403), 4 tentativas de path traversal (404); investigação assíncrona (CPF: 0 requisições). |
| CLI | 1 | versão, fontes, demo, verificar, exportar, diff — com `PYTHONIOENCODING=cp1252` (cenário Windows). |

## 2. Verificações manuais em navegador ✅

- **Painel** renderizado no Chromium com a demo: formulário, lista de casos, quadro de mudanças, grafo de forças, fatos com evidência. Capturas usadas no manual (`manual/img/`).
- **Dossiê 2.0** renderizado: métricas, mudanças, grafo, fronteira, uso de fontes.
- **Manual** renderizado por seção com Playwright: **0 erros de console**.
- **Servidor MCP** exercitado manualmente com 7 mensagens (incluindo lixo e traversal).

## 3. Ao vivo (executado; bloqueado pelo ambiente ⚠️)

Investigações reais via CLI, painel e MCP rodaram de ponta a ponta sem exceção; cada `403` do proxy ficou registrado na custódia com `status_http: 0`.

## 4. Esquemas conferidos em documentação

- InternetDB (`cpes, hostnames, ip, ports, tags, vulns`) — anúncio oficial da Shodan.
- BrasilAPI CNPJ (campos de topo) — código de terceiros que consome a API.
- **Não confirmados nesta sessão** (formato usado conforme conhecimento prévio; conferir na 1ª execução real): `qsa` da BrasilAPI, BrasilAPI CEP v2 (`location.coordinates`), RIPEstat (`prefix-overview`, `as-overview`, `announced-prefixes`), Certspotter (`dns_names`), urlscan (`results[].page`), Keybase (`proofs_summary.all`), CIRCL hashlookup (`FileName`), keys.openpgp.org (armadura), e o campo `payload.commits` dos eventos públicos do GitHub (a API pode não trazer mais os commits — a fonte informa quando nenhum e-mail aparece).

## 5. Pendente — validar na sua máquina (5 minutos)

```bash
python3 garimpo.py investigar registro.br          # RDAP .br (publicIds), DNS, CT, Wayback, urlscan
python3 garimpo.py investigar 8.8.8.8              # RDAP, InternetDB, PTR, RIPEstat → AS15169, Tor
python3 garimpo.py investigar AS15169              # RIPEstat ASN
python3 garimpo.py investigar <CNPJ com sócios>    # QSA, CEP, contatos
python3 garimpo.py investigar <seu username>       # GitHub, commits, Keybase, Hacker News
python3 garimpo.py investigar d41d8cd98f00b204e9800998ecf8427e   # hashlookup
```

Se alguma fonte voltar sem fatos, a resposta bruta está em `evidencias/` — é ela que diz se o formato mudou.

## 6. Veredito

Núcleo, fontes (contra fixtures), exportações, monitoramento, MCP e painel **aprovados** em quatro versões de Python. Fontes ao vivo **prontas, não observadas** nesta sandbox.
