# Relatório de testes em nuvem — GARIMPO 1.1.0

**Ambiente:** sandbox Linux (Anthropic cloud), Python 3, Chromium headless, 2026-10-15 (America/Sao_Paulo).
**Limitação do ambiente:** a sandbox tem **allowlist de rede**. Os endpoints OSINT reais (dns.google, rdap.org, rdap.registro.br, crt.sh, internetdb.shodan.io, brasilapi.com.br, web.archive.org, gravatar.com) retornam `403 Forbidden` do proxy — bloqueio do ambiente, não defeito da ferramenta. Por isso os parsers foram testados contra **fixtures no formato documentado** de cada API, e a validação ao vivo fica para a máquina local (seção 5).

## 1. Suíte automatizada — `testes/test_garimpo.py` ✅ 21/21

```bash
python3 -m unittest discover -s testes -v      # 21 testes, ~0,03 s, offline, só stdlib
```

| Grupo | Testes | O que prova |
|---|---|---|
| Detecção | 3 | Matriz de 20 valores: CPF/CNPJ válidos (formatados e crus), CPF/CNPJ formatados com DV inválido → `documento_invalido`, telefones BR (`+55 31 99999-8888`, `(31) 99999-8888`, crus), e-mail, URL, IPv4, IPv6, hash MD5, domínios, pessoa, username. CPF nunca casa com a regex de domínio. Validadores de DV. |
| Custódia | 5 | Caso íntegro; **evidência adulterada** (linha exata apontada); **ledger forjado** (campo alterado); **registro removido** (corrente quebrada); caso retomado continua a corrente. |
| Orçamento | 1 | Com teto 0, nenhuma requisição sai. |
| Fontes (parsers) | 9 | RDAP do registro.br para `.br` e rdap.org para o resto; eventos, nameservers e vCard; DoH → IP; crt.sh → subdomínios (sem o próprio seed); Wayback CDX; InternetDB com dados e com `{"detail": …}`; BrasilAPI → **organização** + sócios; CPF faz **zero** requisições; GitHub → e-mail público; e-mail → domínio; telefone BR formatado → DDD/celular. |
| Pivô e dossiê | 3 | BFS barra profundidade além do limite e confiança < 0,6; demo idempotente (ledger não duplica); dossiê **escapa HTML** (sem injeção via dado coletado); comando `verificar` impresso com o caminho certo. |

### Validação dos esquemas usados nas fixtures
- **InternetDB:** campos `cpes, hostnames, ip, ports, tags, vulns` confirmados no anúncio oficial da Shodan.
- **BrasilAPI CNPJ:** campos de topo (`razao_social`, `nome_fantasia`, `descricao_situacao_cadastral`, `data_inicio_atividade`, `municipio`, `uf`, `cnae_fiscal_descricao`) confirmados em código de terceiros que consome a API. O formato interno de `qsa` (`nome_socio`, `qualificacao_socio`) **não pôde ser confirmado em documentação nesta sessão** — confira na primeira consulta real a um CNPJ com sócios.
- RDAP (RFC 9083), DoH JSON do Google, crt.sh `output=json`, Wayback CDX e GitHub `/users`: formatos públicos estáveis, usados conforme a especificação.

## 2. Testes de regressão dos bugs corrigidos na 1.1.0 ✅

| Bug na 1.0.0 | Antes | Agora |
|---|---|---|
| CPF formatado com DV inválido | `dominio` (faria RDAP de um CPF) | `documento_invalido`, nenhuma consulta |
| Telefone BR formatado | `pessoa` | `telefone` |
| Comando `verificar` no dossiê | só o nome da pasta | caminho completo do caso |
| Demo rodada 2× | ledger com registros duplicados | ledger recomeça (2 registros) |
| Razão social de CNPJ | nó `pessoa` | nó `organizacao` |
| Saída redirecionada no Windows (cp1252) | `UnicodeEncodeError` em `✔`/`⛏️` | saída forçada em UTF-8 + `PYTHONUTF8=1` nos `.bat` |
| Arquivo do ledger aberto sem fechar | vazamento de handle | leitura única com `with` |

## 3. Figura isométrica (`manual/figura/`) ✅

- Verificação de pontas de linha da skill /anatomy: **0 de 531 pontas soltas**, tema escuro e claro.
- Capturas: desktop 1440, celular 390 px (sem rolagem lateral), tema claro, ciclo completo até `orçamento esgotado · 8/8` e reinício automático para `casa · prof 0 · 0/8`.
- Console limpo em todas as execuções.

## 4. Pipeline ao vivo (executado; fontes bloqueadas pelo ambiente ⚠️)

`python3 garimpo.py investigar registro.br --profundidade 1` executou de ponta a ponta sem exceção: 7 requisições, cada falha `403` registrada na cadeia de custódia com `status_http: 0`, dossiê e ledger gerados, orçamento respeitado.

## 5. Pendente — validar na sua máquina (2 minutos)

```bash
python3 garimpo.py investigar registro.br          # RDAP registro.br, DNS, crt.sh, Wayback
python3 garimpo.py investigar 8.8.8.8              # RDAP de IP, InternetDB, PTR
python3 garimpo.py investigar <um CNPJ com sócios> # confere o formato de qsa
python3 garimpo.py verificar casos/<caso>
```

Esperado: fatos com fonte `rdap_registro_br`, `dns`, `crtsh`, `internetdb`, `brasilapi` no dossiê, e `✔ Cadeia de custódia ÍNTEGRA`.

## 6. Veredito

Núcleo (detecção, pivô, orçamento, custódia, dossiê) e figura **aprovados**. Fontes ao vivo **prontas, mas não observadas** nesta sandbox; o tratamento de erro já provou degradar sem perder rastro.
