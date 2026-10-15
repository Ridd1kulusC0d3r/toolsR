# ⛏️ GARIMPO

> **Motor de pivô OSINT passivo · 100% Python stdlib · keyless · com cadeia de custódia forense**
> Família **DEIVOSINT** · irmão do [Mineiro](https://github.com/Ridd1kulusC0d3r/Mineiro-OSINT-Extractor): o Mineiro extrai, o GARIMPO garimpa os vínculos.

```bash
python3 garimpo.py investigar alvo.com.br
```

Sem `pip install`. Sem API key. Sem LLM. Um arquivo.

## O que ele faz

Você entrega **um seed** (domínio, IP, e-mail, username, CNPJ, CPF, telefone — inclusive `(31) 99999-8888` —, URL ou hash; ele detecta sozinho) e o GARIMPO:

1. **Detecta o tipo** da entidade — incluindo CPF e CNPJ com validação de dígitos verificadores offline (formato de CPF/CNPJ com DV errado vira `documento_invalido` e não é consultado);
2. **Consulta só fontes passivas e keyless** — nenhuma requisição toca a infraestrutura do alvo;
3. **Pivota em BFS com orçamento** — cada descoberta de alta confiança vira novo nó, até os tetos de profundidade, entidades e requisições;
4. **Hasheia e encadeia cada evidência bruta** (SHA-256 em ledger hash-encadeado) — adulterou um byte, quebrou a corrente;
5. **Gera um dossiê HTML standalone em pt-BR** com grafo SVG de vínculos e fato-a-fato com fonte.

## Fontes (todas sem chave)

| Fonte | Entidade | Nível | O que é enviado, e para onde |
|---|---|---|---|
| RDAP (registro.br p/ `.br`, rdap.org p/ o resto) | domínio, IP | passiva | 1 requisição ao servidor do registro — nunca ao alvo |
| DNS over HTTPS (dns.google) | domínio, e-mail, IP | passiva* | consulta via resolvedor do Google; os nameservers do alvo veem o resolvedor, não você |
| crt.sh | domínio | passiva | lê o índice público de transparência de certificados (subdomínios) |
| InternetDB (Shodan keyless) | IP | passiva | lê o índice **existente** da Shodan — não dispara scan novo |
| Internet Archive / Wayback CDX | domínio, URL | passiva | lê o índice do Archive |
| GitHub API | username | passiva | 1–2 requisições públicas (60/h sem token) |
| Gravatar | e-mail | passiva | 1 requisição com o hash MD5 do e-mail |
| **BrasilAPI (CNPJ/Receita)** | CNPJ | passiva | dados públicos da Receita Federal: razão social, QSA, CNAE |
| Cálculo local | CPF, hash, telefone | **offline** | nenhum byte sai da máquina |

**Passivo ≠ anônimo.** Cada serviço consultado vê o que você pesquisou (e seu IP). `python3 garimpo.py fontes` imprime esta tabela.

**Decisão ética explícita:** CPF recebe **apenas** validação matemática offline. Pivotar CPF contra bases vazadas está fora do escopo de uma ferramenta passiva e legal.

## Comandos

```bash
python3 garimpo.py investigar ALVO [--profundidade 1] [--max-entidades 12] [--max-requisicoes 30]
python3 garimpo.py detectar VALOR        # só mostra o tipo detectado
python3 garimpo.py fontes                # tabela de ruído
python3 garimpo.py verificar CASO_DIR    # reverifica a cadeia de custódia
python3 garimpo.py demo                  # caso de demonstração 100% offline
python3 -m unittest discover -s testes -v   # roda a suíte de testes (21, offline)
```

Cada caso vira um diretório:

```
casos/2026-10-15_020830_alvo/
├── caso.json          # grafo completo, legível por máquina
├── dossie.html        # dossiê standalone (abre offline, pt-BR)
├── ledger.jsonl       # cadeia de custódia hash-encadeada
└── evidencias/        # resposta bruta de cada requisição, byte a byte
```

## Por que ele existe (engenharia reversa do OpenOSINT)

O GARIMPO nasceu da dissecação completa do [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) (~22 mil linhas, 100 módulos). O estudo inteiro está em [`docs/ENGENHARIA-REVERSA-OPENOSINT.md`](docs/ENGENHARIA-REVERSA-OPENOSINT.md). Resumo do que foi **mantido** e do que foi **corrigido**:

| | OpenOSINT | GARIMPO |
|---|---|---|
| Passivo por padrão, tabela de ruído honesta | ✅ ótimo | ✅ mantido (e sempre passivo) |
| Orçamento de chamadas não negociável | ✅ ótimo | ✅ mantido |
| Fluxo principal | exige LLM + chave Anthropic | **determinístico, zero IA** |
| Dependências | ~20 obrigatórias | **0 — stdlib pura** |
| Fontes brasileiras | nenhuma | **registro.br RDAP, BrasilAPI/CNPJ, CPF/CNPJ offline** |
| Extração para pivô | regex sobre texto livre | **JSON estruturado por fonte** |
| Proveniência | sidecar por statement | **+ cadeia de custódia SHA-256 encadeada e verificável** |
| InternetDB, crt.sh, Wayback | ausentes | **nativos e keyless** |
| Relatório | PDF/HTML EN/IT | **dossiê HTML standalone pt-BR** |

## Estrutura do repositório

```
garimpo.py                      # a ferramenta inteira (1 arquivo, stdlib)
COMECE-AQUI.md                  # comece por aqui (uma ação por vez)
manual/manual.html              # manual ilustrado para usuários leigos
manual/figura/                  # figura isométrica interativa (a "bancada"), temas escuro e claro
lancadores/                     # dois cliques: .bat (Windows), .command (macOS), .sh (Linux)
demo/                           # caso de demonstração
testes/test_garimpo.py          # suíte automatizada: 21 testes, unittest, offline
testes/RELATORIO-DE-TESTES.md   # resultado dos testes em nuvem
docs/ENGENHARIA-REVERSA-OPENOSINT.md
```

## Licença e aviso legal

MIT. **Uso legal e autorizado apenas.** Os fatos do dossiê vêm de execuções reais das fontes listadas — são pistas a confirmar, não prova. Você é o único responsável pelo uso.

---

*GARIMPO · DEIVOSINT · Deivison Lourenço ([@Ridd1kulusC0d3r](https://github.com/Ridd1kulusC0d3r))*
