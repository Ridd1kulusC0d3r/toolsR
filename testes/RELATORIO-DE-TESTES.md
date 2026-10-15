# Relatório de testes em nuvem — GARIMPO 1.0.0

**Ambiente:** sandbox Linux (Anthropic cloud), Python 3.x, 2026-10-15 (America/Sao_Paulo).
**Observação importante do ambiente:** a sandbox de nuvem tem **allowlist de rede** (apenas registries de pacotes e GitHub com escopo). Os endpoints OSINT reais (dns.google, rdap.org, crt.sh, internetdb.shodan.io, brasilapi.com.br, web.archive.org, gravatar.com) retornam `403 Forbidden` do proxy — **bloqueio do ambiente, não defeito da ferramenta**. Na máquina do usuário, com internet normal, essas fontes respondem.

## 1. Testes offline (executados e aprovados ✅)

| # | Teste | Comando | Resultado |
|---|---|---|---|
| T1 | Detecção de CPF válido | `detectar "529.982.247-25"` | ✅ `cpf` |
| T2 | Detecção de CNPJ válido | `detectar "11.222.333/0001-81"` | ✅ `cnpj` |
| T3 | Rejeição de CPF com DV inválido | `detectar "111.111.111-11"` | ✅ não classifica como `cpf` |
| T4 | Detecção de e-mail | `detectar deivsec@gmail.com` | ✅ `email` |
| T5 | Detecção de IP | `detectar 8.8.8.8` | ✅ `ip` |
| T6 | Detecção de domínio `.br` | `detectar registro.br` | ✅ `dominio` |
| T7 | Demo offline gera dossiê | `demo` | ✅ `casos/demo/dossie.html` criado, abre no navegador |
| T8 | Cadeia de custódia íntegra | `verificar demo/caso-demo` | ✅ "Cadeia de custódia ÍNTEGRA" |
| T9 | Tabela de ruído | `fontes` | ✅ imprime nível e destino de cada fonte |
| T10 | Zero dependências | `python3 -I garimpo.py …` (modo isolado) | ✅ roda só com stdlib |

## 2. Teste de rede ao vivo (executado; degradação graciosa ✅, fontes bloqueadas pelo ambiente ⚠️)

```
python3 garimpo.py investigar registro.br --profundidade 1 --caso testes/caso-registro-br
```

- ✅ Pipeline completo executou de ponta a ponta sem exceção: detecção → 7 requisições (RDAP registro.br, DoH A/MX/TXT/DMARC, crt.sh, Wayback) → grafo → dossiê → ledger.
- ✅ Cada falha de rede foi **registrada na cadeia de custódia** (`ERRO: Tunnel connection failed: 403 Forbidden`, status 0) — nada se perde silenciosamente.
- ✅ Orçamento respeitado (7/20 requisições), duração 1,66 s.
- ⚠️ Nenhum dado real retornou **porque o proxy da sandbox bloqueia esses hosts** (confirmado com `curl` direto: `CONNECT tunnel failed, response 403`).

## 3. Teste de adulteração da custódia (executado ✅)

Procedimento: alterar 1 byte de um arquivo em `evidencias/` e rodar `verificar`.
Resultado esperado e obtido: ✅ `✘ Cadeia de custódia COMPROMETIDA … evidência adulterada` — a corrente SHA-256 detecta a modificação.

## 4. Pendente de validação na máquina do usuário

| Fonte | O que validar |
|---|---|
| rdap.registro.br / rdap.org | eventos de registro, nameservers, entidades |
| dns.google (DoH) | A/MX/TXT/SPF/DMARC/PTR |
| crt.sh | subdomínios via CT (pode ser lento; timeout 15 s por requisição) |
| internetdb.shodan.io | portas/CVEs/hostnames por IP |
| brasilapi.com.br | CNPJ → razão social, QSA (pivô para sócios) |
| api.github.com | perfil por username (limite 60/h sem token) |
| gravatar.com / web.archive.org | perfil por e-mail / snapshots |

**Como validar em 2 minutos:** `python3 garimpo.py investigar registro.br` e conferir se o dossiê traz fatos de `rdap_registro_br`, `dns` e `crtsh`; depois `python3 garimpo.py verificar casos/<caso>`.

## 5. Veredito

Núcleo lógico (detecção, pivô, orçamento, custódia, dossiê) **aprovado** em nuvem. Camada de fontes ao vivo **bloqueada pelo ambiente de teste** e pronta para validação local — o tratamento de erro já provou degradar graciosamente com todas as fontes fora do ar.
