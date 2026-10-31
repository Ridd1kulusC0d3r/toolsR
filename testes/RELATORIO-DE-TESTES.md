# Relatório de testes em nuvem — GARIMPO 2.1.0

**Ambiente:** sandbox Linux (Anthropic cloud), Chromium headless, 2026-10-30 (America/Sao_Paulo).
**Pythons testados:** 3.9.25, 3.11, 3.12.3, 3.13.
**Limitação do ambiente:** a sandbox tem allowlist de rede; todas as fontes OSINT/CTI reais respondem `403 Forbidden` do proxy. Os parsers são testados contra **fixtures no formato documentado** de cada API/feed; a validação ao vivo fica para a máquina local (seção 5).

## 1. Suíte automatizada — `testes/test_garimpo.py` ✅ 68/68 (em cada versão de Python)

```bash
python3 -m unittest discover -s testes -v      # ~4 s, offline, só stdlib
```

Herdado da 2.0 (44 testes): detecção, custódia (incl. 40 gravações concorrentes), rede (cache, rastreio de evidência, erro→custódia), 20 fontes contra fixtures, motor/fronteira, demo, STIX/GraphML/CSV, MCP stdio e painel HTTP com defesas.

**Novos na 2.1 (24 testes):**

| Grupo | Testes | O que prova |
|---|---|---|
| CTI (ameaças) | 6 | Feodo (acerto/erro), SSLBL, OpenPhish (host e URL), Digitalside por tipo (IP/domínio/hash), **ThreatFox com CSV real** (aspas e espaço após vírgula), e todas registradas no registro de fontes. |
| Análise | 5 | Linha do tempo **ignora CNPJ** e pega data seguida de `T` (`2019-03-04T12:00`); reputação agrega ⚠ com evidência; **sócios cruzados** (2 CNPJs → 1 sócio); exposição sinaliza reputação. |
| Lote | 3 | Leitura TXT (dedup, sem comentário) e CSV (acha coluna `ioc`, ou por nome); **merge de vários seeds num caso** com custódia íntegra. |
| Demo 2.1 | 2 | Reputação pega o IP no ThreatFox na semana 2; linha do tempo **sem falso positivo** de CNPJ; ESPELHO e dossiê trazem as seções novas; o diff mostra a reputação surgindo. |
| MCP 2.1 | 1 | `garimpo_reputacao` e `garimpo_espelho` (gera `espelho.html`); `garimpo_caso` destaca a reputação no topo. |
| Painel 2.1 | 1 | `/api/casos/<id>` traz `analise` (reputação, linha do tempo, exposição); rota `/espelho` responde 200. |
| CLI 2.1 | 3 | versão 2.1; fontes CTI listadas; `lote` e `espelho` rodam offline (CPF/telefone: zero rede). |

## 2. Verificações manuais em navegador ✅
- **Dossiê 2.1**: banner de reputação, linha do tempo, diff com o alerta ThreatFox surgindo.
- **ESPELHO**: placar 65/100, classes de exposição, recomendações, linha do tempo. Captura em `manual/img/espelho.png`.
- **Painel 2.1**: chip de exposição, botão ESPELHO, banner de reputação, **anel vermelho** no nó de C2, linha do tempo. Captura em `manual/img/painel.png`.
- **Manual**: renderizado por seção com Playwright, **0 erros de console**.
- **MCP** `garimpo_espelho`/`garimpo_reputacao` exercitados.

## 3. Ao vivo (executado; bloqueado pelo ambiente ⚠️)
Investigações, lote e espelho rodaram de ponta a ponta sem exceção; cada `403` do proxy ficou na custódia com `status_http: 0`.

## 4. Esquemas conferidos / a confirmar
- **CTI**: os formatos usados seguem a documentação pública de cada feed (Feodo `ipblocklist.json`, SSLBL `sslipblacklist.csv`, OpenPhish `feed.txt`, Digitalside `latest*.txt`, ThreatFox `export/csv/recent/`). **Confirmar na máquina local** se cada feed segue keyless — o **abuse.ch passou a exigir Auth-Key em vários endpoints de API**; o GARIMPO usa só feeds de download, e degrada graciosamente (403 → custódia → "não acusa").
- Demais fontes: conforme o relatório da 2.0 (InternetDB e BrasilAPI confirmados; RIPEstat, urlscan, Keybase, GitHub-commits, qsa da BrasilAPI a confirmar na 1ª execução real).

## 5. Pendente — validar na sua máquina (5 minutos)

```bash
python3 garimpo.py investigar 8.8.8.8          # reputação: Feodo/SSLBL/Digitalside/ThreatFox
python3 garimpo.py espelho SEU-DOMINIO          # auto-auditoria OPSEC
python3 garimpo.py lote iocs.txt --exportar stix  # lote + STIX consolidado
python3 garimpo.py investigar <um IP de C2 conhecido>   # deve abrir com banner vermelho
```

Se um feed de CTI voltar vazio/403, a resposta bruta está em `evidencias/` — é ela que diz se virou pago.

## 6. Veredito
Núcleo, 33 fontes (contra fixtures), reputação CTI, análise (timeline/QSA/exposição), lote, ESPELHO, MCP e painel **aprovados** em quatro versões de Python. Fontes ao vivo **prontas, não observadas** nesta sandbox.
