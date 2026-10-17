# ⛏️ COMECE AQUI — GARIMPO 2.0

**Uma ação por vez. Siga na ordem.**

## ✅ Ação 1 — Confira o Python (30 segundos)

```bash
python3 --version
```

Apareceu `Python 3.9` ou maior? **Pronto** — o GARIMPO não instala nada. (Windows: tente `python --version`.)

## ✅ Ação 2 — Abra o painel (dois cliques)

Na pasta `lancadores/`, dois cliques em:

- Windows: `GARIMPO-Painel-Windows.bat`
- macOS: `GARIMPO-Painel-macOS.command` (na 1ª vez: botão direito → Abrir)
- Linux: `garimpo-painel.sh`

O navegador abre em `http://127.0.0.1:8765`. *(Terminal: `python3 garimpo.py painel`.)*

## ✅ Ação 3 — Clique em "Abrir a demonstração"

Duas coletas fictícias de `exemplo.com.br` com uma semana de diferença. Repare no quadro **Mudanças** (subdomínio novo, porta nova, sócio novo), arraste os nós do grafo e clique num `#n` para ver a evidência bruta.

## ✅ Ação 4 — Sua primeira investigação real

No painel, digite um alvo **que você tem autorização para investigar** e clique em **Garimpar**.
*(Terminal: `python3 garimpo.py investigar exemplo.com.br`.)*

## ✅ Ação 5 — Verifique e entregue

No painel: **Verificar custódia** → deve aparecer `✔ custódia ÍNTEGRA`. Para entregar, envie a pasta do caso inteira (fica em `casos/`).

---

**Depois, quando quiser:** monitorar um alvo toda semana (`monitorar`), exportar para MISP/OpenCTI/Gephi/Maltego (`exportar`), ou plugar no Claude (`mcp`). Tudo explicado em **`manual/manual.html`**.

> ⚖️ **Uso legal e autorizado apenas.** O GARIMPO é sempre passivo (nunca toca a infraestrutura do alvo), mas passivo não é anônimo: cada fonte vê o que você pesquisou. `python3 garimpo.py fontes` mostra a tabela de ruído.
