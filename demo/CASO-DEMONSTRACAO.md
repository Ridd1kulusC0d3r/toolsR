# Caso de demonstração — GARIMPO 2.1

## O que é
Duas coletas **fictícias** do mesmo alvo (`exemplo.com.br`), com uma semana de diferença, geradas pelo **motor real** (só a linha que fala com a rede é trocada por respostas sintéticas no formato real de cada API).

- `demo-anterior/` — 1º de outubro
- `demo/` — 8 de outubro, com `diff.json`, o quadro **Mudanças**, o relatório **ESPELHO** (`espelho.html`) e o banner de **reputação**

IPs e ASN são das faixas reservadas para documentação (RFC 5737 / RFC 5398). Pessoas e empresa são fictícias.

## O que observar (novidades 2.1)
1. **Reputação:** na semana 2, o IP `203.0.113.10` aparece no **ThreatFox** como C2 (como se o servidor tivesse sido comprometido) — banner vermelho no topo do dossiê, anel vermelho no grafo do painel, e a mudança aparece no diff.
2. **Linha do tempo:** fatos datados em ordem — abertura do CNPJ (2018), registro do domínio (2019), snapshots, o alerta de C2 (2026).
3. **ESPELHO:** abra `demo/espelho.html` — placar de exposição e classes defensivas.
4. **Pivô brasileiro:** RDAP do registro.br → CNPJ do titular → sócios, e-mail, CEP → coordenadas.

## Rode
```bash
python3 garimpo.py demo                       # recria em casos/demo e casos/demo-anterior
python3 garimpo.py verificar casos/demo
python3 garimpo.py diff casos/demo-anterior casos/demo
```
Ou no painel: **Abrir a demonstração**.
