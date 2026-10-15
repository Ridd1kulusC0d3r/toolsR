# Caso de demonstração — GARIMPO

## O que é
Um caso **100% offline e determinístico** (`python3 garimpo.py demo`) com dados sintéticos:
seed `exemplo.com.br` → IP fictício `203.0.113.10` (faixa reservada para documentação)
→ subdomínio `app.exemplo.com.br`. Serve para conhecer o formato do dossiê, do
`caso.json` e do `ledger.jsonl` sem gastar uma requisição e sem tocar entidade real.

## Rode
```bash
python3 garimpo.py demo            # gera em casos/demo/
python3 garimpo.py verificar casos/demo
```
Ou dois cliques em `lancadores/GARIMPO-Demo-Windows.bat` / `lancadores/garimpo-demo.sh`.

## O que observar no dossiê
1. O grafo SVG com o seed maior no centro e 2 entidades na profundidade 1;
2. Cada fato com a fonte na coluna da esquerda;
3. O aviso de custódia no rodapé — e o `verificar` respondendo ÍNTEGRA.

Um dossiê real de referência também está em `demo/caso-demo/` (gerado por esta entrega).
