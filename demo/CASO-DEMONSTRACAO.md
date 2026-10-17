# Caso de demonstração — GARIMPO 2.0

## O que é
Duas coletas **fictícias** do mesmo alvo (`exemplo.com.br`), com uma semana de diferença, geradas pelo **motor real**: só a linha que fala com a rede é trocada por respostas sintéticas no formato real de cada API. Detecção, fontes, pivô, custódia, dossiê e diff rodam de verdade.

- `demo-anterior/` — 1º de outubro
- `demo/` — 8 de outubro, com `diff.json` e o quadro **Mudanças** no dossiê

IPs e ASN são das faixas reservadas para documentação (RFC 5737 / RFC 5398). Pessoas e empresa são fictícias.

## O que observar
1. **Pivô brasileiro:** o RDAP do registro.br traz o CNPJ do titular → BrasilAPI → sócios, e-mail, telefone e CEP → coordenadas.
2. **Mudanças:** subdomínio `staging` novo (CT), porta 8443 nova (InternetDB), sócio novo no QSA.
3. **Evidência por fato:** cada linha do dossiê tem `#n`, que abre a resposta bruta.
4. **Fronteira:** nameservers e o username `contato` aparecem pontilhados — achados, não consultados.

## Rode
```bash
python3 garimpo.py demo                       # recria em casos/demo e casos/demo-anterior
python3 garimpo.py verificar casos/demo
python3 garimpo.py diff casos/demo-anterior casos/demo
```
Ou no painel: **Abrir a demonstração**.
