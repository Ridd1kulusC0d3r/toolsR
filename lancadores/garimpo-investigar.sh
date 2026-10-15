#!/usr/bin/env bash
# GARIMPO — investigação guiada (Linux). Dois cliques (Executar no terminal) ou ./garimpo-investigar.sh
cd "$(dirname "$0")/.." || exit 1
read -rp "Digite o alvo (domínio, IP, e-mail, username, CNPJ, URL, telefone): " ALVO
SAIDA=$(python3 garimpo.py investigar "$ALVO" | tee /dev/tty)
DOSSIE=$(printf '%s\n' "$SAIDA" | sed -n 's/^✔ Dossiê: //p')
[ -n "$DOSSIE" ] && { xdg-open "$DOSSIE" 2>/dev/null || echo "Abra no navegador: $PWD/$DOSSIE"; }
