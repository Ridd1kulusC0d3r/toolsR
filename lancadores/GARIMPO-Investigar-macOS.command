#!/usr/bin/env bash
# GARIMPO — investigação guiada (macOS). Dois cliques no Finder.
cd "$(dirname "$0")/.." || exit 1
read -rp "Digite o alvo (domínio, IP, e-mail, username, CNPJ, URL, telefone): " ALVO
SAIDA=$(python3 garimpo.py investigar "$ALVO" | tee /dev/tty)
DOSSIE=$(printf '%s\n' "$SAIDA" | sed -n 's/^✔ Dossiê: //p')
[ -n "$DOSSIE" ] && open "$DOSSIE"
echo; read -rp "Pressione Enter para fechar..." _
