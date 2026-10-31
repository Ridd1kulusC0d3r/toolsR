#!/usr/bin/env bash
# GARIMPO — ESPELHO (auto-auditoria OPSEC, Linux). Rode só no SEU ativo.
cd "$(dirname "$0")/.." || exit 1
read -rp "Digite o SEU domínio/marca: " ALVO
SAIDA=$(python3 garimpo.py espelho "$ALVO" | tee /dev/tty)
REL=$(printf '%s\n' "$SAIDA" | sed -n 's/^✔ Relatório ESPELHO: //p')
[ -n "$REL" ] && { xdg-open "$REL" 2>/dev/null || echo "Abra: $PWD/$REL"; }
