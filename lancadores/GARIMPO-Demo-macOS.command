#!/usr/bin/env bash
# GARIMPO — demonstração offline (macOS). Dois cliques no Finder.
# Se o macOS bloquear: botão direito → Abrir (só na primeira vez).
cd "$(dirname "$0")/.." || exit 1
python3 garimpo.py demo && open "casos/demo/dossie.html"
echo; read -rp "Pronto. Pressione Enter para fechar..." _
