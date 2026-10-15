#!/usr/bin/env bash
# GARIMPO — demonstração offline (Linux/macOS). Dois cliques ou ./garimpo-demo.sh
cd "$(dirname "$0")/.." || exit 1
python3 garimpo.py demo
DOSSIE="casos/demo/dossie.html"
command -v xdg-open >/dev/null && xdg-open "$DOSSIE" || open "$DOSSIE" 2>/dev/null || \
  echo "Abra no navegador: $PWD/$DOSSIE"
