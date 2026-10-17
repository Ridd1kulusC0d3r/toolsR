#!/usr/bin/env bash
# GARIMPO — painel web local (macOS). Dois cliques no Finder; feche a janela para encerrar.
cd "$(dirname "$0")/.." || exit 1
python3 garimpo.py painel
