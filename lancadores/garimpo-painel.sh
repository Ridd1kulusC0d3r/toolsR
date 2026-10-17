#!/usr/bin/env bash
# GARIMPO — painel web local (Linux). Ctrl+C para encerrar.
cd "$(dirname "$0")/.." || exit 1
python3 garimpo.py painel
