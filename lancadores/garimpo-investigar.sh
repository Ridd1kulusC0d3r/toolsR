#!/usr/bin/env bash
# GARIMPO — investigação guiada (Linux/macOS)
cd "$(dirname "$0")/.." || exit 1
read -rp "Digite o alvo (domínio, IP, e-mail, username, CNPJ, URL): " ALVO
python3 garimpo.py investigar "$ALVO"
