#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GARIMPO 2.0 — motor de pivô OSINT passivo, 100% Python stdlib (família DEIVOSINT).

Porta de entrada. O núcleo mora no pacote `jazida/` (a jazida do garimpo).

    python3 garimpo.py investigar ALVO          # investiga e gera dossiê
    python3 garimpo.py monitorar ALVO --contra CASO_ANTERIOR
    python3 garimpo.py diff CASO_A CASO_B
    python3 garimpo.py exportar CASO stix graphml csv
    python3 garimpo.py painel                   # painel web local
    python3 garimpo.py mcp                      # servidor MCP (Claude etc.)
    python3 garimpo.py fontes | detectar V | verificar CASO | demo | versao

Sempre passivo: nenhuma requisição toca a infraestrutura do alvo.
Licença MIT · Deivison Lourenço (@Ridd1kulusC0d3r) · DEIVOSINT.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jazida import *  # noqa: E402,F401,F403  (API pública para quem importa garimpo)
from jazida.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
