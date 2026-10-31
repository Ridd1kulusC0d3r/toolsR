# -*- coding: utf-8 -*-
"""Enriquecimento em lote: vários IOCs num caso só.

Lê uma lista de alvos (um por linha, ou uma coluna de CSV) — o típico export
de um SIEM/feed — e enriquece todos passivamente num único caso, com custódia
e grafo compartilhados, um dossiê e (opcional) um STIX consolidados.
"""

from __future__ import annotations

import csv
import io
import os

from .motor import investigar_varios
from .rede import Orcamento


def ler_alvos(caminho: str, coluna: str | None = None, limite: int = 500) -> list[str]:
    """Lê alvos de um arquivo. Aceita TXT (um por linha, # comenta) ou CSV.

    Para CSV, usa a coluna `coluna` (por nome do cabeçalho) ou a primeira."""
    with open(caminho, encoding="utf-8-sig") as f:
        texto = f.read()
    alvos: list[str] = []
    cabecalho = texto.splitlines()[0] if texto.strip() else ""
    eh_csv = caminho.lower().endswith(".csv") or ("," in cabecalho and coluna)
    if eh_csv:
        leitor = csv.reader(io.StringIO(texto))
        linhas = list(leitor)
        if not linhas:
            return []
        cab = [c.strip().lower() for c in linhas[0]]
        idx = 0
        if coluna and coluna.strip().lower() in cab:
            idx = cab.index(coluna.strip().lower())
            linhas = linhas[1:]
        elif coluna is None and any(h in cab for h in ("ioc", "indicator", "value", "alvo", "target")):
            for h in ("ioc", "indicator", "value", "alvo", "target"):
                if h in cab:
                    idx = cab.index(h)
                    linhas = linhas[1:]
                    break
        for linha in linhas:
            if idx < len(linha) and linha[idx].strip():
                alvos.append(linha[idx].strip())
    else:
        for linha in texto.splitlines():
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                alvos.append(linha.split(",")[0].strip())
    # dedup mantendo ordem, com teto
    vistos, saida = set(), []
    for a in alvos:
        if a.lower() not in vistos:
            vistos.add(a.lower())
            saida.append(a)
        if len(saida) >= limite:
            break
    return saida


def investigar_lote(alvos, orc: Orcamento, caso_dir: str, silencioso: bool = False,
                    paralelo: int = 4, log=None, progresso=None, cliente_cls=None) -> dict:
    kw = {"silencioso": silencioso, "paralelo": paralelo, "log": log, "progresso": progresso}
    if cliente_cls is not None:
        kw["cliente_cls"] = cliente_cls
    caso = investigar_varios(alvos, orc, caso_dir, **kw)
    caso["lote"] = {"n_alvos": len(alvos)}
    from .motor import salvar_caso
    salvar_caso(caso, caso_dir)
    return caso


def ler_e_investigar(caminho: str, orc: Orcamento, caso_dir: str, coluna: str | None = None,
                     **kw) -> dict:
    alvos = ler_alvos(caminho, coluna)
    if not alvos:
        raise ValueError(f"nenhum alvo lido de {caminho}")
    os.makedirs(caso_dir, exist_ok=True)
    return investigar_lote(alvos, orc, caso_dir, **kw)
