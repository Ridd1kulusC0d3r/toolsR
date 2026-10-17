# -*- coding: utf-8 -*-
"""Registro de fontes (plugins).

Cada fonte é uma função `fn(cliente, valor) -> (fatos, novas)`:
  fatos: list[str]                      — o que se observou, em texto
  novas: list[(tipo, valor, relacao, confianca)] — entidades para o grafo

Regras do registro:
  - toda fonte declara nível de ruído e destino REAL dos bytes;
  - nenhuma fonte toca a infraestrutura do alvo (o GARIMPO é sempre passivo);
  - extração sempre a partir de dados estruturados (JSON/pacotes), nunca de
    texto renderizado por outra ferramenta.

Para criar uma fonte nova basta decorar uma função com @fonte(...) num
módulo deste pacote e importá-lo no fim deste arquivo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

NIVEIS = {
    "passiva": "consulta um terceiro que já tem os dados; o alvo não recebe nada",
    "passiva*": "consulta DNS via resolvedor público; os nameservers do alvo veem o resolvedor, não você",
    "offline": "cálculo local; nenhum byte sai da máquina",
}


@dataclass(frozen=True)
class Fonte:
    nome: str
    tipos: tuple
    nivel: str
    destino: str
    descricao: str
    fn: Callable


REGISTRO: list[Fonte] = []


def fonte(nome: str, tipos, nivel: str, destino: str, descricao: str):
    if nivel not in NIVEIS:
        raise ValueError(f"nível desconhecido: {nivel}")

    def deco(fn):
        REGISTRO.append(Fonte(nome, tuple(tipos), nivel, destino, descricao, fn))
        return fn
    return deco


def fontes_para(tipo: str) -> list[Fonte]:
    return [f for f in REGISTRO if tipo in f.tipos]


def por_nome(nome: str) -> Fonte:
    for f in REGISTRO:
        if f.nome == nome:
            return f
    raise KeyError(nome)


def tabela_ruido() -> list[tuple[str, str, str, str]]:
    """(fonte, tipos, nível, o que é enviado e para onde) — gerada do código."""
    return [(f.nome, ",".join(f.tipos), f.nivel, f"{f.destino} — {f.descricao}") for f in REGISTRO]


from . import dominio, ip, pessoais, brasil, artefatos  # noqa: E402,F401  (registra as fontes)
