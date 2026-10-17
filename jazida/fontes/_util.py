# -*- coding: utf-8 -*-
"""Utilitários compartilhados pelas fontes."""

from __future__ import annotations

import re
import urllib.parse

RE_EMAIL_LIVRE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_URL_LIVRE = re.compile(r"https?://[^\s\"'<>]+")


def doh(c, fonte: str, nome: str, tipo: str):
    """DNS over HTTPS (Google). A consulta vai ao resolvedor, não ao alvo."""
    q = urllib.parse.urlencode({"name": nome, "type": tipo})
    return c.get_json(fonte, f"https://dns.google/resolve?{q}")


def respostas(r, tipo_num: int | None = None) -> list[str]:
    """Valores 'data' de um JSON DoH, filtrando pelo tipo numérico do registro."""
    out = []
    for ans in (r or {}).get("Answer", []) or []:
        if tipo_num is not None and ans.get("type") != tipo_num:
            continue
        out.append(str(ans.get("data", "")).strip().strip('"'))
    return out


def subdominios_de(nomes, dominio: str, limite: int = 25) -> tuple[list[str], int]:
    vistos = set()
    for nome in nomes:
        nome = str(nome).strip().lower().lstrip("*.").rstrip(".")
        if nome.endswith("." + dominio) and nome != dominio:
            vistos.add(nome)
    return sorted(vistos)[:limite], len(vistos)


def vcard_fn(entidade: dict) -> str:
    vc = entidade.get("vcardArray")
    if isinstance(vc, list) and len(vc) > 1:
        for item in vc[1]:
            if item and item[0] == "fn" and len(item) > 3:
                return str(item[3])
    return ""


def emails_em(texto: str) -> list[str]:
    return sorted({e.lower() for e in RE_EMAIL_LIVRE.findall(texto or "")})


# DDD → UF (Anatel). Usado só para análise offline de telefones.
DDD_UF = {
    **dict.fromkeys(["11", "12", "13", "14", "15", "16", "17", "18", "19"], "SP"),
    **dict.fromkeys(["21", "22", "24"], "RJ"), **dict.fromkeys(["27", "28"], "ES"),
    **dict.fromkeys(["31", "32", "33", "34", "35", "37", "38"], "MG"),
    **dict.fromkeys(["41", "42", "43", "44", "45", "46"], "PR"),
    **dict.fromkeys(["47", "48", "49"], "SC"),
    **dict.fromkeys(["51", "53", "54", "55"], "RS"), "61": "DF",
    **dict.fromkeys(["62", "64"], "GO"), "63": "TO", **dict.fromkeys(["65", "66"], "MT"),
    "67": "MS", "68": "AC", "69": "RO", **dict.fromkeys(["71", "73", "74", "75", "77"], "BA"),
    "79": "SE", **dict.fromkeys(["81", "87"], "PE"), "82": "AL", "83": "PB", "84": "RN",
    **dict.fromkeys(["85", "88"], "CE"), **dict.fromkeys(["86", "89"], "PI"),
    **dict.fromkeys(["91", "93", "94"], "PA"), **dict.fromkeys(["92", "97"], "AM"),
    "95": "RR", "96": "AP", **dict.fromkeys(["98", "99"], "MA"),
}
