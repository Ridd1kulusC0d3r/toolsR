# -*- coding: utf-8 -*-
"""Fontes de URL, hash, pessoa e organização."""

from __future__ import annotations

import urllib.parse

from ..deteccao import RE_DOMINIO
from . import fonte


@fonte("url_host", ["url"], "offline", "nenhum", "extrai o host da URL")
def url_host(c, url):
    _ = c
    host = urllib.parse.urlparse(url).hostname or ""
    if host and RE_DOMINIO.match(host):
        return [f"host: {host.lower()}"], [("dominio", host.lower(), "host_da_url", 1.0)]
    return [], []


@fonte("wayback_url", ["url"], "passiva", "archive.org (availability API)",
       "snapshot mais próximo da URL no Internet Archive")
def wayback_url(c, url):
    r = c.get_json("wayback_url", "https://archive.org/wayback/available?" + urllib.parse.urlencode({"url": url}))
    snap = ((r or {}).get("archived_snapshots") or {}).get("closest")
    if snap:
        return [f"snapshot mais próximo: {snap.get('timestamp')} → {snap.get('url')}"], []
    return (["sem snapshot no Internet Archive"] if r is not None else []), []


@fonte("circl_hashlookup", ["hash"], "passiva", "hashlookup.circl.lu",
       "o arquivo é conhecido (NSRL e outras bases de software legítimo)?")
def circl_hashlookup(c, h):
    algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
    status, corpo = c.get("circl_hashlookup", f"https://hashlookup.circl.lu/lookup/{algo}/{h.lower()}")
    fatos = [f"formato: {algo.upper()}"]
    if status == 404:
        fatos.append("não consta no CIRCL hashlookup — desconhecido NÃO significa malicioso")
    elif status == 200:
        import json
        try:
            r = json.loads(corpo.decode("utf-8", errors="replace"))
        except ValueError:
            r = {}
        nome = r.get("FileName") or r.get("filename")
        fatos.append("arquivo CONHECIDO em base de software legítimo" + (f": {nome}" if nome else ""))
        for chave in ("ProductName", "ProductVersion", "ProductManufacturer", "FileSize", "source"):
            if r.get(chave):
                fatos.append(f"{chave}: {r[chave]}")
    return fatos, []


@fonte("nota_pessoa", ["pessoa", "organizacao"], "offline", "nenhum",
       "registra o nome no grafo; pivô por nome exige buscador (fora do modo keyless)")
def nota_pessoa(c, nome):
    _ = c, nome
    return ["registrada no grafo; pivô por nome exige buscador (fora do modo keyless)"], []
