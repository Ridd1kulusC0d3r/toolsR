# -*- coding: utf-8 -*-
"""Fontes de IP e ASN: RDAP, InternetDB (Shodan keyless), PTR, RIPEstat e a
lista oficial de saídas Tor."""

from __future__ import annotations

import ipaddress
import urllib.parse

from ..deteccao import RE_DOMINIO, so_digitos
from . import fonte
from ._util import doh, respostas

TOR_LISTA = "https://check.torproject.org/torbulkexitlist"


@fonte("rdap_ip", ["ip"], "passiva", "rdap.org → RIR responsável",
       "dono do bloco, país e contatos do registro regional")
def rdap_ip(c, ip):
    fatos = []
    r = c.get_json("rdap_ip", f"https://rdap.org/ip/{ip}")
    if r:
        if r.get("name"):
            fatos.append(f"bloco: {r['name']}")
        if r.get("startAddress") and r.get("endAddress"):
            fatos.append(f"faixa: {r['startAddress']} – {r['endAddress']}")
        if r.get("country"):
            fatos.append(f"país do registro: {r['country']}")
        for ent in (r.get("entities") or [])[:4]:
            fatos.append(f"entidade com papel: {','.join(ent.get('roles', []) or [])}")
    return fatos, []


@fonte("internetdb", ["ip"], "passiva", "internetdb.shodan.io",
       "lê o índice EXISTENTE da Shodan; não dispara scan")
def internetdb(c, ip):
    fatos, novas = [], []
    r = c.get_json("internetdb", f"https://internetdb.shodan.io/{ip}")
    if r and not r.get("detail"):
        if r.get("ports"):
            fatos.append(f"portas vistas pela Shodan: {r['ports']}")
        for cve in (r.get("vulns") or [])[:15]:
            fatos.append(f"vulnerabilidade indexada: {cve}")
        for tag in r.get("tags") or []:
            fatos.append(f"etiqueta Shodan: {tag}")
        for cpe in (r.get("cpes") or [])[:10]:
            fatos.append(f"software (CPE): {cpe}")
        for h in (r.get("hostnames") or [])[:8]:
            fatos.append(f"hostname: {h}")
            if RE_DOMINIO.match(h):
                novas.append(("dominio", h.lower(), "hospedado_em", 0.7))
    return fatos, novas


@fonte("ptr", ["ip"], "passiva*", "dns.google (DoH)", "DNS reverso (PTR)")
def ptr(c, ip):
    fatos, novas = [], []
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return fatos, novas
    for h in respostas(doh(c, "ptr", rev, "PTR"), 12):
        h = h.rstrip(".").lower()
        fatos.append(f"PTR: {h}")
        if RE_DOMINIO.match(h):
            novas.append(("dominio", h, "dns_reverso", 0.6))
    return fatos, novas


@fonte("ripestat_ip", ["ip"], "passiva", "stat.ripe.net",
       "prefixo anunciado e ASN de origem (dados de roteamento BGP)")
def ripestat_ip(c, ip):
    fatos, novas = [], []
    q = urllib.parse.urlencode({"resource": ip})
    r = c.get_json("ripestat_ip", f"https://stat.ripe.net/data/prefix-overview/data.json?{q}")
    d = (r or {}).get("data") or {}
    if d.get("resource") and d.get("announced"):
        fatos.append(f"prefixo anunciado: {d['resource']}")
    elif d:
        fatos.append("IP não anunciado na tabela BGP global no momento da consulta")
    for a in d.get("asns") or []:
        asn = a.get("asn")
        if asn:
            fatos.append(f"origem BGP: AS{asn} — {a.get('holder', '?')}")
            novas.append(("asn", f"AS{asn}", "anunciado_por", 0.9))
    return fatos, novas


@fonte("ripestat_asn", ["asn"], "passiva", "stat.ripe.net",
       "dono do sistema autônomo e quantidade de prefixos anunciados")
def ripestat_asn(c, asn):
    fatos = []
    num = so_digitos(asn)
    r = c.get_json("ripestat_asn", f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{num}")
    d = (r or {}).get("data") or {}
    if d.get("holder"):
        fatos.append(f"titular: {d['holder']}")
    if "announced" in d:
        fatos.append("anunciando rotas agora" if d["announced"] else "sem rotas anunciadas agora")
    p = c.get_json("ripestat_asn", f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{num}")
    prefixos = ((p or {}).get("data") or {}).get("prefixes")
    if isinstance(prefixos, list):
        v4 = sum(1 for x in prefixos if ":" not in str(x.get("prefix", "")))
        fatos.append(f"prefixos anunciados: {len(prefixos)} ({v4} IPv4, {len(prefixos) - v4} IPv6)")
    return fatos, []


@fonte("tor_saida", ["ip"], "passiva", "check.torproject.org",
       "baixa UMA vez por investigação a lista pública de saídas Tor e compara localmente")
def tor_saida(c, ip):
    texto = c.get_texto("tor_saida", TOR_LISTA, accept="text/plain")
    if texto is None:
        return [], []
    saidas = {linha.strip() for linha in texto.splitlines() if linha.strip() and not linha.startswith("#")}
    if ip in saidas:
        return ["É NÓ DE SAÍDA TOR (lista oficial do Tor Project, no momento da consulta)"], []
    if ":" in ip:
        return ["lista de saídas Tor cobre só IPv4 — IPv6 não avaliado"], []
    return [f"não consta entre as {len(saidas)} saídas Tor da lista oficial"], []
