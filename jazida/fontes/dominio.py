# -*- coding: utf-8 -*-
"""Fontes de domínio: RDAP (registro.br/rdap.org), DNS completo, CT (crt.sh e
Certspotter), Wayback e urlscan.io."""

from __future__ import annotations

import urllib.parse

from ..deteccao import RE_DOMINIO, formatar_cnpj, so_digitos, validar_cnpj
from . import fonte
from ._util import doh, respostas, subdominios_de, vcard_fn


@fonte("rdap_dominio", ["dominio"], "passiva", "rdap.registro.br (.br) / rdap.org",
       "1 requisição ao servidor RDAP do registro — nunca ao alvo")
def rdap_dominio(c, dominio):
    fatos, novas = [], []
    if dominio.endswith(".br"):
        r = c.get_json("rdap_dominio", f"https://rdap.registro.br/domain/{dominio}")
    else:
        r = c.get_json("rdap_dominio", f"https://rdap.org/domain/{dominio}")
    if not r:
        return fatos, novas
    for ev in r.get("events", []) or []:
        fatos.append(f"evento {ev.get('eventAction')}: {ev.get('eventDate')}")
    for st in r.get("status", []) or []:
        fatos.append(f"status: {st}")
    for ns in r.get("nameservers", []) or []:
        n = str(ns.get("ldhName") or "").lower().rstrip(".")
        if n:
            fatos.append(f"nameserver: {n}")
            novas.append(("dominio", n, "nameserver_de", 0.5))  # infra compartilhada: não pivota
    for ent in r.get("entities", []) or []:
        papeis = ",".join(ent.get("roles", []) or []) or "?"
        nome = vcard_fn(ent)
        if nome:
            fatos.append(f"{papeis}: {nome}")
        # registro.br publica o documento do titular em publicIds (RFC 9083)
        for pid in ent.get("publicIds", []) or []:
            tipo = str(pid.get("type", "")).lower()
            ident = str(pid.get("identifier", ""))
            if tipo == "cnpj" and validar_cnpj(ident):
                fatos.append(f"titular ({papeis}) com CNPJ {formatar_cnpj(ident)}")
                novas.append(("cnpj", formatar_cnpj(ident), "titular_do_dominio", 0.9))
            elif tipo == "cpf" or len(so_digitos(ident)) == 11:
                # decisão de projeto: CPF nunca é armazenado nem pivotado
                fatos.append(f"titular ({papeis}) é pessoa física — documento não coletado por decisão de projeto")
    return fatos, novas


@fonte("dns", ["dominio"], "passiva*", "dns.google (DoH)",
       "A/AAAA/MX/NS/TXT/SOA/CAA/DMARC via resolvedor público")
def dns(c, dominio):
    fatos, novas = [], []
    tipos = (("A", 1), ("AAAA", 28), ("MX", 15), ("NS", 2), ("TXT", 16), ("SOA", 6), ("CAA", 257))
    for nome_t, num in tipos:
        for dado in respostas(doh(c, "dns", dominio, nome_t), num):
            if nome_t == "TXT":
                if dado.startswith("v=spf1"):
                    fatos.append(f"SPF: {dado[:160]}")
                    for tok in dado.split():
                        if tok.startswith("include:"):
                            fatos.append(f"SPF delega envio a: {tok[8:]}")
                else:
                    fatos.append(f"TXT: {dado[:120]}")
                continue
            fatos.append(f"{nome_t}: {dado}")
            if nome_t in ("A", "AAAA"):
                novas.append(("ip", dado, "resolve_para", 0.9))
            elif nome_t == "MX":
                mx = dado.split()[-1].rstrip(".").lower()
                if RE_DOMINIO.match(mx):
                    novas.append(("dominio", mx, "servidor_de_email", 0.7))
            elif nome_t == "CAA":
                fatos.append(f"autoridade certificadora autorizada: {dado.split()[-1].strip(chr(34))}")
    for dado in respostas(doh(c, "dns", f"_dmarc.{dominio}", "TXT"), 16):
        fatos.append(f"DMARC: {dado[:160]}")
    return fatos, novas


@fonte("crtsh", ["dominio"], "passiva", "crt.sh",
       "lê o índice público de Certificate Transparency")
def crtsh(c, dominio):
    fatos, novas = [], []
    ct = c.get_json("crtsh", f"https://crt.sh/?q=%25.{urllib.parse.quote(dominio)}&output=json")
    if isinstance(ct, list):
        nomes = []
        for cert in ct[:400]:
            nomes.extend(str(cert.get("name_value", "")).splitlines())
        subs, total = subdominios_de(nomes, dominio)
        for s in subs:
            fatos.append(f"subdomínio (CT): {s}")
            novas.append(("dominio", s, "subdominio_de", 0.8))
        if total:
            fatos.append(f"subdomínios únicos em CT (crt.sh): {total}")
    return fatos, novas


@fonte("certspotter", ["dominio"], "passiva", "api.certspotter.com",
       "lê emissões de certificados já registradas (alternativa ao crt.sh)")
def certspotter(c, dominio):
    fatos, novas = [], []
    q = urllib.parse.urlencode({"domain": dominio, "include_subdomains": "true", "expand": "dns_names"})
    r = c.get_json("certspotter", f"https://api.certspotter.com/v1/issuances?{q}")
    if isinstance(r, list):
        nomes = [n for emissao in r for n in (emissao.get("dns_names") or [])]
        subs, total = subdominios_de(nomes, dominio)
        for s in subs:
            fatos.append(f"subdomínio (Certspotter): {s}")
            novas.append(("dominio", s, "subdominio_de", 0.8))
        if r:
            fatos.append(f"emissões de certificado vistas: {len(r)} · subdomínios únicos: {total}")
    return fatos, novas


@fonte("wayback", ["dominio"], "passiva", "web.archive.org (CDX)",
       "lê o índice do Internet Archive")
def wayback(c, dominio):
    fatos = []
    base = "https://web.archive.org/cdx/search/cdx?"
    prim = c.get_json("wayback", base + urllib.parse.urlencode(
        {"url": dominio, "output": "json", "limit": "1", "fl": "timestamp,original"}))
    if isinstance(prim, list) and len(prim) > 1:
        t = prim[1][0]
        fatos.append(f"primeiro snapshot no Internet Archive: {t[:4]}-{t[4:6]}-{t[6:8]}")
    ult = c.get_json("wayback", base + urllib.parse.urlencode(
        {"url": dominio, "output": "json", "limit": "-1", "fl": "timestamp,original"}))
    if isinstance(ult, list) and len(ult) > 1:
        t = ult[-1][0]
        fatos.append(f"último snapshot no Internet Archive: {t[:4]}-{t[4:6]}-{t[6:8]}")
    return fatos, []


@fonte("urlscan", ["dominio"], "passiva", "urlscan.io (busca pública)",
       "lê varreduras que terceiros JÁ fizeram; não submete nada")
def urlscan(c, dominio):
    fatos, novas = [], []
    q = urllib.parse.urlencode({"q": f"domain:{dominio}", "size": "10"})
    r = c.get_json("urlscan", f"https://urlscan.io/api/v1/search/?{q}")
    resultados = (r or {}).get("results", []) or []
    for item in resultados[:10]:
        page = item.get("page", {}) or {}
        quando = str((item.get("task", {}) or {}).get("time", ""))[:10]
        fatos.append(f"varredura pública {quando}: {page.get('url', '?')} · IP {page.get('ip', '?')} · "
                     f"{page.get('asnname', '?')} · servidor {page.get('server', '?')}")
        if page.get("ip"):
            # IP de varredura pode ser CDN: entra no grafo, mas não pivota
            novas.append(("ip", page["ip"], "visto_no_urlscan", 0.5))
    if resultados:
        fatos.append(f"varreduras públicas no urlscan.io: {(r or {}).get('total', len(resultados))}")
    return fatos, novas
