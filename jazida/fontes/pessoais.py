# -*- coding: utf-8 -*-
"""Fontes de identidade digital: e-mail e username.

Gravatar, keys.openpgp.org (UIDs da chave), GitHub (perfil + e-mails de
commits públicos), Keybase (contas provadas criptograficamente) e Hacker News.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import urllib.parse

from ..deteccao import RE_DOMINIO, RE_USERNAME
from . import fonte
from ._util import emails_em, RE_URL_LIVRE


# ----------------------------------------------------------------- e-mail
@fonte("email_local", ["email"], "offline", "nenhum",
       "separa domínio e parte local do e-mail")
def email_local(c, email):
    _ = c
    local, dominio = email.split("@", 1)
    novas = [("dominio", dominio.lower(), "dominio_do_email", 1.0)]
    if RE_USERNAME.match(local):
        novas.append(("username", local, "parte_local_do_email", 0.5))
    return [f"domínio do e-mail: {dominio.lower()}"], novas


@fonte("gravatar", ["email"], "passiva", "gravatar.com",
       "1 requisição com o hash MD5 do e-mail (o dono não é notificado)")
def gravatar(c, email):
    fatos, novas = [], []
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r = c.get_json("gravatar", f"https://en.gravatar.com/{md5}.json")
    if r and r.get("entry"):
        e0 = r["entry"][0]
        if e0.get("displayName"):
            fatos.append(f"nome exibido: {e0['displayName']}")
        if e0.get("preferredUsername"):
            u = e0["preferredUsername"]
            fatos.append(f"username preferido: {u}")
            novas.append(("username", u, "mesmo_titular", 0.8))
        for conta in (e0.get("accounts") or [])[:10]:
            fatos.append(f"conta vinculada: {conta.get('shortname')} → {conta.get('url')}")
            if conta.get("username"):
                novas.append(("username", conta["username"], f"conta_{conta.get('shortname', 'externa')}", 0.7))
    return fatos, novas


def uids_openpgp(armadura: str) -> list[str]:
    """Extrai os User IDs (pacote tag 13) de uma chave pública OpenPGP em
    armadura ASCII — parser mínimo da RFC 4880/9580, só stdlib."""
    corpo = []
    dentro = False
    for linha in armadura.splitlines():
        linha = linha.strip()
        if linha.startswith("-----BEGIN PGP"):
            dentro, corpo = True, []
            continue
        if linha.startswith("-----END PGP"):
            break
        if not dentro or ":" in linha and not corpo:
            continue  # cabeçalhos da armadura
        if linha == "" or linha.startswith("="):  # linha vazia ou checksum CRC24
            continue
        corpo.append(linha)
    try:
        dados = base64.b64decode("".join(corpo))
    except (ValueError, base64.binascii.Error):
        return []
    uids, i = [], 0
    while i < len(dados):
        cab = dados[i]
        if not cab & 0x80:
            break
        if cab & 0x40:  # formato novo
            tag, i = cab & 0x3F, i + 1
            if i >= len(dados):
                break
            o = dados[i]
            if o < 192:
                tam, i = o, i + 1
            elif o < 224:
                tam, i = ((o - 192) << 8) + dados[i + 1] + 192, i + 2
            elif o == 255:
                tam, i = int.from_bytes(dados[i + 1:i + 5], "big"), i + 5
            else:
                break  # comprimento parcial: não usado em chaves publicadas
        else:  # formato antigo
            tag, ltipo, i = (cab >> 2) & 0x0F, cab & 0x03, i + 1
            n = {0: 1, 1: 2, 2: 4}.get(ltipo)
            if n is None:
                break
            tam, i = int.from_bytes(dados[i:i + n], "big"), i + n
        if tag == 13:
            uids.append(dados[i:i + tam].decode("utf-8", errors="replace"))
        i += tam
    return uids


@fonte("pgp", ["email"], "passiva", "keys.openpgp.org",
       "procura chave pública publicada (só e-mails verificados aparecem)")
def pgp(c, email):
    fatos, novas = [], []
    texto = c.get_texto("pgp", "https://keys.openpgp.org/vks/v1/by-email/" + urllib.parse.quote(email),
                        accept="application/pgp-keys")
    if not texto or "BEGIN PGP" not in texto:
        return fatos, novas
    uids = uids_openpgp(texto)
    fatos.append(f"chave pública OpenPGP publicada · {len(uids)} identidade(s) verificada(s)")
    for uid in uids:
        fatos.append(f"UID: {uid}")
        m = re.match(r"^\s*(.*?)\s*<([^>]+)>\s*$", uid)
        if m:
            nome, outro = m.group(1).strip(), m.group(2).strip().lower()
            if nome:
                novas.append(("pessoa", nome, "nome_na_chave_pgp", 0.6))
            if outro != email.lower():
                novas.append(("email", outro, "mesma_chave_pgp", 0.85))
    return fatos, novas


# ----------------------------------------------------------------- username
@fonte("github", ["username"], "passiva", "api.github.com",
       "perfil público (60 req/h sem token)")
def github(c, user):
    fatos, novas = [], []
    gh = c.get_json("github", f"https://api.github.com/users/{urllib.parse.quote(user)}")
    if gh and gh.get("login"):
        fatos.append(f"perfil: {gh.get('html_url')}")
        if gh.get("name"):
            fatos.append(f"nome: {gh['name']}")
            novas.append(("pessoa", gh["name"], "nome_no_github", 0.7))
        if gh.get("email"):
            fatos.append(f"e-mail público: {gh['email']}")
            novas.append(("email", gh["email"], "email_publico_github", 0.9))
        if gh.get("blog"):
            fatos.append(f"site: {gh['blog']}")
            host = urllib.parse.urlparse(gh["blog"] if "://" in gh["blog"] else "http://" + gh["blog"]).hostname
            if host and RE_DOMINIO.match(host):
                novas.append(("dominio", host.lower(), "site_no_github", 0.7))
        for campo, rotulo in (("company", "empresa declarada"), ("location", "localização declarada"),
                              ("twitter_username", "X/Twitter declarado"), ("bio", "bio")):
            if gh.get(campo):
                fatos.append(f"{rotulo}: {str(gh[campo])[:160]}")
        if gh.get("twitter_username"):
            novas.append(("username", gh["twitter_username"], "twitter_no_github", 0.7))
        fatos.append(f"repos públicos: {gh.get('public_repos')} · seguidores: {gh.get('followers')} · "
                     f"criado em: {str(gh.get('created_at'))[:10]}")
    return fatos, novas


@fonte("github_commits", ["username"], "passiva", "api.github.com (eventos públicos)",
       "e-mails de autor em commits públicos recentes")
def github_commits(c, user):
    fatos, novas = [], []
    ev = c.get_json("github_commits", f"https://api.github.com/users/{urllib.parse.quote(user)}/events/public?per_page=30")
    if not isinstance(ev, list):
        return fatos, novas
    vistos = {}
    for e in ev:
        if e.get("type") != "PushEvent":
            continue
        for commit in (e.get("payload") or {}).get("commits") or []:
            autor = commit.get("author") or {}
            em = str(autor.get("email", "")).lower()
            if em and "noreply" not in em:
                vistos.setdefault(em, autor.get("name", ""))
    for em, nome in sorted(vistos.items()):
        fatos.append(f"e-mail em commit público: {em}" + (f" (autor: {nome})" if nome else ""))
        novas.append(("email", em, "email_de_commit", 0.8))
    if not vistos:
        fatos.append(f"{len(ev)} evento(s) público(s) recente(s); nenhum e-mail de commit exposto")
    return fatos, novas


@fonte("keybase", ["username"], "passiva", "keybase.io",
       "contas e domínios PROVADOS criptograficamente pelo titular")
def keybase(c, user):
    fatos, novas = [], []
    q = urllib.parse.urlencode({"usernames": user})
    r = c.get_json("keybase", f"https://keybase.io/_/api/1.0/user/lookup.json?{q}")
    them = (r or {}).get("them") or []
    if not them or not them[0]:
        return fatos, novas
    t = them[0]
    perfil = t.get("profile") or {}
    if perfil.get("full_name"):
        fatos.append(f"nome no Keybase: {perfil['full_name']}")
        novas.append(("pessoa", perfil["full_name"], "nome_no_keybase", 0.7))
    for prova in ((t.get("proofs_summary") or {}).get("all") or [])[:20]:
        ptipo, tag = prova.get("proof_type", "?"), prova.get("nametag", "")
        fatos.append(f"prova Keybase: {ptipo} → {tag} ({prova.get('service_url', '')})")
        if ptipo in ("dns", "generic_web_site") and RE_DOMINIO.match(tag):
            novas.append(("dominio", tag.lower(), "provado_no_keybase", 0.85))
        elif tag and RE_USERNAME.match(tag) and tag.lower() != user.lower():
            novas.append(("username", tag, f"provado_no_keybase_{ptipo}", 0.85))
    return fatos, novas


@fonte("hackernews", ["username"], "passiva", "hacker-news.firebaseio.com",
       "perfil público do Hacker News (API oficial)")
def hackernews(c, user):
    import datetime as _dt
    fatos, novas = [], []
    r = c.get_json("hackernews", f"https://hacker-news.firebaseio.com/v0/user/{urllib.parse.quote(user)}.json")
    if not r or not r.get("id"):
        return fatos, novas
    criado = _dt.datetime.fromtimestamp(int(r.get("created", 0)), _dt.timezone.utc).date().isoformat()
    fatos.append(f"conta no Hacker News desde {criado} · karma {r.get('karma')}")
    sobre = html.unescape(re.sub(r"<[^>]+>", " ", str(r.get("about") or "")))
    if sobre.strip():
        fatos.append(f"sobre: {' '.join(sobre.split())[:200]}")
        for em in emails_em(sobre):
            novas.append(("email", em, "email_no_perfil_hn", 0.7))
        for url in RE_URL_LIVRE.findall(sobre)[:5]:
            host = urllib.parse.urlparse(url).hostname
            if host and RE_DOMINIO.match(host):
                novas.append(("dominio", host.lower(), "site_no_perfil_hn", 0.6))
    return fatos, novas
