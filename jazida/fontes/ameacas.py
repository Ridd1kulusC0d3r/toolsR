# -*- coding: utf-8 -*-
"""Fontes de inteligência de ameaças (CTI), todas keyless e por feed público.

Padrão: baixa UMA vez por investigação a lista/feed pública (o cliente cacheia
por URL, então vários alvos do mesmo tipo reaproveitam o download) e compara
localmente. É o mesmo desenho da lista de saídas Tor.

Honestidade importante: o abuse.ch passou a exigir uma Auth-Key (conta
gratuita) em vários endpoints de API. Aqui usamos **apenas feeds/listas de
download público**. Se algum deles passar a exigir chave, a requisição
devolve 403, fica registrada na custódia e a fonte simplesmente não acusa
nada — nunca derruba a investigação. Confirme a disponibilidade na sua
máquina (a sandbox de teste bloqueia a rede).

Um acerto de reputação é prefixado com "⚠ " para a camada de análise
(jazida/analise.py) somar os sinais por nó.
"""

from __future__ import annotations

import csv
import io
import json

from . import fonte

ALERTA = "⚠ "
# nomes das fontes de CTI — usados por jazida/analise.py para a reputação
NOMES_AMEACA = ("feodo_c2", "sslbl_c2", "openphish", "digitalside", "threatfox")

FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SSLBL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
OPENPHISH = "https://openphish.com/feed.txt"
DS_DOMINIOS = "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
DS_IPS = "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"
DS_HASHES = "https://osint.digitalside.it/Threat-Intel/lists/latesthashes.txt"
THREATFOX = "https://threatfox.abuse.ch/export/csv/recent/"


def _linhas(texto: str):
    for linha in (texto or "").splitlines():
        linha = linha.strip()
        if linha and not linha.startswith("#"):
            yield linha


def _csv_sem_comentario(texto: str):
    corpo = "\n".join(l for l in (texto or "").splitlines() if not l.lstrip().startswith("#"))
    return csv.reader(io.StringIO(corpo))


# --------------------------------------------------------------------- IP
@fonte("feodo_c2", ["ip"], "passiva", "feodotracker.abuse.ch",
       "lista pública de C2 de botnets (Dridex, Emotet, QakBot…) — baixa e compara local")
def feodo_c2(c, ip):
    texto = c.get_texto("feodo_c2", FEODO, accept="application/json")
    if texto is None:
        return [], []
    try:
        dados = json.loads(texto)
    except json.JSONDecodeError:
        return [], []
    for reg in dados if isinstance(dados, list) else []:
        if str(reg.get("ip_address")) == ip:
            malware = reg.get("malware") or "?"
            return [f"{ALERTA}consta no Feodo Tracker como C2 de botnet: {malware} "
                    f"(porta {reg.get('port')}, situação {reg.get('status')}, "
                    f"primeira vez {str(reg.get('first_seen'))[:10]})"], []
    return [f"não consta no Feodo Tracker ({sum(1 for _ in dados)} C2 na lista do momento)"], []


@fonte("sslbl_c2", ["ip"], "passiva", "sslbl.abuse.ch",
       "lista pública de IPs de C2 por certificado TLS malicioso (SSLBL) — baixa e compara local")
def sslbl_c2(c, ip):
    texto = c.get_texto("sslbl_c2", SSLBL, accept="text/csv")
    if texto is None:
        return [], []
    for linha in _csv_sem_comentario(texto):
        if len(linha) >= 2 and linha[1].strip() == ip:
            return [f"{ALERTA}consta na SSL Blacklist (SSLBL) como C2 TLS "
                    f"(primeira vez {linha[0][:10]}, porta {linha[2] if len(linha) > 2 else '?'})"], []
    return ["não consta na SSL Blacklist (SSLBL)"], []


# ---------------------------------------------------------- domínio / url
@fonte("openphish", ["dominio", "url"], "passiva", "openphish.com",
       "feed comunitário de URLs de phishing — baixa e compara o host local")
def openphish(c, valor):
    import urllib.parse
    texto = c.get_texto("openphish", OPENPHISH, accept="text/plain")
    if texto is None:
        return [], []
    alvo = valor.lower().rstrip("/")
    host_alvo = (urllib.parse.urlparse(alvo if "://" in alvo else "http://" + alvo).hostname or alvo)
    acertos = []
    total = 0
    for url in _linhas(texto):
        total += 1
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host == host_alvo or url.lower().rstrip("/") == alvo:
            acertos.append(url)
    if acertos:
        return [f"{ALERTA}host aparece em {len(acertos)} URL(s) de phishing no feed OpenPhish "
                f"(ex.: {acertos[0][:120]})"], []
    return [f"não aparece no feed OpenPhish ({total} URLs no momento)"], []


# ------------------------------------------------- Digitalside (multi-tipo)
def _digitalside(c, url, valor, rotulo):
    texto = c.get_texto("digitalside", url, accept="text/plain")
    if texto is None:
        return []
    alvo = valor.lower()
    for item in _linhas(texto):
        if item.lower() == alvo:
            return [f"{ALERTA}consta na feed Digitalside OSINT ({rotulo}) — indicador malicioso recente"]
    return [f"não consta na feed Digitalside OSINT ({rotulo})"]


@fonte("digitalside", ["dominio", "ip", "hash"], "passiva", "osint.digitalside.it",
       "feeds OSINT de IOCs recentes (domínios, IPs e hashes maliciosos) — baixa e compara local")
def digitalside(c, valor):
    from ..deteccao import detectar_tipo
    t = detectar_tipo(valor)
    if t == "ip":
        return _digitalside(c, DS_IPS, valor, "IPs"), []
    if t == "hash":
        return _digitalside(c, DS_HASHES, valor, "hashes"), []
    return _digitalside(c, DS_DOMINIOS, valor, "domínios"), []


# ------------------------------------------------- ThreatFox (multi-tipo)
@fonte("threatfox", ["ip", "dominio", "hash", "url"], "passiva", "threatfox.abuse.ch",
       "export CSV público de IOCs recentes com família de malware — baixa e compara local")
def threatfox(c, valor):
    texto = c.get_texto("threatfox", THREATFOX, accept="text/csv")
    if texto is None:
        return [], []
    alvo = valor.lower().rstrip("/")
    for linha in _csv_sem_comentario(texto):
        if len(linha) < 9:
            continue
        ioc = linha[2].strip().strip('"').lower()
        # ThreatFox grava IP como "ip:porta"
        if ioc == alvo or ioc.split(":")[0] == alvo:
            malware = linha[7].strip().strip('"') or linha[5].strip().strip('"') or "?"
            ameaca = linha[4].strip().strip('"')
            conf = linha[8].strip().strip('"')
            return [f"{ALERTA}consta no ThreatFox: {ameaca} / {malware} "
                    f"(confiança {conf}%, primeira vez {linha[0][:10]})"], []
    return ["não consta no export recente do ThreatFox"], []
