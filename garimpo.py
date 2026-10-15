#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GARIMPO — Motor de pivô OSINT passivo, 100% stdlib.  (família DEIVOSINT)

Nascido da engenharia reversa do OpenOSINT/OpenOSINT, o GARIMPO mantém o que
aquele projeto acerta (passivo por padrão, orçamento de chamadas, proveniência)
e corrige as lacunas encontradas:

  1. Fontes brasileiras de primeira classe (registro.br RDAP, BrasilAPI/CNPJ,
     validação offline de CPF/CNPJ).
  2. Nenhuma dependência: Python 3.9+ puro — sem LLM, sem API key obrigatória.
  3. Pivô determinístico: extração a partir de JSON estruturado por fonte,
     nunca regex sobre texto livre de saída de ferramenta.
  4. Cadeia de custódia forense: toda resposta bruta é salva, hasheada com
     SHA-256 e encadeada num ledger (hash do registro anterior entra no
     hash do próximo) — qualquer adulteração quebra a corrente.
  5. Fontes keyless que o OpenOSINT ignora: InternetDB (Shodan sem chave),
     crt.sh, Wayback CDX.
  6. Dossiê HTML standalone em pt-BR, com grafo SVG, aberto offline.

Uso:
    python3 garimpo.py investigar ALVO [--profundidade N] [--max-entidades N]
                                       [--max-requisicoes N] [--caso DIR]
    python3 garimpo.py detectar VALOR
    python3 garimpo.py fontes
    python3 garimpo.py verificar CASO_DIR          # confere a cadeia de custódia
    python3 garimpo.py demo                        # caso de demonstração offline

Modo passivo SEMPRE: nenhuma requisição toca a infraestrutura do alvo.
Consultas vão apenas a terceiros (RDAP, DoH, crt.sh, APIs públicas) — e esses
terceiros veem o que você pesquisou. Passivo não é anônimo.

Licença: MIT.  Autor: Deivison Lourenço (@Ridd1kulusC0d3r) · DEIVOSINT.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import html as _html
import ipaddress
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

VERSAO = "1.0.0"
USER_AGENT = f"GARIMPO/{VERSAO} (DEIVOSINT; OSINT passivo; +https://github.com/Ridd1kulusC0d3r/toolsR)"
TIMEOUT = 15  # segundos por requisição

# ---------------------------------------------------------------------------
# 1. DETECÇÃO DE ENTIDADE (melhoria: CPF/CNPJ/BR-phone que o OpenOSINT não tem)
# ---------------------------------------------------------------------------

RE_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}$", re.IGNORECASE)
RE_URL = re.compile(r"^https?://", re.IGNORECASE)
RE_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
RE_DOMINIO = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9\-]{2,})+$"
)
RE_CPF = re.compile(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$")
RE_CNPJ = re.compile(r"^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$")
RE_TELEFONE = re.compile(r"^\+?\d{7,15}$")
RE_USERNAME = re.compile(r"^[A-Za-z0-9._\-]{2,39}$")


def _so_digitos(v: str) -> str:
    return re.sub(r"\D", "", v)


def validar_cpf(cpf: str) -> bool:
    """Valida os dígitos verificadores de um CPF (offline)."""
    d = _so_digitos(cpf)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for i in (9, 10):
        soma = sum(int(d[j]) * ((i + 1) - j) for j in range(i))
        dv = (soma * 10) % 11
        if dv == 10:
            dv = 0
        if dv != int(d[i]):
            return False
    return True


def validar_cnpj(cnpj: str) -> bool:
    """Valida os dígitos verificadores de um CNPJ (offline)."""
    d = _so_digitos(cnpj)
    if len(d) != 14 or d == d[0] * 14:
        return False
    pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    pesos2 = [6] + pesos1
    for pesos, i in ((pesos1, 12), (pesos2, 13)):
        soma = sum(int(d[j]) * pesos[j] for j in range(i))
        dv = soma % 11
        dv = 0 if dv < 2 else 11 - dv
        if dv != int(d[i]):
            return False
    return True


def detectar_tipo(valor: str) -> str:
    """Classifica um valor em um tipo de entidade.

    Ordem (mais específico primeiro): email → url → ip → hash → cnpj → cpf
    → telefone → domínio → pessoa (tem espaço) → username.
    CPF/CNPJ só são aceitos com dígitos verificadores válidos — um número de
    11 dígitos com DV inválido cai para "telefone", nunca vira CPF por engano.
    """
    v = valor.strip()
    if RE_EMAIL.match(v):
        return "email"
    if RE_URL.match(v):
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if RE_HASH.match(v):
        return "hash"
    if RE_CNPJ.match(v) and validar_cnpj(v):
        return "cnpj"
    if RE_CPF.match(v) and validar_cpf(v):
        return "cpf"
    if RE_TELEFONE.match(v):
        return "telefone"
    if RE_DOMINIO.match(v):
        return "dominio"
    if " " in v:
        return "pessoa"
    return "username"


# ---------------------------------------------------------------------------
# 2. CADEIA DE CUSTÓDIA — ledger encadeado por SHA-256 (lacuna forense)
# ---------------------------------------------------------------------------

class Custodia:
    """Guarda cada evidência bruta e mantém um ledger hash-encadeado.

    Cada registro contém o SHA-256 dos bytes brutos recebidos E o hash do
    registro anterior; o hash do registro é o SHA-256 do JSON canônico.
    Alterar qualquer byte de qualquer evidência quebra toda a corrente dali
    em diante — verificável offline com `garimpo.py verificar`.
    """

    def __init__(self, caso_dir: str):
        self.caso_dir = caso_dir
        self.evid_dir = os.path.join(caso_dir, "evidencias")
        os.makedirs(self.evid_dir, exist_ok=True)
        self.ledger_path = os.path.join(caso_dir, "ledger.jsonl")
        self._ultimo_hash = "0" * 64
        if os.path.exists(self.ledger_path):
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for linha in f:
                    if linha.strip():
                        self._ultimo_hash = json.loads(linha)["hash_registro"]
        self.seq = sum(1 for _ in open(self.ledger_path, encoding="utf-8")) \
            if os.path.exists(self.ledger_path) else 0

    def registrar(self, fonte: str, url: str, corpo: bytes, status: int) -> dict:
        self.seq += 1
        sha = hashlib.sha256(corpo).hexdigest()
        arq = f"{self.seq:04d}_{fonte}_{sha[:12]}.bin"
        with open(os.path.join(self.evid_dir, arq), "wb") as f:
            f.write(corpo)
        reg = {
            "seq": self.seq,
            "quando_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "fonte": fonte,
            "url": url,
            "status_http": status,
            "bytes": len(corpo),
            "sha256_evidencia": sha,
            "arquivo": arq,
            "hash_anterior": self._ultimo_hash,
        }
        canonico = json.dumps(reg, sort_keys=True, ensure_ascii=False).encode()
        reg["hash_registro"] = hashlib.sha256(canonico).hexdigest()
        self._ultimo_hash = reg["hash_registro"]
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(reg, ensure_ascii=False) + "\n")
        return reg

    @staticmethod
    def verificar(caso_dir: str) -> tuple[bool, list[str]]:
        """Reverifica hashes das evidências e o encadeamento do ledger."""
        problemas: list[str] = []
        ledger = os.path.join(caso_dir, "ledger.jsonl")
        if not os.path.exists(ledger):
            return False, ["ledger.jsonl não encontrado"]
        anterior = "0" * 64
        with open(ledger, encoding="utf-8") as f:
            for n, linha in enumerate(f, 1):
                reg = json.loads(linha)
                hash_decl = reg.pop("hash_registro")
                recalc = hashlib.sha256(
                    json.dumps(reg, sort_keys=True, ensure_ascii=False).encode()
                ).hexdigest()
                if recalc != hash_decl:
                    problemas.append(f"linha {n}: hash do registro não confere")
                if reg["hash_anterior"] != anterior:
                    problemas.append(f"linha {n}: corrente quebrada (hash_anterior)")
                anterior = hash_decl
                arq = os.path.join(caso_dir, "evidencias", reg["arquivo"])
                if not os.path.exists(arq):
                    problemas.append(f"linha {n}: evidência ausente ({reg['arquivo']})")
                    continue
                with open(arq, "rb") as ef:
                    if hashlib.sha256(ef.read()).hexdigest() != reg["sha256_evidencia"]:
                        problemas.append(f"linha {n}: evidência adulterada ({reg['arquivo']})")
        return (not problemas), problemas


# ---------------------------------------------------------------------------
# 3. CLIENTE HTTP com orçamento (stdlib urllib)
# ---------------------------------------------------------------------------

class Orcamento:
    """Caps não negociáveis — herdados do melhor acerto do OpenOSINT."""

    def __init__(self, max_requisicoes: int, max_entidades: int, profundidade: int):
        self.max_requisicoes = max_requisicoes
        self.max_entidades = max_entidades
        self.profundidade = profundidade
        self.requisicoes = 0

    def pode_requisitar(self) -> bool:
        return self.requisicoes < self.max_requisicoes


class Cliente:
    def __init__(self, custodia: Custodia, orcamento: Orcamento, silencioso: bool = False):
        self.custodia = custodia
        self.orc = orcamento
        self.silencioso = silencioso

    def get_json(self, fonte: str, url: str):
        """GET → bytes brutos → custódia → JSON (ou None).  Nunca levanta."""
        if not self.orc.pode_requisitar():
            return None
        self.orc.requisicoes += 1
        if not self.silencioso:
            print(f"  → [{fonte}] {url}")
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                corpo = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            corpo = e.read() if e.fp else b""
            status = e.code
        except Exception as e:  # DNS, timeout, TLS…
            self.custodia.registrar(fonte, url, f"ERRO: {e}".encode(), 0)
            return None
        self.custodia.registrar(fonte, url, corpo, status)
        if status != 200 or not corpo:
            return None
        try:
            return json.loads(corpo.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None


# ---------------------------------------------------------------------------
# 4. FONTES PASSIVAS KEYLESS (cada uma devolve entidades + fatos estruturados)
#    Lacuna corrigida: extração de JSON estruturado, não regex em texto livre.
# ---------------------------------------------------------------------------

def _doh(c: Cliente, nome: str, tipo: str):
    """DNS over HTTPS (Google) — a consulta vai ao resolvedor, não ao alvo."""
    q = urllib.parse.urlencode({"name": nome, "type": tipo})
    return c.get_json("doh", f"https://dns.google/resolve?{q}")


def fonte_dominio(c: Cliente, dominio: str):
    fatos, novas = [], []
    # RDAP — registro.br para .br (lacuna Brasil), rdap.org para o resto
    if dominio.endswith(".br"):
        rdap = c.get_json("rdap_registro_br",
                          f"https://rdap.registro.br/domain/{dominio}")
    else:
        rdap = c.get_json("rdap", f"https://rdap.org/domain/{dominio}")
    if rdap:
        for ev in rdap.get("events", []):
            fatos.append(("rdap", f"evento {ev.get('eventAction')}: {ev.get('eventDate')}"))
        for ns in rdap.get("nameservers", []):
            n = (ns.get("ldhName") or "").lower().rstrip(".")
            if n:
                fatos.append(("rdap", f"nameserver: {n}"))
                novas.append(("dominio", n, "nameserver_de", 0.7))
        for ent in rdap.get("entities", []):
            for papel in ent.get("roles", []):
                vc = ent.get("vcardArray")
                nome_ent = ""
                if isinstance(vc, list) and len(vc) > 1:
                    for item in vc[1]:
                        if item and item[0] == "fn":
                            nome_ent = item[3]
                if nome_ent:
                    fatos.append(("rdap", f"{papel}: {nome_ent}"))
    # DNS (A, MX, TXT) via DoH
    for t in ("A", "MX", "TXT"):
        r = _doh(c, dominio, t)
        for ans in (r or {}).get("Answer", []):
            dado = str(ans.get("data", "")).strip('"')
            fatos.append(("dns", f"{t}: {dado}"))
            if t == "A":
                novas.append(("ip", dado, "resolve_para", 0.9))
            elif t == "MX":
                mx = dado.split()[-1].rstrip(".").lower()
                if RE_DOMINIO.match(mx):
                    novas.append(("dominio", mx, "servidor_de_email", 0.7))
            elif t == "TXT" and "v=spf1" in dado:
                fatos.append(("dns", f"SPF presente: {dado[:120]}"))
    dmarc = _doh(c, f"_dmarc.{dominio}", "TXT")
    for ans in (dmarc or {}).get("Answer", []):
        fatos.append(("dns", f"DMARC: {str(ans.get('data', '')).strip(chr(34))[:120]}"))
    # crt.sh — subdomínios por transparência de certificados (keyless)
    ct = c.get_json("crtsh",
                    f"https://crt.sh/?q=%25.{urllib.parse.quote(dominio)}&output=json")
    if isinstance(ct, list):
        vistos = set()
        for cert in ct[:200]:
            for nome in str(cert.get("name_value", "")).splitlines():
                nome = nome.strip().lower().lstrip("*.")
                if nome.endswith(dominio) and nome != dominio and nome not in vistos:
                    vistos.add(nome)
        for sub in sorted(vistos)[:25]:
            fatos.append(("crtsh", f"subdomínio (CT): {sub}"))
            novas.append(("dominio", sub, "subdominio_de", 0.8))
        if vistos:
            fatos.append(("crtsh", f"total de subdomínios únicos em CT: {len(vistos)}"))
    # Wayback CDX — memória histórica (keyless, lacuna do OpenOSINT)
    wb = c.get_json("wayback",
                    "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode({
                        "url": dominio, "output": "json", "limit": "5",
                        "fl": "timestamp,original", "collapse": "digest"}))
    if isinstance(wb, list) and len(wb) > 1:
        primeiro = wb[1][0]
        fatos.append(("wayback", f"primeiro snapshot no Internet Archive: {primeiro[:4]}-{primeiro[4:6]}-{primeiro[6:8]}"))
    return fatos, novas


def fonte_ip(c: Cliente, ip: str):
    fatos, novas = [], []
    rdap = c.get_json("rdap", f"https://rdap.org/ip/{ip}")
    if rdap:
        if rdap.get("name"):
            fatos.append(("rdap", f"bloco: {rdap['name']}"))
        if rdap.get("country"):
            fatos.append(("rdap", f"país do registro: {rdap['country']}"))
        for ent in rdap.get("entities", [])[:3]:
            for papel in ent.get("roles", []):
                fatos.append(("rdap", f"entidade com papel: {papel}"))
    # InternetDB (Shodan keyless) — portas/CVEs sem chave, sem novo scan
    idb = c.get_json("internetdb", f"https://internetdb.shodan.io/{ip}")
    if idb and not idb.get("detail"):
        if idb.get("ports"):
            fatos.append(("internetdb", f"portas vistas pela Shodan: {idb['ports']}"))
        for cve in (idb.get("vulns") or [])[:10]:
            fatos.append(("internetdb", f"vulnerabilidade indexada: {cve}"))
        for h in (idb.get("hostnames") or [])[:5]:
            fatos.append(("internetdb", f"hostname: {h}"))
            if RE_DOMINIO.match(h):
                novas.append(("dominio", h, "hospedado_em", 0.7))
    # PTR via DoH
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
        ptr = _doh(c, rev, "PTR")
        for ans in (ptr or {}).get("Answer", []):
            h = str(ans.get("data", "")).rstrip(".").lower()
            fatos.append(("dns", f"PTR: {h}"))
    except ValueError:
        pass
    return fatos, novas


def fonte_email(c: Cliente, email: str):
    fatos, novas = [], []
    dominio = email.split("@", 1)[1].lower()
    novas.append(("dominio", dominio, "dominio_do_email", 1.0))
    # Gravatar (consulta a terceiro; o dono do e-mail não é notificado)
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    grav = c.get_json("gravatar", f"https://www.gravatar.com/{md5}.json")
    if grav and grav.get("entry"):
        e0 = grav["entry"][0]
        if e0.get("displayName"):
            fatos.append(("gravatar", f"nome exibido: {e0['displayName']}"))
        if e0.get("preferredUsername"):
            u = e0["preferredUsername"]
            fatos.append(("gravatar", f"username preferido: {u}"))
            novas.append(("username", u, "mesmo_titular", 0.8))
        for conta in e0.get("accounts", [])[:8]:
            fatos.append(("gravatar", f"conta vinculada: {conta.get('shortname')} → {conta.get('url')}"))
    local = email.split("@", 1)[0]
    if RE_USERNAME.match(local):
        novas.append(("username", local, "parte_local_do_email", 0.5))
    return fatos, novas


def fonte_username(c: Cliente, user: str):
    fatos, novas = [], []
    gh = c.get_json("github", f"https://api.github.com/users/{urllib.parse.quote(user)}")
    if gh and gh.get("login"):
        fatos.append(("github", f"perfil: {gh.get('html_url')}"))
        if gh.get("name"):
            fatos.append(("github", f"nome: {gh['name']}"))
            novas.append(("pessoa", gh["name"], "nome_no_github", 0.7))
        if gh.get("email"):
            fatos.append(("github", f"e-mail público: {gh['email']}"))
            novas.append(("email", gh["email"], "email_publico_github", 0.9))
        if gh.get("blog"):
            fatos.append(("github", f"site: {gh['blog']}"))
        if gh.get("company"):
            fatos.append(("github", f"empresa declarada: {gh['company']}"))
        if gh.get("location"):
            fatos.append(("github", f"localização declarada: {gh['location']}"))
        fatos.append(("github", f"repos públicos: {gh.get('public_repos')} · "
                                f"seguidores: {gh.get('followers')} · criado em: {str(gh.get('created_at'))[:10]}"))
    return fatos, novas


def fonte_cnpj(c: Cliente, cnpj: str):
    """Lacuna Brasil corrigida: Receita via BrasilAPI (keyless)."""
    fatos, novas = [], []
    d = _so_digitos(cnpj)
    r = c.get_json("brasilapi_cnpj", f"https://brasilapi.com.br/api/cnpj/v1/{d}")
    if r and r.get("razao_social"):
        fatos.append(("brasilapi", f"razão social: {r['razao_social']}"))
        novas.append(("pessoa", r["razao_social"], "razao_social", 0.9))
        if r.get("nome_fantasia"):
            fatos.append(("brasilapi", f"nome fantasia: {r['nome_fantasia']}"))
        fatos.append(("brasilapi", f"situação: {r.get('descricao_situacao_cadastral')} · "
                                   f"abertura: {r.get('data_inicio_atividade')}"))
        fatos.append(("brasilapi", f"município/UF: {r.get('municipio')}/{r.get('uf')}"))
        if r.get("cnae_fiscal_descricao"):
            fatos.append(("brasilapi", f"CNAE principal: {r['cnae_fiscal_descricao']}"))
        for socio in (r.get("qsa") or [])[:10]:
            nome = socio.get("nome_socio")
            if nome:
                fatos.append(("brasilapi", f"sócio ({socio.get('qualificacao_socio', '?')}): {nome}"))
                novas.append(("pessoa", nome, "socio_de", 0.9))
    return fatos, novas


def fonte_cpf(c: Cliente, cpf: str):
    """CPF: SOMENTE validação matemática offline — nenhuma consulta é feita.

    Decisão ética deliberada: pivotar CPF contra bases vazadas está fora do
    escopo de uma ferramenta passiva e legal."""
    _ = c
    d = _so_digitos(cpf)
    uf_por_digito = {
        "0": "RS", "1": "DF/GO/MT/MS/TO", "2": "AC/AM/AP/PA/RO/RR",
        "3": "CE/MA/PI", "4": "AL/PB/PE/RN", "5": "BA/SE",
        "6": "MG", "7": "ES/RJ", "8": "SP", "9": "PR/SC"}
    fatos = [("local", "dígitos verificadores: VÁLIDOS (cálculo offline)"),
             ("local", f"região fiscal provável (9º dígito): {uf_por_digito[d[8]]}"),
             ("local", "nenhuma consulta externa é feita para CPF — por decisão de projeto")]
    return fatos, []


def fonte_url(c: Cliente, url: str):
    fatos, novas = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    if host and RE_DOMINIO.match(host):
        novas.append(("dominio", host, "host_da_url", 1.0))
    wb = c.get_json("wayback", "https://archive.org/wayback/available?" +
                    urllib.parse.urlencode({"url": url}))
    snap = ((wb or {}).get("archived_snapshots") or {}).get("closest")
    if snap:
        fatos.append(("wayback", f"snapshot mais próximo: {snap.get('timestamp')} → {snap.get('url')}"))
    return fatos, novas


def fonte_hash(c: Cliente, h: str):
    _ = c
    tipo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(h)]
    return [("local", f"formato identificado: {tipo} (análise offline; "
                      "pivô em sandboxes exige chave de API — fora do modo keyless)")], []


def fonte_telefone(c: Cliente, tel: str):
    _ = c
    d = _so_digitos(tel)
    fatos = []
    if d.startswith("55") and len(d) in (12, 13):
        ddd, resto = d[2:4], d[4:]
        fatos.append(("local", f"Brasil (+55) · DDD {ddd}"))
        fatos.append(("local", "celular (9 dígitos)" if len(resto) == 9 and resto[0] == "9"
                      else "fixo ou formato antigo"))
    elif len(d) in (10, 11) and d[0] != "0":
        fatos.append(("local", f"possível número BR sem código do país · DDD {d[:2]}"))
    else:
        fatos.append(("local", "código de país não identificado como +55; análise offline apenas"))
    fatos.append(("local", "nenhuma consulta externa — fontes keyless de telefone não são confiáveis"))
    return fatos, []


FONTES = {
    "dominio": fonte_dominio, "ip": fonte_ip, "email": fonte_email,
    "username": fonte_username, "cnpj": fonte_cnpj, "cpf": fonte_cpf,
    "url": fonte_url, "hash": fonte_hash, "telefone": fonte_telefone,
    "pessoa": lambda c, v: ([("local", "pessoa registrada no grafo; pivô por nome "
                              "exige buscador (fora do modo keyless)")], []),
}

TABELA_RUIDO = [
    ("rdap / rdap_registro_br", "passiva", "1 requisição ao servidor RDAP do registro — nunca ao alvo"),
    ("doh (dns.google)", "passiva*", "consulta DNS via resolvedor Google; nameservers do alvo veem o resolvedor, não você"),
    ("crtsh", "passiva", "lê o índice público de transparência de certificados"),
    ("internetdb", "passiva", "lê o índice existente da Shodan; NÃO dispara novo scan"),
    ("wayback", "passiva", "lê o índice do Internet Archive"),
    ("github", "passiva", "1–2 requisições à API pública (limite 60/h sem chave)"),
    ("gravatar", "passiva", "1 requisição ao Gravatar com hash MD5 do e-mail"),
    ("brasilapi_cnpj", "passiva", "1 requisição à BrasilAPI (dados públicos da Receita)"),
    ("local (cpf/hash/telefone)", "offline", "cálculo local; nenhum byte sai da máquina"),
]


# ---------------------------------------------------------------------------
# 5. GRAFO + PIVÔ BFS com orçamento
# ---------------------------------------------------------------------------

def investigar(seed: str, orc: Orcamento, caso_dir: str, silencioso: bool = False) -> dict:
    custodia = Custodia(caso_dir)
    cliente = Cliente(custodia, orc, silencioso)
    tipo_seed = detectar_tipo(seed)
    inicio = time.time()

    grafo = {"no_seed": seed, "nos": {}, "arestas": []}
    fila: deque[tuple[str, str, int]] = deque([(tipo_seed, seed.strip(), 0)])
    visitados: set[str] = set()

    while fila:
        tipo, valor, prof = fila.popleft()
        chave = f"{tipo}:{valor.lower()}"
        if chave in visitados or len(grafo["nos"]) >= orc.max_entidades:
            continue
        visitados.add(chave)
        if not silencioso:
            print(f"\n[{prof}] {tipo.upper()} → {valor}")
        fatos, novas = FONTES.get(tipo, FONTES["pessoa"])(cliente, valor)
        grafo["nos"][chave] = {"tipo": tipo, "valor": valor, "profundidade": prof,
                               "fatos": [{"fonte": f, "fato": t} for f, t in fatos]}
        if not silencioso:
            for f, t in fatos:
                print(f"    [{f}] {t}")
        if prof >= orc.profundidade:
            continue
        for ntipo, nvalor, relacao, conf in novas:
            nchave = f"{ntipo}:{nvalor.lower()}"
            grafo["arestas"].append({"de": chave, "para": nchave,
                                     "relacao": relacao, "confianca": conf})
            if conf >= 0.6 and nchave not in visitados:
                fila.append((ntipo, nvalor, prof + 1))

    caso = {
        "ferramenta": f"GARIMPO {VERSAO} (DEIVOSINT)",
        "seed": seed, "tipo_seed": tipo_seed,
        "iniciado_utc": _dt.datetime.fromtimestamp(inicio, _dt.timezone.utc).isoformat(),
        "duracao_s": round(time.time() - inicio, 2),
        "orcamento": {"profundidade": orc.profundidade,
                      "max_entidades": orc.max_entidades,
                      "max_requisicoes": orc.max_requisicoes,
                      "requisicoes_feitas": orc.requisicoes},
        "grafo": grafo,
    }
    with open(os.path.join(caso_dir, "caso.json"), "w", encoding="utf-8") as f:
        json.dump(caso, f, ensure_ascii=False, indent=2)
    return caso


# ---------------------------------------------------------------------------
# 6. DOSSIÊ HTML pt-BR (standalone, com grafo SVG) — lacuna de relatório
# ---------------------------------------------------------------------------

CORES_TIPO = {"dominio": "#3b82f6", "ip": "#f59e0b", "email": "#10b981",
              "username": "#8b5cf6", "cnpj": "#ef4444", "cpf": "#ef4444",
              "pessoa": "#ec4899", "url": "#06b6d4", "hash": "#64748b",
              "telefone": "#eab308"}


def _svg_grafo(grafo: dict) -> str:
    nos = list(grafo["nos"].items())
    if not nos:
        return "<p>Grafo vazio.</p>"
    W, H, cx, cy = 900, 520, 450, 260
    pos = {}
    seed_chave = next((k for k, n in nos if n["profundidade"] == 0), nos[0][0])
    pos[seed_chave] = (cx, cy)
    resto = [k for k, _ in nos if k != seed_chave]
    por_prof: dict[int, list] = {}
    for k in resto:
        por_prof.setdefault(grafo["nos"][k]["profundidade"], []).append(k)
    for prof, grupo in por_prof.items():
        raio = 110 * prof + 70
        for i, k in enumerate(grupo):
            ang = 2 * math.pi * i / max(len(grupo), 1) - math.pi / 2
            pos[k] = (cx + raio * math.cos(ang), cy + raio * 0.72 * math.sin(ang))
    linhas = []
    for a in grafo["arestas"]:
        if a["de"] in pos and a["para"] in pos:
            x1, y1 = pos[a["de"]]; x2, y2 = pos[a["para"]]
            linhas.append(
                f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                f'stroke="#94a3b8" stroke-width="1.4" opacity="{0.35 + 0.6 * a["confianca"]:.2f}"/>'
                f'<text x="{(x1 + x2) / 2:.0f}" y="{(y1 + y2) / 2 - 4:.0f}" font-size="9" '
                f'fill="#64748b" text-anchor="middle">{_html.escape(a["relacao"])}</text>')
    circulos = []
    for k, (x, y) in pos.items():
        n = grafo["nos"][k]
        cor = CORES_TIPO.get(n["tipo"], "#64748b")
        r = 26 if n["profundidade"] == 0 else 16
        rotulo = n["valor"] if len(n["valor"]) <= 28 else n["valor"][:25] + "…"
        circulos.append(
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r}" fill="{cor}" opacity="0.92" '
            f'stroke="#0f172a" stroke-width="2"/>'
            f'<text x="{x:.0f}" y="{y + r + 13:.0f}" font-size="11" font-weight="600" '
            f'fill="#e2e8f0" text-anchor="middle">{_html.escape(rotulo)}</text>'
            f'<text x="{x:.0f}" y="{y + 4:.0f}" font-size="9" fill="#fff" '
            f'text-anchor="middle">{n["tipo"][:3].upper()}</text>')
    return (f'<svg viewBox="0 0 {W} {H}" style="width:100%;background:#0f172a;'
            f'border-radius:12px">{"".join(linhas)}{"".join(circulos)}</svg>')


def gerar_dossie(caso: dict, caso_dir: str) -> str:
    g = caso["grafo"]
    secoes = []
    for chave, n in g["nos"].items():
        fatos_html = "".join(
            f'<tr><td class="fonte">{_html.escape(f["fonte"])}</td>'
            f'<td>{_html.escape(f["fato"])}</td></tr>' for f in n["fatos"]) \
            or '<tr><td colspan="2">Nenhum fato coletado.</td></tr>'
        cor = CORES_TIPO.get(n["tipo"], "#64748b")
        secoes.append(f"""
<details {'open' if n['profundidade'] == 0 else ''}>
<summary><span class="pill" style="background:{cor}">{n['tipo']}</span>
<b>{_html.escape(n['valor'])}</b> <span class="prof">profundidade {n['profundidade']}</span></summary>
<table>{fatos_html}</table></details>""")
    doc = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dossiê GARIMPO — {_html.escape(caso['seed'])}</title>
<style>
:root{{color-scheme:dark}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0b1220;color:#e2e8f0;
max-width:980px;margin:0 auto;padding:24px 16px}}
h1{{font-size:1.5rem}}h1 small{{color:#60a5fa;font-weight:400}}
.meta{{display:flex;gap:16px;flex-wrap:wrap;font-size:.85rem;color:#94a3b8;
background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:12px 16px}}
.pill{{color:#fff;border-radius:999px;padding:2px 10px;font-size:.72rem;
text-transform:uppercase;margin-right:8px}}
.prof{{color:#64748b;font-size:.78rem;margin-left:8px}}
details{{background:#111a2e;border:1px solid #1e293b;border-radius:12px;
margin:10px 0;padding:4px 14px}}
summary{{cursor:pointer;padding:10px 0;font-size:.95rem}}
table{{width:100%;border-collapse:collapse;margin:6px 0 14px;font-size:.86rem}}
td{{padding:6px 8px;border-top:1px solid #1e293b;vertical-align:top}}
td.fonte{{color:#60a5fa;white-space:nowrap;width:140px;font-family:ui-monospace,monospace}}
.aviso{{border-left:3px solid #f59e0b;background:#1c1917;padding:10px 14px;
border-radius:8px;font-size:.84rem;color:#fbbf24;margin:16px 0}}
footer{{color:#475569;font-size:.78rem;margin-top:28px;border-top:1px solid #1e293b;
padding-top:12px}}
</style></head><body>
<h1>⛏️ GARIMPO <small>· dossiê de investigação passiva · DEIVOSINT</small></h1>
<div class="meta">
<span><b>Seed:</b> {_html.escape(caso['seed'])} ({caso['tipo_seed']})</span>
<span><b>Início (UTC):</b> {caso['iniciado_utc'][:19]}</span>
<span><b>Duração:</b> {caso['duracao_s']}s</span>
<span><b>Entidades:</b> {len(g['nos'])}</span>
<span><b>Vínculos:</b> {len(g['arestas'])}</span>
<span><b>Requisições:</b> {caso['orcamento']['requisicoes_feitas']}/{caso['orcamento']['max_requisicoes']}</span>
</div>
<h2>Grafo de vínculos</h2>
{_svg_grafo(g)}
<h2>Entidades e fatos (com fonte por linha)</h2>
{''.join(secoes)}
<div class="aviso"><b>Cadeia de custódia:</b> cada resposta bruta está salva em
<code>evidencias/</code> e registrada em <code>ledger.jsonl</code> com SHA-256
encadeado. Verifique com <code>python3 garimpo.py verificar {os.path.basename(caso_dir)}</code>.
Fatos vêm de execuções reais das fontes listadas; são pistas a confirmar, não prova.
Uso legal e autorizado apenas.</div>
<footer>GARIMPO {VERSAO} · família DEIVOSINT · Deivison Lourenço (@Ridd1kulusC0d3r)
· 100% Python stdlib · passivo por padrão</footer>
</body></html>"""
    caminho = os.path.join(caso_dir, "dossie.html")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(doc)
    return caminho


# ---------------------------------------------------------------------------
# 7. DEMO offline (caso de demonstração determinístico)
# ---------------------------------------------------------------------------

def rodar_demo(caso_dir: str) -> str:
    """Gera um caso sintético SEM rede — para conhecer a ferramenta em 10s."""
    custodia = Custodia(caso_dir)
    for fonte, url, corpo in [
        ("rdap", "demo://rdap/exemplo.com.br", b'{"demo": true}'),
        ("crtsh", "demo://crtsh/exemplo.com.br", b'[{"name_value": "app.exemplo.com.br"}]'),
    ]:
        custodia.registrar(fonte, url, corpo, 200)
    grafo = {
        "no_seed": "exemplo.com.br",
        "nos": {
            "dominio:exemplo.com.br": {"tipo": "dominio", "valor": "exemplo.com.br",
                "profundidade": 0, "fatos": [
                    {"fonte": "rdap_registro_br", "fato": "evento registration: 2019-03-04"},
                    {"fonte": "dns", "fato": "A: 203.0.113.10"},
                    {"fonte": "crtsh", "fato": "subdomínio (CT): app.exemplo.com.br"}]},
            "ip:203.0.113.10": {"tipo": "ip", "valor": "203.0.113.10",
                "profundidade": 1, "fatos": [
                    {"fonte": "internetdb", "fato": "portas vistas pela Shodan: [443]"},
                    {"fonte": "rdap", "fato": "país do registro: BR"}]},
            "dominio:app.exemplo.com.br": {"tipo": "dominio", "valor": "app.exemplo.com.br",
                "profundidade": 1, "fatos": [
                    {"fonte": "dns", "fato": "A: 203.0.113.10"}]},
        },
        "arestas": [
            {"de": "dominio:exemplo.com.br", "para": "ip:203.0.113.10",
             "relacao": "resolve_para", "confianca": 0.9},
            {"de": "dominio:exemplo.com.br", "para": "dominio:app.exemplo.com.br",
             "relacao": "subdominio_de", "confianca": 0.8},
        ],
    }
    caso = {"ferramenta": f"GARIMPO {VERSAO} (DEMO offline)", "seed": "exemplo.com.br",
            "tipo_seed": "dominio",
            "iniciado_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "duracao_s": 0.0,
            "orcamento": {"profundidade": 1, "max_entidades": 10,
                          "max_requisicoes": 0, "requisicoes_feitas": 0},
            "grafo": grafo}
    with open(os.path.join(caso_dir, "caso.json"), "w", encoding="utf-8") as f:
        json.dump(caso, f, ensure_ascii=False, indent=2)
    return gerar_dossie(caso, caso_dir)


# ---------------------------------------------------------------------------
# 8. CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="garimpo",
        description="GARIMPO — pivô OSINT passivo, keyless, stdlib (DEIVOSINT)")
    sub = p.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("investigar", help="investiga um alvo e gera dossiê HTML")
    inv.add_argument("alvo")
    inv.add_argument("--profundidade", type=int, default=1,
                     help="saltos de pivô a partir do seed (padrão: 1)")
    inv.add_argument("--max-entidades", type=int, default=12)
    inv.add_argument("--max-requisicoes", type=int, default=30,
                     help="teto duro de requisições HTTP (padrão: 30)")
    inv.add_argument("--caso", default=None,
                     help="diretório do caso (padrão: casos/AAAA-MM-DD_HHMMSS_alvo)")
    inv.add_argument("--silencioso", action="store_true")

    det = sub.add_parser("detectar", help="mostra o tipo detectado de um valor")
    det.add_argument("valor")

    sub.add_parser("fontes", help="tabela de ruído: o que cada fonte envia, e para onde")

    ver = sub.add_parser("verificar", help="verifica a cadeia de custódia de um caso")
    ver.add_argument("caso_dir")

    demo = sub.add_parser("demo", help="caso de demonstração offline (sem rede)")
    demo.add_argument("--caso", default="casos/demo")

    args = p.parse_args(argv)

    if args.cmd == "detectar":
        print(detectar_tipo(args.valor))
        return 0

    if args.cmd == "fontes":
        print(f"{'FONTE':28} {'NÍVEL':10} O QUE É ENVIADO, E PARA ONDE")
        print("-" * 100)
        for f, nivel, desc in TABELA_RUIDO:
            print(f"{f:28} {nivel:10} {desc}")
        print("\n* Passiva não é privada: cada serviço consultado vê o que você pesquisou.")
        print("  Nenhuma fonte do GARIMPO toca a infraestrutura do alvo.")
        return 0

    if args.cmd == "verificar":
        ok, problemas = Custodia.verificar(args.caso_dir)
        if ok:
            print("✔ Cadeia de custódia ÍNTEGRA: hashes e encadeamento conferem.")
            return 0
        print("✘ Cadeia de custódia COMPROMETIDA:")
        for pr in problemas:
            print(f"  - {pr}")
        return 1

    if args.cmd == "demo":
        os.makedirs(args.caso, exist_ok=True)
        caminho = rodar_demo(args.caso)
        print(f"✔ Demo gerada. Abra no navegador: {caminho}")
        return 0

    # investigar
    tipo = detectar_tipo(args.alvo)
    carimbo = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    alvo_slug = re.sub(r"[^A-Za-z0-9.-]", "_", args.alvo)[:40]
    caso_dir = args.caso or os.path.join("casos", f"{carimbo}_{alvo_slug}")
    os.makedirs(caso_dir, exist_ok=True)
    print(f"⛏️  GARIMPO {VERSAO} · seed: {args.alvo} (detectado: {tipo})")
    print(f"    caso: {caso_dir} · modo: PASSIVO (sempre)")
    orc = Orcamento(args.max_requisicoes, args.max_entidades, args.profundidade)
    caso = investigar(args.alvo, orc, caso_dir, args.silencioso)
    caminho = gerar_dossie(caso, caso_dir)
    print(f"\n✔ {len(caso['grafo']['nos'])} entidades · {len(caso['grafo']['arestas'])} vínculos · "
          f"{caso['orcamento']['requisicoes_feitas']} requisições · {caso['duracao_s']}s")
    print(f"✔ Dossiê: {caminho}")
    print(f"✔ Custódia: {os.path.join(caso_dir, 'ledger.jsonl')} "
          f"(verifique com: python3 garimpo.py verificar {caso_dir})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
