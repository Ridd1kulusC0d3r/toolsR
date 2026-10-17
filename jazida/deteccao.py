# -*- coding: utf-8 -*-
"""Detecção de tipo de entidade e validadores brasileiros (offline)."""

from __future__ import annotations

import ipaddress
import re

RE_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}$", re.IGNORECASE)
RE_URL = re.compile(r"^https?://", re.IGNORECASE)
RE_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
# O último rótulo (TLD) precisa começar com letra: "111.111.111-11" não é domínio.
RE_DOMINIO = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z][a-zA-Z0-9\-]{1,62}$"
)
RE_CPF = re.compile(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$")
RE_CNPJ = re.compile(r"^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$")
RE_TELEFONE = re.compile(r"^\+?\d{7,15}$")
RE_TELEFONE_FMT = re.compile(r"^\+?[\d\s().\-]{8,24}$")
RE_USERNAME = re.compile(r"^[A-Za-z0-9._\-]{2,39}$")
RE_ASN = re.compile(r"^AS\d{1,10}$", re.IGNORECASE)
RE_CEP = re.compile(r"^\d{5}-\d{3}$")  # só com hífen: 8 dígitos crus são ambíguos

TIPOS = ("email", "url", "ip", "hash", "asn", "cep", "cnpj", "cpf",
         "documento_invalido", "telefone", "dominio", "pessoa", "organizacao", "username")


def so_digitos(v: str) -> str:
    return re.sub(r"\D", "", v)


def validar_cpf(cpf: str) -> bool:
    d = so_digitos(cpf)
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
    d = so_digitos(cnpj)
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


def formatar_cnpj(cnpj: str) -> str:
    d = so_digitos(cnpj)
    return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}" if len(d) == 14 else cnpj


def normalizar(tipo: str, valor: str) -> str:
    """Forma canônica para deduplicar nós (mesma entidade, grafias diferentes)."""
    v = valor.strip()
    if tipo in ("dominio", "email", "username", "hash"):
        return v.lower().rstrip(".")
    if tipo == "cnpj":
        return formatar_cnpj(v)
    if tipo == "asn":
        return "AS" + so_digitos(v)
    if tipo == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v
    if tipo == "telefone":
        return "+" + so_digitos(v) if v.startswith("+") else so_digitos(v)
    return v


def detectar_tipo(valor: str) -> str:
    """Classifica um valor.

    Ordem: email → url → ip → hash → asn → cep → cnpj → cpf → documento_invalido
    → telefone → domínio → pessoa (tem espaço) → username.
    CPF/CNPJ só valem com DV correto; formatados com DV errado viram
    "documento_invalido" e nunca são consultados.
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
    if RE_ASN.match(v):
        return "asn"
    if RE_CEP.match(v):
        return "cep"
    eh_cnpj, eh_cpf = RE_CNPJ.match(v), RE_CPF.match(v)
    if eh_cnpj and validar_cnpj(v):
        return "cnpj"
    if eh_cpf and validar_cpf(v):
        return "cpf"
    if (eh_cnpj or eh_cpf) and not v.isdigit():
        return "documento_invalido"
    if RE_TELEFONE.match(v):
        return "telefone"
    if RE_TELEFONE_FMT.match(v) and 10 <= len(so_digitos(v)) <= 15:
        return "telefone"
    if RE_DOMINIO.match(v):
        return "dominio"
    if " " in v:
        return "pessoa"
    return "username"
