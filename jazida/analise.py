# -*- coding: utf-8 -*-
"""Camada de análise: derivados calculados a partir de um caso já coletado.

Nada aqui faz rede — só lê o grafo e os fatos. É o que o dossiê, o painel e o
modo ESPELHO consomem.

  linha_do_tempo(caso)   fatos datados em ordem cronológica
  reputacao(caso)        sinais de ameaça (CTI) agregados por nó
  socios_cruzados(caso)  sócios que aparecem em mais de um CNPJ do caso
  exposicao(caso)        auto-auditoria OPSEC (ESPELHO): classes e pontuação
"""

from __future__ import annotations

import re

from .fontes.ameacas import ALERTA

# Anos restritos a 19xx/20xx para não casar com pedaços de CNPJ/CPF/telefone.
# (?<!\d) e (?!\d) no lugar de \b: "2019-03-04T12:00" tem 'T' depois do dia,
# onde \b não existe (T é caractere de palavra).
RE_DATA = re.compile(r"(?<!\d)((?:19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?!\d)")
RE_ANO_MES = re.compile(r"(?<!\d)((?:19|20)\d{2})-(0[1-9]|1[0-2])(?!\d)")


def _nos(caso):
    return caso.get("grafo", {}).get("nos", {})


def _arestas(caso):
    return caso.get("grafo", {}).get("arestas", [])


# --------------------------------------------------------------- linha do tempo
def linha_do_tempo(caso) -> list[dict]:
    """Extrai fatos com data e os devolve em ordem (mais antigo primeiro).

    Pega a primeira data completa (AAAA-MM-DD) de cada fato; se não houver,
    tenta AAAA-MM. Fatos sem data ficam de fora."""
    linha = []
    for chave, no in _nos(caso).items():
        for f in no.get("fatos", []):
            texto = f.get("fato", "")
            m = RE_DATA.search(texto)
            if m:
                data = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
            else:
                m2 = RE_ANO_MES.search(texto)
                if not m2:
                    continue
                data = f"{m2.group(1)}-{m2.group(2)}-01"
            linha.append({"data": data, "chave": chave, "tipo": no["tipo"],
                          "valor": no["valor"], "fonte": f.get("fonte", ""), "fato": texto})
    linha.sort(key=lambda x: x["data"])
    return linha


# ------------------------------------------------------------------ reputação
def reputacao(caso) -> dict:
    """Agrega os sinais de ameaça (fatos marcados com ⚠) por nó."""
    flags = []
    por_no = {}
    for chave, no in _nos(caso).items():
        acertos = [f for f in no.get("fatos", []) if f.get("fato", "").startswith(ALERTA)]
        if acertos:
            por_no[chave] = {"tipo": no["tipo"], "valor": no["valor"],
                             "sinais": [{"fonte": f["fonte"], "fato": f["fato"].lstrip(ALERTA),
                                         "evidencias": f.get("evidencias", [])} for f in acertos]}
            for f in acertos:
                flags.append({"chave": chave, "fonte": f["fonte"], "fato": f["fato"].lstrip(ALERTA)})
    return {"total": len(flags), "nos": por_no}


# --------------------------------------------------------------- QSA cruzado
def socios_cruzados(caso) -> list[dict]:
    """Sócios (pessoas) ligados por 'socio_de' a mais de um CNPJ no caso.

    Correlação de dado corporativo público já coletado — não faz consulta
    nova nem busca reversa por pessoa."""
    nos = _nos(caso)
    por_socio: dict[str, list[str]] = {}
    for a in _arestas(caso):
        if a.get("relacao") == "socio_de":
            por_socio.setdefault(a["para"], []).append(a["de"])
    saida = []
    for socio, cnpjs in por_socio.items():
        unicos = sorted(set(cnpjs))
        if len(unicos) > 1 and socio in nos:
            saida.append({"socio": nos[socio]["valor"], "chave": socio,
                          "empresas": [nos[c]["valor"] if c in nos else c for c in unicos]})
    saida.sort(key=lambda x: -len(x["empresas"]))
    return saida


# ----------------------------------------------------------------- exposição
_PESOS = {"reputacao": 40, "autenticacao": 20, "superficie": 20, "vazamento": 15, "historico": 5}


def exposicao(caso) -> dict:
    """ESPELHO: o que um observador passivo vê do alvo, em classes defensivas.

    Pontuação 0–100 = quanto da exposição possível foi observada (mais alto =
    mais exposto). É um retrato do que está à mostra, não um veredito de risco."""
    nos = _nos(caso)
    seed_chave = caso.get("grafo", {}).get("no_seed")
    seed = nos.get(seed_chave, {})
    seed_fatos = " | ".join(f.get("fato", "") for f in seed.get("fatos", []))

    rep = reputacao(caso)
    subdominios = sum(1 for a in _arestas(caso) if a.get("relacao") == "subdominio_de")
    portas = [f["fato"] for n in nos.values() for f in n.get("fatos", []) if "portas vistas" in f.get("fato", "")]
    cves = [f["fato"] for n in nos.values() for f in n.get("fatos", []) if "vulnerabilidade indexada" in f.get("fato", "")]
    emails_commit = [f for n in nos.values() for f in n.get("fatos", []) if "e-mail em commit" in f.get("fato", "")]
    emails_pub = [k for k, n in nos.items() if n["tipo"] == "email"]
    tem_spf = "SPF" in seed_fatos
    tem_dmarc = "DMARC" in seed_fatos
    tem_wayback = "Internet Archive" in seed_fatos

    classes = []

    def classe(nome, titulo, exposto, achados, recomendacao):
        classes.append({"id": nome, "titulo": titulo, "exposto": exposto,
                        "achados": achados, "recomendacao": recomendacao, "peso": _PESOS[nome]})

    classe("reputacao", "Reputação em listas de ameaça",
           rep["total"] > 0,
           [s["fato"] for v in rep["nos"].values() for s in v["sinais"]],
           "Se algo seu consta em lista de C2/phishing, trate como incidente: pode ser comprometimento ou abuso de marca."
           if rep["total"] else "Nada em listas de ameaça públicas no momento.")

    achados_auth = []
    if tem_spf:
        achados_auth.append("SPF publicado")
    if tem_dmarc:
        achados_auth.append("DMARC publicado")
    faltando = [x for x, ok in (("SPF", tem_spf), ("DMARC", tem_dmarc)) if not ok]
    classe("autenticacao", "Autenticação de e-mail (anti-spoofing)",
           bool(faltando),
           achados_auth or ["nenhum registro de autenticação de e-mail visível"],
           f"Falta {', '.join(faltando)} — facilita falsificação do seu domínio em phishing. Publique e endureça (p=reject)."
           if faltando else "SPF e DMARC presentes. Confira se o DMARC está em p=quarantine ou reject.")

    achados_sup = []
    if subdominios:
        achados_sup.append(f"{subdominios} subdomínio(s) expostos em Certificate Transparency")
    achados_sup += portas[:3] + cves[:5]
    classe("superficie", "Superfície exposta (subdomínios, portas, CVEs)",
           bool(subdominios or portas or cves),
           achados_sup or ["nenhuma superfície adicional observada passivamente"],
           "Revise se subdomínios de homologação/dev deviam estar públicos; trate CVEs indexadas como prioridade."
           if (subdominios or cves) else "Pouca superfície passiva à mostra.")

    achados_vaz = emails_commit[:5] + ([f"{len(emails_pub)} e-mail(s) no grafo"] if emails_pub else [])
    classe("vazamento", "Vazamento de identidade (e-mails, commits)",
           bool(emails_commit),
           [f["fato"] for f in emails_commit[:5]] or (["e-mails no grafo: " + str(len(emails_pub))] if emails_pub else ["nenhum e-mail exposto em commits"]),
           "E-mails corporativos em commits públicos alimentam spearphishing. Oriente o time a usar e-mail noreply do GitHub."
           if emails_commit else "Nenhum e-mail exposto em commit público observado.")

    classe("historico", "Pegada histórica (Internet Archive)",
           tem_wayback,
           ["presente no Internet Archive" if tem_wayback else "sem snapshot no Internet Archive"],
           "Conteúdo antigo pode revelar tecnologias, e-mails e caminhos já removidos. Vale revisar o que está arquivado.")

    pontos = sum(c["peso"] for c in classes if c["exposto"])
    return {"seed": caso.get("seed"), "pontuacao": pontos, "classes": classes,
            "reputacao_total": rep["total"],
            "resumo": _resumo_exposicao(pontos, rep["total"])}


def _resumo_exposicao(pontos, rep_total):
    if rep_total:
        return "ATENÇÃO: há sinal em lista de ameaça — verifique antes de tudo."
    if pontos >= 55:
        return "Exposição passiva alta: há bastante coisa visível para um observador externo."
    if pontos >= 30:
        return "Exposição passiva média: alguns pontos valem revisão."
    return "Exposição passiva baixa: pouco à mostra passivamente."
