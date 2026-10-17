# -*- coding: utf-8 -*-
"""Exportações: STIX 2.1 (bundle JSON), GraphML (Gephi/yEd/Cytoscape) e CSV
(entidades + vínculos, importável no Maltego e em planilhas).

Privacidade por projeto: CPF nunca é exportado.
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import uuid
import xml.etree.ElementTree as ET

from . import VERSAO

FORMATOS = ("stix", "graphml", "csv", "json")
NS_SCO = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # namespace OASIS p/ IDs determinísticos de SCO
NS_GARIMPO = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Ridd1kulusC0d3r/toolsR")
NAO_EXPORTA = {"cpf"}


def _id_sco(tipo: str, props: dict) -> str:
    canon = json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{tipo}--{uuid.uuid5(NS_SCO, canon)}"


def _id_sdo(tipo: str, chave: str) -> str:
    return f"{tipo}--{uuid.uuid5(NS_GARIMPO, tipo + '|' + chave)}"


def _stix_obj(no: dict, chave: str, criador: str, agora: str):
    t, v = no["tipo"], no["valor"]
    if t == "dominio":
        return {"type": "domain-name", "spec_version": "2.1", "id": _id_sco("domain-name", {"value": v}), "value": v}
    if t == "ip":
        st = "ipv6-addr" if ":" in v else "ipv4-addr"
        return {"type": st, "spec_version": "2.1", "id": _id_sco(st, {"value": v}), "value": v}
    if t == "email":
        return {"type": "email-addr", "spec_version": "2.1", "id": _id_sco("email-addr", {"value": v}), "value": v}
    if t == "url":
        return {"type": "url", "spec_version": "2.1", "id": _id_sco("url", {"value": v}), "value": v}
    if t == "asn":
        n = int(v[2:])
        return {"type": "autonomous-system", "spec_version": "2.1",
                "id": _id_sco("autonomous-system", {"number": n}), "number": n}
    if t == "hash":
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(v)]
        return {"type": "file", "spec_version": "2.1", "id": _id_sco("file", {"hashes": {algo: v}}),
                "hashes": {algo: v}}
    if t == "username":
        return {"type": "user-account", "spec_version": "2.1",
                "id": _id_sco("user-account", {"account_login": v}), "account_login": v}
    base = {"spec_version": "2.1", "created": agora, "modified": agora, "created_by_ref": criador}
    if t in ("pessoa", "organizacao", "cnpj"):
        classe = "individual" if t == "pessoa" else "organization"
        obj = {"type": "identity", "id": _id_sdo("identity", chave), "name": v, "identity_class": classe, **base}
        if t == "cnpj":
            obj["x_garimpo_cnpj"] = v
        return obj
    if t == "cep":
        return {"type": "location", "id": _id_sdo("location", chave), "postal_code": v,
                "country": "BR", **base}
    if t == "telefone":
        return {"type": "identity", "id": _id_sdo("identity", chave), "name": f"telefone {v}",
                "identity_class": "unknown", "contact_information": v, **base}
    return None  # cpf, documento_invalido: não exportados


def stix(caso: dict) -> dict:
    agora = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    criador = _id_sdo("identity", "garimpo")
    objs = [{"type": "identity", "spec_version": "2.1", "id": criador, "created": agora, "modified": agora,
             "name": f"GARIMPO {VERSAO} (DEIVOSINT)", "identity_class": "system"}]
    ids = {}
    for chave, no in caso["grafo"]["nos"].items():
        if no["tipo"] in NAO_EXPORTA:
            continue
        o = _stix_obj(no, chave, criador, agora)
        if o:
            ids[chave] = o["id"]
            objs.append(o)
            if no.get("fatos"):
                objs.append({"type": "note", "spec_version": "2.1", "id": _id_sdo("note", chave + caso["iniciado_utc"]),
                             "created": agora, "modified": agora, "created_by_ref": criador,
                             "abstract": f"GARIMPO: fatos sobre {no['valor']}"[:250],
                             "content": "\n".join(f"[{f['fonte']}] {f['fato']}" for f in no["fatos"]),
                             "authors": ["GARIMPO"], "object_refs": [o["id"]]})
    for a in caso["grafo"]["arestas"]:
        if a["de"] in ids and a["para"] in ids:
            rel = a["relacao"].replace("_", "-").lower()
            if rel == "resolve-para":
                rel = "resolves-to"
            objs.append({"type": "relationship", "spec_version": "2.1",
                         "id": _id_sdo("relationship", f"{a['de']}|{a['para']}|{a['relacao']}"),
                         "created": agora, "modified": agora, "created_by_ref": criador,
                         "relationship_type": rel, "source_ref": ids[a["de"]], "target_ref": ids[a["para"]],
                         "confidence": int(round(a["confianca"] * 100)),
                         "description": f"fonte GARIMPO: {a.get('fonte', '?')}"})
    objs.append({"type": "grouping", "spec_version": "2.1", "id": _id_sdo("grouping", caso["seed"] + caso["iniciado_utc"]),
                 "created": agora, "modified": agora, "created_by_ref": criador,
                 "name": f"GARIMPO — {caso['seed']} — {caso['iniciado_utc'][:19]}",
                 "context": "unspecified", "object_refs": [o["id"] for o in objs[1:]] or [criador]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def graphml(caso: dict) -> str:
    ns = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", ns)
    raiz = ET.Element(f"{{{ns}}}graphml")
    chaves = [("tipo", "node", "string"), ("valor", "node", "string"), ("profundidade", "node", "int"),
              ("investigado", "node", "boolean"), ("fatos", "node", "string"),
              ("relacao", "edge", "string"), ("confianca", "edge", "double"), ("fonte", "edge", "string")]
    for nome, alvo, tipo in chaves:
        ET.SubElement(raiz, f"{{{ns}}}key", id=nome, **{"for": alvo, "attr.name": nome, "attr.type": tipo})
    g = ET.SubElement(raiz, f"{{{ns}}}graph", id="garimpo", edgedefault="directed")
    validos = set()
    for chave, no in caso["grafo"]["nos"].items():
        if no["tipo"] in NAO_EXPORTA:
            continue
        validos.add(chave)
        n = ET.SubElement(g, f"{{{ns}}}node", id=chave)
        for k, v in (("tipo", no["tipo"]), ("valor", no["valor"]), ("profundidade", no["profundidade"]),
                     ("investigado", str(bool(no["investigado"])).lower()),
                     ("fatos", " | ".join(f"[{f['fonte']}] {f['fato']}" for f in no["fatos"]))):
            ET.SubElement(n, f"{{{ns}}}data", key=k).text = str(v)
    for i, a in enumerate(caso["grafo"]["arestas"]):
        if a["de"] in validos and a["para"] in validos:
            e = ET.SubElement(g, f"{{{ns}}}edge", id=f"e{i}", source=a["de"], target=a["para"])
            for k in ("relacao", "confianca", "fonte"):
                ET.SubElement(e, f"{{{ns}}}data", key=k).text = str(a.get(k, ""))
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(raiz, encoding="unicode")


def exportar(caso: dict, caso_dir: str, formato: str) -> list[str]:
    if formato not in FORMATOS:
        raise ValueError(f"formato desconhecido: {formato} (use {', '.join(FORMATOS)})")
    pasta = os.path.join(caso_dir, "exportacoes")
    os.makedirs(pasta, exist_ok=True)
    if formato == "stix":
        caminho = os.path.join(pasta, "garimpo-stix21.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(stix(caso), f, ensure_ascii=False, indent=2)
        return [caminho]
    if formato == "graphml":
        caminho = os.path.join(pasta, "garimpo.graphml")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(graphml(caso))
        return [caminho]
    if formato == "json":
        caminho = os.path.join(pasta, "garimpo-grafo.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(caso["grafo"], f, ensure_ascii=False, indent=2)
        return [caminho]
    ent, vin = os.path.join(pasta, "entidades.csv"), os.path.join(pasta, "vinculos.csv")
    nos = caso["grafo"]["nos"]
    with open(ent, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["chave", "tipo", "valor", "profundidade", "investigado", "n_fatos", "fatos"])
        for k, n in nos.items():
            if n["tipo"] in NAO_EXPORTA:
                continue
            w.writerow([k, n["tipo"], n["valor"], n["profundidade"], n["investigado"], len(n["fatos"]),
                        " | ".join(f"[{x['fonte']}] {x['fato']}" for x in n["fatos"])])
    with open(vin, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["origem_tipo", "origem", "destino_tipo", "destino", "relacao", "confianca", "fonte"])
        for a in caso["grafo"]["arestas"]:
            o, d = nos.get(a["de"]), nos.get(a["para"])
            if not o or not d or o["tipo"] in NAO_EXPORTA or d["tipo"] in NAO_EXPORTA:
                continue
            w.writerow([o["tipo"], o["valor"], d["tipo"], d["valor"], a["relacao"], a["confianca"], a.get("fonte", "")])
    return [ent, vin]
