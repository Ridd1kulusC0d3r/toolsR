# -*- coding: utf-8 -*-
"""Monitoramento: o que mudou no alvo entre duas coletas.

Compara entidades consultadas, fatos (por fonte+texto, ignorando evidência)
e vínculos. Útil para acompanhar um alvo ao longo do tempo: novo subdomínio,
porta nova na Shodan, sócio que entrou/saiu do QSA, chave PGP publicada…
"""

from __future__ import annotations

import html as _h

E = _h.escape


def _fatos(no: dict) -> set:
    return {(f["fonte"], f["fato"]) for f in no.get("fatos", [])}


def _arestas(caso: dict) -> set:
    return {(a["de"], a["para"], a["relacao"]) for a in caso["grafo"]["arestas"]}


def comparar(antes: dict, depois: dict) -> dict:
    na, nd = antes["grafo"]["nos"], depois["grafo"]["nos"]
    inv_a = {k for k, n in na.items() if n.get("investigado", True)}
    inv_d = {k for k, n in nd.items() if n.get("investigado", True)}
    fatos_novos, fatos_sumidos = {}, {}
    for k in sorted(inv_a & inv_d):
        fa, fd = _fatos(na[k]), _fatos(nd[k])
        if fd - fa:
            fatos_novos[k] = sorted(fd - fa)
        if fa - fd:
            fatos_sumidos[k] = sorted(fa - fd)
    aa, ad = _arestas(antes), _arestas(depois)
    d = {
        "antes": {"seed": antes["seed"], "iniciado_utc": antes["iniciado_utc"]},
        "depois": {"seed": depois["seed"], "iniciado_utc": depois["iniciado_utc"]},
        "entidades_novas": sorted(set(nd) - set(na)),
        "entidades_sumidas": sorted(set(na) - set(nd)),
        "fatos_novos": {k: [list(x) for x in v] for k, v in fatos_novos.items()},
        "fatos_sumidos": {k: [list(x) for x in v] for k, v in fatos_sumidos.items()},
        "vinculos_novos": [list(x) for x in sorted(ad - aa)],
        "vinculos_sumidos": [list(x) for x in sorted(aa - ad)],
    }
    d["total_mudancas"] = (len(d["entidades_novas"]) + len(d["entidades_sumidas"])
                           + sum(map(len, fatos_novos.values())) + sum(map(len, fatos_sumidos.values()))
                           + len(d["vinculos_novos"]) + len(d["vinculos_sumidos"]))
    return d


def relatorio_texto(d: dict) -> str:
    linhas = [f"Mudanças de {d['antes']['iniciado_utc'][:19]} para {d['depois']['iniciado_utc'][:19]} "
              f"(seed {d['depois']['seed']}): {d['total_mudancas']}"]
    if not d["total_mudancas"]:
        return linhas[0] + "\n  nada mudou."
    for k in d["entidades_novas"]:
        linhas.append(f"  + entidade {k}")
    for k in d["entidades_sumidas"]:
        linhas.append(f"  - entidade {k}")
    for k, fs in d["fatos_novos"].items():
        for fonte, fato in fs:
            linhas.append(f"  + [{k}] [{fonte}] {fato}")
    for k, fs in d["fatos_sumidos"].items():
        for fonte, fato in fs:
            linhas.append(f"  - [{k}] [{fonte}] {fato}")
    for de, para, rel in d["vinculos_novos"]:
        linhas.append(f"  + vínculo {de} —{rel}→ {para}")
    for de, para, rel in d["vinculos_sumidos"]:
        linhas.append(f"  - vínculo {de} —{rel}→ {para}")
    return "\n".join(linhas)


def diff_html(d: dict) -> str:
    if not d["total_mudancas"]:
        corpo = "<p>Nada mudou desde a coleta anterior.</p>"
    else:
        itens = []
        for k in d["entidades_novas"]:
            itens.append(f'<li class="mais">+ entidade {E(k)}</li>')
        for k in d["entidades_sumidas"]:
            itens.append(f'<li class="menos">− entidade {E(k)}</li>')
        for k, fs in d["fatos_novos"].items():
            itens += [f'<li class="mais">+ <b>{E(k)}</b> [{E(f)}] {E(t)}</li>' for f, t in fs]
        for k, fs in d["fatos_sumidos"].items():
            itens += [f'<li class="menos">− <b>{E(k)}</b> [{E(f)}] {E(t)}</li>' for f, t in fs]
        for de, para, rel in d["vinculos_novos"]:
            itens.append(f'<li class="mais">+ vínculo {E(de)} —{E(rel)}→ {E(para)}</li>')
        for de, para, rel in d["vinculos_sumidos"]:
            itens.append(f'<li class="menos">− vínculo {E(de)} —{E(rel)}→ {E(para)}</li>')
        corpo = f"<ul>{''.join(itens)}</ul>"
    return (f'<h2>Mudanças desde {E(d["antes"]["iniciado_utc"][:19])} UTC ({d["total_mudancas"]})</h2>'
            f'<div class="mud">{corpo}</div>')
