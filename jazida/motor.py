# -*- coding: utf-8 -*-
"""Motor de pivô: BFS por camadas, fontes em paralelo dentro de cada camada,
orçamento rígido, e cada fato amarrado às evidências que o sustentam.

Esquema do caso.json (versao_esquema 2):
  grafo.nos[chave] = {tipo, valor, profundidade, investigado, fatos:[{fonte, fato, evidencias:[seq]}]}
  grafo.arestas    = [{de, para, relacao, confianca, fonte}]
Nós com investigado=False são a FRONTEIRA: descobertos, mas não consultados
(limite de profundidade, de entidades ou confiança < 0,6).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

from . import VERSAO
from .custodia import Custodia
from .deteccao import detectar_tipo, normalizar
from .fontes import fontes_para
from .rede import Cliente, Orcamento

CONFIANCA_PIVO = 0.6
LIMITE_FRONTEIRA = 6  # nós totais ≤ max_entidades × 6


def chave_de(tipo: str, valor: str) -> str:
    return f"{tipo}:{normalizar(tipo, valor).lower()}"


def _executar(cliente: Cliente, fonte, valor: str):
    cliente.iniciar_rastreio()
    try:
        fatos, novas = fonte.fn(cliente, valor)
    except Exception as e:  # uma fonte quebrada nunca derruba a investigação
        fatos, novas = [f"falha interna da fonte: {type(e).__name__}: {e}"], []
    return fatos, novas, cliente.encerrar_rastreio()


def investigar(seed: str, orc: Orcamento, caso_dir: str, silencioso: bool = False,
               paralelo: int = 4, log=None, progresso=None, cliente_cls=Cliente) -> dict:
    log = log or print
    custodia = Custodia(caso_dir)
    cliente = cliente_cls(custodia, orc, silencioso, log=log)
    tipo_seed = detectar_tipo(seed)
    inicio = time.time()
    nos: dict[str, dict] = {}
    arestas: list[dict] = []
    uso_fontes: dict[str, int] = {}

    def no(tipo, valor, prof, investigado):
        k = chave_de(tipo, valor)
        if k not in nos:
            nos[k] = {"tipo": tipo, "valor": normalizar(tipo, valor), "profundidade": prof,
                      "investigado": investigado, "fatos": []}
        return k

    camada = [(tipo_seed, seed.strip())]
    prof = 0
    with ThreadPoolExecutor(max_workers=max(1, paralelo)) as pool:
        while camada:
            # quem desta camada será investigado (teto de entidades)
            alvos = []
            ja = sum(1 for n in nos.values() if n["investigado"])
            for tipo, valor in camada:
                k = chave_de(tipo, valor)
                if nos.get(k, {}).get("investigado"):
                    continue
                if ja + len(alvos) >= orc.max_entidades:
                    break
                no(tipo, valor, prof, True)
                nos[k]["investigado"] = True
                alvos.append((k, tipo, valor))
            if not alvos:
                break
            tarefas = []
            for k, tipo, valor in alvos:
                if not silencioso:
                    log(f"\n[{prof}] {tipo.upper()} → {valor}")
                for f in fontes_para(tipo):
                    tarefas.append((k, f, pool.submit(_executar, cliente, f, nos[k]["valor"])))
            proxima = []
            for k, f, fut in tarefas:  # ordem de submissão → grafo determinístico
                fatos, novas, seqs = fut.result()
                uso_fontes[f.nome] = uso_fontes.get(f.nome, 0) + 1
                for texto in fatos:
                    nos[k]["fatos"].append({"fonte": f.nome, "fato": texto, "evidencias": seqs})
                    if not silencioso:
                        log(f"    [{f.nome}] {texto}")
                for ntipo, nvalor, relacao, conf in novas:
                    nk = chave_de(ntipo, nvalor)
                    if nk == k:
                        continue
                    if nk not in nos and len(nos) >= orc.max_entidades * LIMITE_FRONTEIRA:
                        continue  # grafo legível: a fronteira também tem teto
                    no(ntipo, nvalor, prof + 1, False)
                    if not any(a["de"] == k and a["para"] == nk and a["relacao"] == relacao for a in arestas):
                        arestas.append({"de": k, "para": nk, "relacao": relacao,
                                        "confianca": conf, "fonte": f.nome})
                    if conf >= CONFIANCA_PIVO and prof < orc.profundidade and not nos[nk]["investigado"]:
                        proxima.append((ntipo, nvalor))
                if progresso:
                    progresso(orc.requisicoes, len(nos))
            camada = list(dict.fromkeys(proxima))  # remove duplicatas, mantém ordem
            prof += 1

    caso = {
        "versao_esquema": 2,
        "ferramenta": f"GARIMPO {VERSAO} (DEIVOSINT)",
        "seed": seed, "tipo_seed": tipo_seed,
        "iniciado_utc": _dt.datetime.fromtimestamp(inicio, _dt.timezone.utc).isoformat(),
        "duracao_s": round(time.time() - inicio, 2),
        "orcamento": {"profundidade": orc.profundidade, "max_entidades": orc.max_entidades,
                      "max_requisicoes": orc.max_requisicoes, "requisicoes_feitas": orc.requisicoes},
        "fontes_usadas": uso_fontes,
        "grafo": {"no_seed": chave_de(tipo_seed, seed), "nos": nos, "arestas": arestas},
    }
    salvar_caso(caso, caso_dir)
    return caso


def salvar_caso(caso: dict, caso_dir: str) -> None:
    with open(os.path.join(caso_dir, "caso.json"), "w", encoding="utf-8") as f:
        json.dump(caso, f, ensure_ascii=False, indent=2)


def carregar_caso(caso_dir: str) -> dict:
    with open(os.path.join(caso_dir, "caso.json"), encoding="utf-8") as f:
        caso = json.load(f)
    return migrar(caso)


def migrar(caso: dict) -> dict:
    """Lê casos da 1.x (esquema 1) no formato 2."""
    if caso.get("versao_esquema") == 2:
        return caso
    g = caso.get("grafo", {})
    for n in g.get("nos", {}).values():
        n.setdefault("investigado", True)
        for f in n.get("fatos", []):
            f.setdefault("evidencias", [])
    for a in g.get("arestas", []):
        a.setdefault("fonte", "?")
    caso["versao_esquema"] = 2
    caso.setdefault("fontes_usadas", {})
    return caso
