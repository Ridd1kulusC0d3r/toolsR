# -*- coding: utf-8 -*-
"""Linha de comando do GARIMPO 2.0."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys

from . import VERSAO
from .custodia import Custodia
from .deteccao import detectar_tipo
from .dossie import gerar_dossie
from .exportar import FORMATOS, exportar
from .fontes import NIVEIS, tabela_ruido
from .monitor import comparar, relatorio_texto
from .motor import carregar_caso, investigar, salvar_caso
from .rede import Orcamento


def _utf8():
    # Windows redireciona stdout em cp1252 e quebraria com "✔"/"⛏️": força UTF-8.
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def novo_caso_dir(alvo: str, base: str = "casos") -> str:
    carimbo = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    slug = re.sub(r"[^A-Za-z0-9.-]", "_", alvo)[:40]
    d = os.path.join(base, f"{carimbo}_{slug}")
    n = 2
    while os.path.exists(d):
        d = os.path.join(base, f"{carimbo}_{slug}_{n}")
        n += 1
    os.makedirs(d)
    return d


def _opcoes_investigacao(sp):
    sp.add_argument("alvo")
    sp.add_argument("--profundidade", type=int, default=1, help="saltos de pivô a partir do seed (padrão 1)")
    sp.add_argument("--max-entidades", type=int, default=12, help="teto de entidades CONSULTADAS (padrão 12)")
    sp.add_argument("--max-requisicoes", type=int, default=40, help="teto duro de requisições HTTP (padrão 40)")
    sp.add_argument("--paralelo", type=int, default=4, help="consultas simultâneas (padrão 4)")
    sp.add_argument("--caso", default=None, help="pasta do caso (padrão casos/AAAA-MM-DD_HHMMSS_alvo)")
    sp.add_argument("--exportar", default="", help=f"formatos extras separados por vírgula: {','.join(FORMATOS)}")
    sp.add_argument("--silencioso", action="store_true")


def _rodar(args, diff_contra: str | None = None) -> int:
    tipo = detectar_tipo(args.alvo)
    caso_dir = args.caso or novo_caso_dir(args.alvo)
    os.makedirs(caso_dir, exist_ok=True)
    print(f"⛏️  GARIMPO {VERSAO} · seed: {args.alvo} (detectado: {tipo})")
    print(f"    caso: {caso_dir} · modo: PASSIVO (sempre) · paralelo: {args.paralelo}")
    orc = Orcamento(args.max_requisicoes, args.max_entidades, args.profundidade)
    caso = investigar(args.alvo, orc, caso_dir, args.silencioso, paralelo=args.paralelo)
    diff = None
    if diff_contra:
        diff = comparar(carregar_caso(diff_contra), caso)
        with open(os.path.join(caso_dir, "diff.json"), "w", encoding="utf-8") as f:
            json.dump(diff, f, ensure_ascii=False, indent=2)
        caso["comparado_com"] = os.path.basename(os.path.normpath(diff_contra))
        salvar_caso(caso, caso_dir)
    caminho = gerar_dossie(caso, caso_dir, diff=diff)
    nos = caso["grafo"]["nos"]
    inv = sum(1 for n in nos.values() if n["investigado"])
    print(f"\n✔ {inv} entidades consultadas · {len(nos) - inv} na fronteira · {len(caso['grafo']['arestas'])} vínculos · "
          f"{caso['orcamento']['requisicoes_feitas']} requisições · {caso['duracao_s']}s")
    for fmt in [x.strip() for x in args.exportar.split(",") if x.strip()]:
        for p in exportar(caso, caso_dir, fmt):
            print(f"✔ Exportado ({fmt}): {p}")
    if diff is not None:
        print("\n" + relatorio_texto(diff))
    print(f"✔ Dossiê: {caminho}")
    print(f"✔ Custódia: {os.path.join(caso_dir, 'ledger.jsonl')} (verifique com: python3 garimpo.py verificar {caso_dir})")
    return 0


def main(argv=None) -> int:
    _utf8()
    p = argparse.ArgumentParser(prog="garimpo", description=f"GARIMPO {VERSAO} — pivô OSINT passivo, keyless, stdlib (DEIVOSINT)")
    sub = p.add_subparsers(dest="cmd", required=True)

    _opcoes_investigacao(sub.add_parser("investigar", help="investiga um alvo e gera dossiê"))
    mon = sub.add_parser("monitorar", help="investiga de novo e mostra o que mudou desde uma coleta anterior")
    _opcoes_investigacao(mon)
    mon.add_argument("--contra", required=True, help="pasta do caso anterior")

    df = sub.add_parser("diff", help="compara duas coletas (anterior, nova)")
    df.add_argument("caso_antes")
    df.add_argument("caso_depois")
    df.add_argument("--json", action="store_true", help="imprime o diff em JSON")

    ex = sub.add_parser("exportar", help=f"exporta um caso: {', '.join(FORMATOS)}")
    ex.add_argument("caso_dir")
    ex.add_argument("formatos", nargs="+", choices=FORMATOS)

    det = sub.add_parser("detectar", help="mostra o tipo detectado de um valor")
    det.add_argument("valor")
    sub.add_parser("fontes", help="tabela de ruído: o que cada fonte envia, e para onde")
    ver = sub.add_parser("verificar", help="verifica a cadeia de custódia de um caso")
    ver.add_argument("caso_dir")
    dm = sub.add_parser("demo", help="duas coletas de demonstração offline + diff")
    dm.add_argument("--base", default="casos")
    pn = sub.add_parser("painel", help="abre o painel web local (127.0.0.1)")
    pn.add_argument("--porta", type=int, default=8765)
    pn.add_argument("--casos", default="casos")
    pn.add_argument("--sem-navegador", action="store_true")
    mc = sub.add_parser("mcp", help="servidor MCP (stdio) para Claude e outros clientes")
    mc.add_argument("--casos", default="casos")
    sub.add_parser("versao", help="mostra a versão")

    a = p.parse_args(argv)

    if a.cmd == "versao":
        print(f"GARIMPO {VERSAO}")
        return 0
    if a.cmd == "detectar":
        print(detectar_tipo(a.valor))
        return 0
    if a.cmd == "fontes":
        linhas = tabela_ruido()
        print(f"{'FONTE':20} {'TIPOS':22} {'NÍVEL':9} O QUE É ENVIADO, E PARA ONDE")
        print("-" * 118)
        for nome, tipos, nivel, desc in linhas:
            print(f"{nome:20} {tipos:22} {nivel:9} {desc}")
        print(f"\n{len(linhas)} fontes. Níveis:")
        for n, d in NIVEIS.items():
            print(f"  {n:9} {d}")
        print("Passiva não é privada: cada serviço consultado vê o que você pesquisou. "
              "Nenhuma fonte toca a infraestrutura do alvo.")
        return 0
    if a.cmd == "verificar":
        ok, problemas = Custodia.verificar(a.caso_dir)
        if ok:
            print("✔ Cadeia de custódia ÍNTEGRA: hashes e encadeamento conferem.")
            return 0
        print("✘ Cadeia de custódia COMPROMETIDA:")
        for pr in problemas:
            print(f"  - {pr}")
        return 1
    if a.cmd == "diff":
        d = comparar(carregar_caso(a.caso_antes), carregar_caso(a.caso_depois))
        print(json.dumps(d, ensure_ascii=False, indent=2) if a.json else relatorio_texto(d))
        return 0
    if a.cmd == "exportar":
        caso = carregar_caso(a.caso_dir)
        for fmt in a.formatos:
            for caminho in exportar(caso, a.caso_dir, fmt):
                print(f"✔ {fmt}: {caminho}")
        return 0
    if a.cmd == "demo":
        from .demo import rodar_demo
        caminho = rodar_demo(a.base)
        print(f"✔ Demo gerada (duas coletas fictícias + diff). Abra no navegador: {caminho}")
        print(f"  Anterior: {os.path.join(a.base, 'demo-anterior', 'dossie.html')}")
        return 0
    if a.cmd == "painel":
        from .painel import servir
        return servir(a.casos, a.porta, abrir=not a.sem_navegador)
    if a.cmd == "mcp":
        from .mcp import servir as servir_mcp
        return servir_mcp(a.casos)
    if a.cmd == "monitorar":
        return _rodar(a, diff_contra=a.contra)
    return _rodar(a)
