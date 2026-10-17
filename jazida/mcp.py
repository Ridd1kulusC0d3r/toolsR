# -*- coding: utf-8 -*-
"""Servidor MCP (Model Context Protocol) em stdlib pura: JSON-RPC 2.0 sobre
stdio, uma mensagem por linha.

Configuração no Claude Desktop (claude_desktop_config.json):

    {"mcpServers": {"garimpo": {"command": "python3",
        "args": ["/caminho/para/toolsR/garimpo.py", "mcp", "--casos", "/caminho/para/casos"]}}}

Regras de segurança:
  - stdout é exclusivo do protocolo; todo log vai para stderr;
  - casos só são lidos/escritos DENTRO da pasta --casos (nome de pasta, nunca caminho);
  - o servidor herda o modo do GARIMPO: sempre passivo, orçamento rígido.
"""

from __future__ import annotations

import json
import os
import re
import sys

from . import VERSAO
from .custodia import Custodia
from .deteccao import detectar_tipo
from .dossie import gerar_dossie
from .exportar import FORMATOS, exportar
from .fontes import tabela_ruido
from .monitor import comparar, relatorio_texto
from .motor import carregar_caso, investigar
from .rede import Orcamento, log_stderr

PROTOCOLO = "2025-06-18"
RE_NOME_CASO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,120}$")

FERRAMENTAS = [
    {"name": "garimpo_investigar",
     "description": "Investiga um alvo (domínio, IP, e-mail, username, CNPJ, CEP, ASN, URL, hash, telefone) "
                    "só com fontes passivas e keyless, pivotando em BFS com orçamento. Gera caso com dossiê HTML "
                    "e cadeia de custódia SHA-256. Fatos são pistas a confirmar, não prova.",
     "inputSchema": {"type": "object", "properties": {
         "alvo": {"type": "string"},
         "profundidade": {"type": "integer", "minimum": 0, "maximum": 3, "default": 1},
         "max_requisicoes": {"type": "integer", "minimum": 1, "maximum": 200, "default": 40},
         "max_entidades": {"type": "integer", "minimum": 1, "maximum": 50, "default": 12}},
         "required": ["alvo"]}},
    {"name": "garimpo_detectar", "description": "Diz o tipo de entidade que o GARIMPO detecta para um valor (offline).",
     "inputSchema": {"type": "object", "properties": {"valor": {"type": "string"}}, "required": ["valor"]}},
    {"name": "garimpo_fontes", "description": "Tabela de ruído: cada fonte, nível e o que é enviado para onde.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "garimpo_casos", "description": "Lista os casos existentes na pasta de casos.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "garimpo_caso", "description": "Lê um caso: entidades, fatos (com fonte e evidência) e vínculos.",
     "inputSchema": {"type": "object", "properties": {"caso": {"type": "string", "description": "nome da pasta do caso"}},
                     "required": ["caso"]}},
    {"name": "garimpo_verificar", "description": "Verifica a cadeia de custódia (SHA-256 encadeado) de um caso.",
     "inputSchema": {"type": "object", "properties": {"caso": {"type": "string"}}, "required": ["caso"]}},
    {"name": "garimpo_comparar", "description": "Diff entre duas coletas: o que surgiu ou sumiu no alvo.",
     "inputSchema": {"type": "object", "properties": {"caso_antes": {"type": "string"}, "caso_depois": {"type": "string"}},
                     "required": ["caso_antes", "caso_depois"]}},
    {"name": "garimpo_exportar", "description": f"Exporta um caso em {', '.join(FORMATOS)} (arquivos na pasta do caso).",
     "inputSchema": {"type": "object", "properties": {"caso": {"type": "string"},
                                                      "formato": {"type": "string", "enum": list(FORMATOS)}},
                     "required": ["caso", "formato"]}},
]


class ErroFerramenta(Exception):
    pass


class Servidor:
    def __init__(self, base: str):
        self.base = os.path.abspath(base)
        os.makedirs(self.base, exist_ok=True)

    def _caso_dir(self, nome: str) -> str:
        if not isinstance(nome, str) or not RE_NOME_CASO.match(nome):
            raise ErroFerramenta("nome de caso inválido: use só o nome da pasta (sem barras)")
        d = os.path.join(self.base, nome)
        if not os.path.isfile(os.path.join(d, "caso.json")):
            raise ErroFerramenta(f"caso não encontrado: {nome}")
        return d

    def _resumo(self, caso: dict, limite: int = 60) -> str:
        g = caso["grafo"]
        linhas = [f"Seed: {caso['seed']} ({caso['tipo_seed']}) · requisições {caso['orcamento']['requisicoes_feitas']}"
                  f"/{caso['orcamento']['max_requisicoes']}"]
        n = 0
        for k, no in g["nos"].items():
            if not no["investigado"]:
                continue
            linhas.append(f"\n## {k} (prof {no['profundidade']})")
            for f in no["fatos"]:
                if n >= limite:
                    linhas.append("… (fatos truncados; use garimpo_caso para o restante)")
                    return "\n".join(linhas)
                linhas.append(f"- [{f['fonte']}] {f['fato']}  (evidência #{','.join(map(str, f.get('evidencias', []))) or '-'})")
                n += 1
        fronteira = [k for k, no in g["nos"].items() if not no["investigado"]]
        if fronteira:
            linhas.append(f"\nFronteira (não consultada): {', '.join(fronteira[:40])}")
        linhas.append("\nVínculos: " + "; ".join(f"{a['de']} —{a['relacao']}→ {a['para']}" for a in g["arestas"][:60]))
        return "\n".join(linhas)

    def chamar(self, nome: str, args: dict) -> str:
        if nome == "garimpo_detectar":
            return detectar_tipo(str(args.get("valor", "")))
        if nome == "garimpo_fontes":
            return "\n".join(f"{a} [{b}] {c}: {d}" for a, b, c, d in tabela_ruido())
        if nome == "garimpo_casos":
            casos = sorted(x for x in os.listdir(self.base) if os.path.isfile(os.path.join(self.base, x, "caso.json")))
            return "\n".join(casos) or "(nenhum caso)"
        if nome == "garimpo_caso":
            return self._resumo(carregar_caso(self._caso_dir(args.get("caso"))), limite=400)
        if nome == "garimpo_verificar":
            ok, prob = Custodia.verificar(self._caso_dir(args.get("caso")))
            return "ÍNTEGRA: hashes e encadeamento conferem." if ok else "COMPROMETIDA:\n" + "\n".join(prob)
        if nome == "garimpo_comparar":
            d = comparar(carregar_caso(self._caso_dir(args.get("caso_antes"))),
                         carregar_caso(self._caso_dir(args.get("caso_depois"))))
            return relatorio_texto(d)
        if nome == "garimpo_exportar":
            d = self._caso_dir(args.get("caso"))
            fmt = args.get("formato")
            if fmt not in FORMATOS:
                raise ErroFerramenta(f"formato inválido: {fmt}")
            return "\n".join(exportar(carregar_caso(d), d, fmt))
        if nome == "garimpo_investigar":
            alvo = str(args.get("alvo", "")).strip()
            if not alvo:
                raise ErroFerramenta("informe o alvo")
            from .cli import novo_caso_dir
            prof = max(0, min(3, int(args.get("profundidade", 1))))
            orc = Orcamento(max(1, min(200, int(args.get("max_requisicoes", 40)))),
                            max(1, min(50, int(args.get("max_entidades", 12)))), prof)
            d = novo_caso_dir(alvo, self.base)
            caso = investigar(alvo, orc, d, silencioso=True, log=log_stderr)
            gerar_dossie(caso, d)
            return (f"Caso: {os.path.basename(d)}\nDossiê: {os.path.join(d, 'dossie.html')}\n\n"
                    + self._resumo(caso))
        raise ErroFerramenta(f"ferramenta desconhecida: {nome}")

    def tratar(self, msg: dict):
        metodo, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notificação (ex.: notifications/initialized) — sem resposta
            return None
        params = msg.get("params") or {}
        try:
            if metodo == "initialize":
                res = {"protocolVersion": params.get("protocolVersion") or PROTOCOLO,
                       "capabilities": {"tools": {"listChanged": False}},
                       "serverInfo": {"name": "garimpo", "title": "GARIMPO (DEIVOSINT)", "version": VERSAO},
                       "instructions": "OSINT passivo e keyless com cadeia de custódia. Comece por garimpo_investigar; "
                                       "trate fatos como pistas e cite a evidência (#seq)."}
            elif metodo == "ping":
                res = {}
            elif metodo == "tools/list":
                res = {"tools": FERRAMENTAS}
            elif metodo == "tools/call":
                try:
                    texto = self.chamar(params.get("name"), params.get("arguments") or {})
                    res = {"content": [{"type": "text", "text": texto}], "isError": False}
                except ErroFerramenta as e:
                    res = {"content": [{"type": "text", "text": f"Erro: {e}"}], "isError": True}
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"método desconhecido: {metodo}"}}
            return {"jsonrpc": "2.0", "id": mid, "result": res}
        except Exception as e:  # nunca derruba o servidor
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}


def servir(base: str = "casos", entrada=None, saida=None) -> int:
    entrada = entrada or sys.stdin
    saida = saida or sys.stdout
    sys.stdout = sys.stderr  # qualquer print acidental vai para stderr, não corrompe o protocolo
    srv = Servidor(base)
    log_stderr(f"GARIMPO {VERSAO} · servidor MCP pronto (casos em {srv.base})")
    for linha in entrada:
        linha = linha.strip()
        if not linha:
            continue
        try:
            msg = json.loads(linha)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "JSON inválido"}}
        else:
            resp = srv.tratar(msg) if isinstance(msg, dict) else {
                "jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "lotes não suportados"}}
        if resp is not None:
            saida.write(json.dumps(resp, ensure_ascii=False) + "\n")
            saida.flush()
    return 0
