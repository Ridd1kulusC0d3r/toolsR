# -*- coding: utf-8 -*-
"""Painel web local do GARIMPO — http.server stdlib, só em 127.0.0.1.

Defesas (é um servidor local que dispara requisições de rede, então
precisa resistir a sites maliciosos abertos no mesmo navegador):
  - escuta só em 127.0.0.1;
  - Host precisa ser 127.0.0.1:<porta> ou localhost:<porta> (anti DNS rebinding);
  - POST exige o cabeçalho X-Garimpo: 1 e JSON (anti CSRF: força preflight CORS,
    que este servidor nunca autoriza);
  - nomes de caso e de evidência validados por regex e resolvidos DENTRO da
    pasta de casos (anti path traversal);
  - CSP restritiva e nosniff em todas as respostas.
"""

from __future__ import annotations

import io
import json
import os
import re
import threading
import traceback
import urllib.parse
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import VERSAO
from .custodia import Custodia
from .deteccao import detectar_tipo
from .dossie import gerar_dossie
from .exportar import FORMATOS, exportar
from .fontes import tabela_ruido
from .monitor import comparar
from .motor import carregar_caso, investigar
from .rede import Orcamento

AQUI = os.path.dirname(os.path.abspath(__file__))
RE_CASO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,120}$")
RE_EVID = re.compile(r"^\d{4,}_[a-z0-9_]+_[0-9a-f]{12}\.bin$")
CSP_APP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
CSP_DOSSIE = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'self'"


class Estado:
    def __init__(self, base: str, porta: int):
        self.base = os.path.abspath(base)
        self.porta = porta
        os.makedirs(self.base, exist_ok=True)
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()

    def caso_dir(self, nome: str) -> str | None:
        if not RE_CASO.match(nome or ""):
            return None
        d = os.path.realpath(os.path.join(self.base, nome))
        if os.path.dirname(d) != os.path.realpath(self.base):
            return None
        return d if os.path.isdir(d) else None

    def listar(self) -> list[dict]:
        out = []
        for nome in sorted(os.listdir(self.base), reverse=True):
            d = os.path.join(self.base, nome)
            job = self.jobs.get(nome)
            if os.path.isfile(os.path.join(d, "caso.json")):
                try:
                    c = carregar_caso(d)
                except (OSError, ValueError):
                    continue
                nos = c["grafo"]["nos"]
                out.append({"id": nome, "seed": c["seed"], "tipo": c["tipo_seed"], "iniciado": c["iniciado_utc"],
                            "investigadas": sum(1 for n in nos.values() if n["investigado"]),
                            "vinculos": len(c["grafo"]["arestas"]), "status": (job or {}).get("status", "pronto")})
            elif job:
                out.append({"id": nome, "seed": job["alvo"], "tipo": detectar_tipo(job["alvo"]), "iniciado": "",
                            "investigadas": job.get("entidades", 0), "vinculos": 0, "status": job["status"]})
        return out

    def iniciar(self, alvo: str, prof: int, max_req: int, max_ent: int, contra: str | None) -> str:
        from .cli import novo_caso_dir
        d = novo_caso_dir(alvo, self.base)
        nome = os.path.basename(d)
        job = {"alvo": alvo, "status": "rodando", "requisicoes": 0, "entidades": 0, "max_requisicoes": max_req}
        self.jobs[nome] = job

        def progresso(req, ent):
            job["requisicoes"], job["entidades"] = req, ent

        def rodar():
            try:
                orc = Orcamento(max_req, max_ent, prof)
                caso = investigar(alvo, orc, d, silencioso=True, progresso=progresso)
                diff = None
                if contra and self.caso_dir(contra):
                    diff = comparar(carregar_caso(self.caso_dir(contra)), caso)
                    with open(os.path.join(d, "diff.json"), "w", encoding="utf-8") as f:
                        json.dump(diff, f, ensure_ascii=False, indent=2)
                gerar_dossie(caso, d, diff=diff)
                job["status"] = "pronto"
            except Exception as e:
                job["status"] = f"erro: {type(e).__name__}: {e}"
                traceback.print_exc()
        threading.Thread(target=rodar, daemon=True).start()
        return nome


class Manipulador(BaseHTTPRequestHandler):
    server_version = f"GARIMPO/{VERSAO}"
    estado: Estado = None  # injetado em servir()

    def log_message(self, fmt, *args):  # silencioso no terminal, exceto erros
        pass

    # ----------------------------------------------------------- respostas
    def _enviar(self, codigo: int, corpo: bytes, tipo: str, extra: dict | None = None, csp: str = CSP_APP):
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)

    def _json(self, codigo: int, obj):
        self._enviar(codigo, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _erro(self, codigo: int, msg: str):
        self._json(codigo, {"erro": msg})

    def _host_ok(self) -> bool:
        p = self.estado.porta
        return self.headers.get("Host", "") in (f"127.0.0.1:{p}", f"localhost:{p}")

    # ----------------------------------------------------------- GET
    def do_GET(self):
        if not self._host_ok():
            return self._erro(403, "Host não permitido")
        url = urllib.parse.urlparse(self.path)
        partes = [urllib.parse.unquote(x) for x in url.path.strip("/").split("/") if x]
        q = dict(urllib.parse.parse_qsl(url.query))
        try:
            if not partes:
                with open(os.path.join(AQUI, "painel.html"), "rb") as f:
                    return self._enviar(200, f.read().replace(b"__VERSAO__", VERSAO.encode()), "text/html; charset=utf-8")
            if partes[0] != "api":
                return self._erro(404, "não encontrado")
            if partes[1:] == ["fontes"]:
                return self._json(200, [{"fonte": a, "tipos": b, "nivel": c, "destino": d} for a, b, c, d in tabela_ruido()])
            if partes[1:] == ["casos"]:
                return self._json(200, self.estado.listar())
            if partes[1:] == ["detectar"]:
                return self._json(200, {"tipo": detectar_tipo(q.get("valor", ""))})
            if partes[1:] == ["comparar"]:
                a, b = self.estado.caso_dir(q.get("a", "")), self.estado.caso_dir(q.get("b", ""))
                if not a or not b:
                    return self._erro(404, "caso não encontrado")
                return self._json(200, comparar(carregar_caso(a), carregar_caso(b)))
            if len(partes) >= 3 and partes[1] == "casos":
                d = self.estado.caso_dir(partes[2])
                if not d:
                    return self._erro(404, "caso não encontrado")
                resto = partes[3:]
                job = self.estado.jobs.get(partes[2])
                if not resto:
                    if not os.path.isfile(os.path.join(d, "caso.json")):
                        return self._json(200, {"status": (job or {}).get("status", "?"), "job": job})
                    caso = carregar_caso(d)
                    caso["status"] = (job or {}).get("status", "pronto")
                    caso["ledger"] = {r["seq"]: {"arquivo": r["arquivo"], "sha256": r["sha256_evidencia"],
                                                 "status": r["status_http"], "url": r["url"], "fonte": r["fonte"]}
                                      for r in Custodia.ler_ledger(d)}
                    p = os.path.join(d, "diff.json")
                    if os.path.isfile(p):
                        with open(p, encoding="utf-8") as f:
                            caso["diff"] = json.load(f)
                    return self._json(200, caso)
                if resto == ["verificar"]:
                    ok, prob = Custodia.verificar(d)
                    return self._json(200, {"ok": ok, "problemas": prob})
                if resto == ["dossie"]:
                    with open(os.path.join(d, "dossie.html"), "rb") as f:
                        corpo = f.read().replace(b'href="evidencias/', f'href="/api/casos/{partes[2]}/evidencias/'.encode())
                    return self._enviar(200, corpo, "text/html; charset=utf-8", csp=CSP_DOSSIE)
                if len(resto) == 2 and resto[0] == "evidencias" and RE_EVID.match(resto[1]):
                    caminho = os.path.join(d, "evidencias", resto[1])
                    if not os.path.isfile(caminho):
                        return self._erro(404, "evidência não encontrada")
                    with open(caminho, "rb") as f:
                        return self._enviar(200, f.read(), "text/plain; charset=utf-8",
                                            {"Content-Disposition": f'inline; filename="{resto[1]}"'})
                if len(resto) == 2 and resto[0] == "exportar" and resto[1] in FORMATOS:
                    arquivos = exportar(carregar_caso(d), d, resto[1])
                    if len(arquivos) == 1:
                        with open(arquivos[0], "rb") as f:
                            dados = f.read()
                        nome = os.path.basename(arquivos[0])
                        tipo = "application/xml" if nome.endswith(".graphml") else "application/json"
                    else:
                        buf = io.BytesIO()
                        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                            for a in arquivos:
                                z.write(a, os.path.basename(a))
                        dados, nome, tipo = buf.getvalue(), f"{partes[2]}-csv.zip", "application/zip"
                    return self._enviar(200, dados, tipo, {"Content-Disposition": f'attachment; filename="{nome}"'})
            return self._erro(404, "não encontrado")
        except (OSError, ValueError) as e:
            return self._erro(500, f"{type(e).__name__}: {e}")

    do_HEAD = do_GET

    # ----------------------------------------------------------- POST
    def do_POST(self):
        if not self._host_ok():
            return self._erro(403, "Host não permitido")
        if self.headers.get("X-Garimpo") != "1" or "application/json" not in self.headers.get("Content-Type", ""):
            return self._erro(403, "requisição sem o cabeçalho X-Garimpo: 1 (proteção anti-CSRF)")
        if self.path == "/api/demo":
            from .demo import rodar_demo
            rodar_demo(self.estado.base)
            return self._json(201, {"id": "demo"})
        if self.path != "/api/investigar":
            return self._erro(404, "não encontrado")
        try:
            tam = min(int(self.headers.get("Content-Length", "0")), 10_000)
            dados = json.loads(self.rfile.read(tam) or b"{}")
            alvo = str(dados.get("alvo", "")).strip()[:300]
            if not alvo:
                return self._erro(400, "informe o alvo")
            prof = max(0, min(3, int(dados.get("profundidade", 1))))
            max_req = max(1, min(300, int(dados.get("max_requisicoes", 40))))
            max_ent = max(1, min(60, int(dados.get("max_entidades", 12))))
            contra = dados.get("contra") or None
        except (ValueError, TypeError):
            return self._erro(400, "parâmetros inválidos")
        nome = self.estado.iniciar(alvo, prof, max_req, max_ent, contra)
        return self._json(202, {"id": nome, "tipo": detectar_tipo(alvo)})


def criar_servidor(base: str, porta: int) -> ThreadingHTTPServer:
    estado = Estado(base, porta)
    manip = type("ManipuladorGarimpo", (Manipulador,), {"estado": estado})
    srv = ThreadingHTTPServer(("127.0.0.1", porta), manip)
    estado.porta = srv.server_address[1]  # porta 0 → porta real (testes)
    srv.estado = estado
    return srv


def servir(base: str = "casos", porta: int = 8765, abrir: bool = True) -> int:
    srv = criar_servidor(base, porta)
    url = f"http://127.0.0.1:{srv.estado.porta}/"
    print(f"⛏️  GARIMPO {VERSAO} · painel em {url}  (casos: {srv.estado.base})")
    print("    Só este computador acessa (127.0.0.1). Ctrl+C para encerrar.")
    if abrir:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nPainel encerrado.")
    finally:
        srv.server_close()
    return 0
