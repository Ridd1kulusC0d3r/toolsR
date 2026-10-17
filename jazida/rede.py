# -*- coding: utf-8 -*-
"""Cliente HTTP stdlib com orçamento, cache por execução, cortesia por host e
rastreio de evidência (qual registro do ledger sustenta cada fato)."""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import VERSAO

USER_AGENT = f"GARIMPO/{VERSAO} (DEIVOSINT; OSINT passivo; +https://github.com/Ridd1kulusC0d3r/toolsR)"
TIMEOUT = 15
CORTESIA = 0.35  # segundos mínimos entre duas requisições ao mesmo host


class Orcamento:
    """Tetos não negociáveis. `reservar()` é atômico (motor paralelo)."""

    def __init__(self, max_requisicoes: int = 30, max_entidades: int = 12, profundidade: int = 1):
        self.max_requisicoes = max_requisicoes
        self.max_entidades = max_entidades
        self.profundidade = profundidade
        self.requisicoes = 0
        self._lock = threading.Lock()

    def pode_requisitar(self) -> bool:
        return self.requisicoes < self.max_requisicoes

    def reservar(self) -> bool:
        with self._lock:
            if self.requisicoes >= self.max_requisicoes:
                return False
            self.requisicoes += 1
            return True


class Cliente:
    def __init__(self, custodia, orcamento: Orcamento, silencioso: bool = False,
                 cortesia: float = CORTESIA, log=None):
        self.custodia = custodia
        self.orc = orcamento
        self.silencioso = silencioso
        self.cortesia = cortesia
        self.log = log or (lambda msg: print(msg))
        self._cache: dict[str, tuple[int, bytes, int]] = {}
        self._cache_lock = threading.Lock()
        self._url_locks: dict[str, threading.Lock] = {}
        self._hosts: dict[str, float] = {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._local = threading.local()

    # --- rastreio de evidência -------------------------------------------
    def iniciar_rastreio(self) -> None:
        self._local.seqs = []

    def encerrar_rastreio(self) -> list[int]:
        seqs = getattr(self._local, "seqs", [])
        self._local.seqs = []
        return sorted(set(seqs))

    def _anotar(self, seq: int) -> None:
        if hasattr(self._local, "seqs"):
            self._local.seqs.append(seq)

    # --- cortesia --------------------------------------------------------
    def _esperar_host(self, url: str) -> None:
        host = urllib.parse.urlparse(url).hostname or ""
        with self._cache_lock:
            lock = self._host_locks.setdefault(host, threading.Lock())
        with lock:
            espera = self._hosts.get(host, 0) + self.cortesia - time.monotonic()
            if espera > 0:
                time.sleep(espera)
            self._hosts[host] = time.monotonic()

    # --- núcleo ----------------------------------------------------------
    def get(self, fonte: str, url: str, accept: str = "application/json"):
        """GET → (status, corpo) e custódia. Nunca levanta. Cache por URL."""
        with self._cache_lock:
            url_lock = self._url_locks.setdefault(url, threading.Lock())
        with url_lock:  # a mesma URL pedida em paralelo sai uma vez só
            if url in self._cache:
                status, corpo, seq = self._cache[url]
                self._anotar(seq)
                return status, corpo
            if not self.orc.reservar():
                return None, b""
            self._esperar_host(url)
            if not self.silencioso:
                self.log(f"  → [{fonte}] {url}")
            try:
                status, corpo = self._buscar(url, accept)
            except Exception as e:  # DNS, timeout, TLS, proxy…
                reg = self.custodia.registrar(fonte, url, f"ERRO: {e}".encode(), 0)
                self._cache[url] = (0, b"", reg["seq"])
                self._anotar(reg["seq"])
                return 0, b""
            reg = self.custodia.registrar(fonte, url, corpo, status)
            self._cache[url] = (status, corpo, reg["seq"])
            self._anotar(reg["seq"])
            return status, corpo

    def _buscar(self, url: str, accept: str) -> tuple[int, bytes]:
        """A única linha que fala com a rede. Subclasses (demo, testes) trocam isto."""
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                corpo = e.read() if e.fp else b""
            except Exception:
                corpo = b""
            return e.code, corpo

    def get_json(self, fonte: str, url: str):
        status, corpo = self.get(fonte, url)
        if status != 200 or not corpo:
            return None
        try:
            return json.loads(corpo.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None

    def get_texto(self, fonte: str, url: str, accept: str = "*/*"):
        status, corpo = self.get(fonte, url, accept=accept)
        if status != 200:
            return None
        return corpo.decode("utf-8", errors="replace")


def log_stderr(msg: str) -> None:
    print(msg, file=sys.stderr)
