# -*- coding: utf-8 -*-
"""Cadeia de custódia: evidência bruta + ledger JSONL hash-encadeado (SHA-256).

Cada registro guarda o SHA-256 dos bytes recebidos e o hash do registro
anterior; o hash do registro é o SHA-256 do JSON canônico. Mudou um byte de
qualquer evidência ou registro → a corrente quebra dali em diante.
Thread-safe: o motor 2.0 consulta fontes em paralelo.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import threading

GENESE = "0" * 64


def _canonico(reg: dict) -> bytes:
    return json.dumps(reg, sort_keys=True, ensure_ascii=False).encode()


class Custodia:
    def __init__(self, caso_dir: str):
        self.caso_dir = caso_dir
        self.evid_dir = os.path.join(caso_dir, "evidencias")
        os.makedirs(self.evid_dir, exist_ok=True)
        self.ledger_path = os.path.join(caso_dir, "ledger.jsonl")
        self._lock = threading.Lock()
        self._ultimo_hash = GENESE
        self.seq = 0
        if os.path.exists(self.ledger_path):  # retoma um caso existente
            with open(self.ledger_path, encoding="utf-8") as f:
                for linha in f:
                    if linha.strip():
                        self._ultimo_hash = json.loads(linha)["hash_registro"]
                        self.seq += 1

    def registrar(self, fonte: str, url: str, corpo: bytes, status: int) -> dict:
        sha = hashlib.sha256(corpo).hexdigest()
        with self._lock:
            self.seq += 1
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
            reg["hash_registro"] = hashlib.sha256(_canonico(reg)).hexdigest()
            self._ultimo_hash = reg["hash_registro"]
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(reg, ensure_ascii=False) + "\n")
        return reg

    @staticmethod
    def ler_ledger(caso_dir: str) -> list[dict]:
        caminho = os.path.join(caso_dir, "ledger.jsonl")
        if not os.path.exists(caminho):
            return []
        with open(caminho, encoding="utf-8") as f:
            return [json.loads(linha) for linha in f if linha.strip()]

    @staticmethod
    def verificar(caso_dir: str) -> tuple[bool, list[str]]:
        problemas: list[str] = []
        ledger = os.path.join(caso_dir, "ledger.jsonl")
        if not os.path.exists(ledger):
            return False, ["ledger.jsonl não encontrado"]
        anterior = GENESE
        with open(ledger, encoding="utf-8") as f:
            linhas = [linha for linha in f if linha.strip()]
        for n, linha in enumerate(linhas, 1):
            try:
                reg = json.loads(linha)
                hash_decl = reg.pop("hash_registro")
            except (json.JSONDecodeError, KeyError):
                problemas.append(f"linha {n}: registro ilegível")
                continue
            if hashlib.sha256(_canonico(reg)).hexdigest() != hash_decl:
                problemas.append(f"linha {n}: hash do registro não confere")
            if reg.get("hash_anterior") != anterior:
                problemas.append(f"linha {n}: corrente quebrada (hash_anterior)")
            anterior = hash_decl
            arq = os.path.join(caso_dir, "evidencias", os.path.basename(str(reg.get("arquivo", ""))))
            if not os.path.isfile(arq):
                problemas.append(f"linha {n}: evidência ausente ({reg.get('arquivo')})")
                continue
            with open(arq, "rb") as ef:
                if hashlib.sha256(ef.read()).hexdigest() != reg.get("sha256_evidencia"):
                    problemas.append(f"linha {n}: evidência adulterada ({reg['arquivo']})")
        return (not problemas), problemas
