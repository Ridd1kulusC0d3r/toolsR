# -*- coding: utf-8 -*-
"""jazida — o núcleo do GARIMPO 2.0 (família DEIVOSINT). 100% Python stdlib.

Módulos:
  deteccao   tipos de entidade e validadores BR (CPF/CNPJ/CEP/telefone)
  custodia   evidência bruta + ledger SHA-256 hash-encadeado
  rede       cliente HTTP com orçamento, cache, cortesia e rastreio de evidência
  fontes/    plugins de fontes passivas e keyless (registro com tabela de ruído)
  motor      pivô BFS paralelo com fronteira
  dossie     dossiê HTML pt-BR standalone
  exportar   STIX 2.1, GraphML, CSV
  monitor    diff entre coletas
  demo       casos de demonstração offline
  mcp        servidor MCP (stdio, JSON-RPC 2.0)
  painel     painel web local (127.0.0.1)
  cli        linha de comando
"""

VERSAO = "2.0.0"

from .custodia import Custodia  # noqa: E402
from .deteccao import (detectar_tipo, normalizar, validar_cnpj, validar_cpf,  # noqa: E402
                       RE_DOMINIO)
from .fontes import REGISTRO, fontes_para, por_nome, tabela_ruido  # noqa: E402
from .motor import carregar_caso, chave_de, investigar  # noqa: E402
from .rede import Cliente, Orcamento  # noqa: E402

__all__ = ["VERSAO", "Custodia", "detectar_tipo", "normalizar", "validar_cnpj", "validar_cpf",
           "RE_DOMINIO", "REGISTRO", "fontes_para", "por_nome", "tabela_ruido",
           "carregar_caso", "chave_de", "investigar", "Cliente", "Orcamento"]
