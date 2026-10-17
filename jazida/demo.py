# -*- coding: utf-8 -*-
"""Demonstração 100% offline, gerada pelo MOTOR REAL.

Um ClienteOffline troca só a linha que fala com a rede (`_buscar`) por
respostas sintéticas no formato real de cada API. Todo o resto — detecção,
fontes, pivô, custódia, dossiê, diff — roda de verdade.

Gera duas coletas do mesmo alvo fictício (exemplo.com.br) com uma semana de
diferença, e o dossiê da mais nova mostra o que mudou: um subdomínio novo
(staging), uma porta nova na Shodan (8443) e um sócio que entrou no QSA.
Todos os dados são fictícios; IPs e ASN são das faixas reservadas para
documentação (RFC 5737 / RFC 5398).
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.parse

from .dossie import gerar_dossie
from .monitor import comparar
from .motor import investigar, salvar_caso
from .rede import Cliente, Orcamento

SEED = "exemplo.com.br"


def _universo(semana: int) -> dict:
    nova = semana >= 2
    subs = ["app.exemplo.com.br", "vpn.exemplo.com.br"] + (["staging.exemplo.com.br"] if nova else [])
    socios = [{"nome_socio": "FULANA DE TAL EXEMPLO", "qualificacao_socio": "Sócio-Administrador"}]
    if nova:
        socios.append({"nome_socio": "BELTRANO EXEMPLO", "qualificacao_socio": "Sócio"})
    return {
        "rdap.registro.br/domain/exemplo.com.br": {
            "events": [{"eventAction": "registration", "eventDate": "2019-03-04T12:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2027-03-04T12:00:00Z"}],
            "status": ["active"],
            "nameservers": [{"ldhName": "ns1.provedor-exemplo.net"}, {"ldhName": "ns2.provedor-exemplo.net"}],
            "entities": [{"roles": ["registrant"],
                          "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "EMPRESA EXEMPLO LTDA"]]],
                          "publicIds": [{"type": "cnpj", "identifier": "11.222.333/0001-81"}]}]},
        "dns:exemplo.com.br:A": {"Answer": [{"type": 1, "data": "203.0.113.10"}]},
        "dns:exemplo.com.br:MX": {"Answer": [{"type": 15, "data": "10 mail.exemplo.com.br."}]},
        "dns:exemplo.com.br:NS": {"Answer": [{"type": 2, "data": "ns1.provedor-exemplo.net."}]},
        "dns:exemplo.com.br:TXT": {"Answer": [{"type": 16, "data": "\"v=spf1 include:_spf.provedor-exemplo.net -all\""}]},
        "dns:exemplo.com.br:CAA": {"Answer": [{"type": 257, "data": "0 issue \"letsencrypt.org\""}]},
        "dns:_dmarc.exemplo.com.br:TXT": {"Answer": [{"type": 16, "data": "\"v=DMARC1; p=quarantine\""}]},
        "crt.sh": [{"name_value": "\n".join(subs + ["*.exemplo.com.br"])}],
        "api.certspotter.com": [{"dns_names": subs}],
        "web.archive.org/cdx:1": [["timestamp", "original"], ["20190312000000", "http://exemplo.com.br/"]],
        "web.archive.org/cdx:-1": [["timestamp", "original"], [f"202609{23 + semana * 7:02d}000000" if semana == 1
                                                                else "20261007000000", "https://exemplo.com.br/"]],
        "urlscan.io": {"total": 1, "results": [{"task": {"time": "2026-09-30T10:00:00Z"},
                                                "page": {"url": "https://exemplo.com.br/", "ip": "203.0.113.10",
                                                         "asnname": "EXEMPLO-AS", "server": "nginx"}}]},
        "brasilapi.com.br/api/cnpj": {
            "razao_social": "EMPRESA EXEMPLO LTDA", "nome_fantasia": "EXEMPLO",
            "descricao_situacao_cadastral": "ATIVA", "data_inicio_atividade": "2018-11-20",
            "natureza_juridica": "Sociedade Empresária Limitada", "porte": "MICRO EMPRESA",
            "cnae_fiscal_descricao": "Desenvolvimento de programas de computador sob encomenda",
            "opcao_pelo_simples": True, "descricao_tipo_de_logradouro": "PRAÇA", "logradouro": "DA SÉ",
            "numero": "1", "bairro": "SÉ", "municipio": "SÃO PAULO", "uf": "SP", "cep": "01001000",
            "email": "contato@exemplo.com.br", "ddd_telefone_1": "1130000000", "qsa": socios},
        "brasilapi.com.br/api/cep": {"cep": "01001000", "state": "SP", "city": "São Paulo",
                                     "neighborhood": "Sé", "street": "Praça da Sé",
                                     "location": {"coordinates": {"latitude": "-23.5503", "longitude": "-46.6339"}}},
        "rdap.org/ip/203.0.113.10": {"name": "TEST-NET-3", "startAddress": "203.0.113.0",
                                     "endAddress": "203.0.113.255", "country": "BR",
                                     "entities": [{"roles": ["registrant"]}]},
        "internetdb.shodan.io/203.0.113.10": {"cpes": ["cpe:/a:nginx:nginx"], "hostnames": ["exemplo.com.br"],
                                              "ip": "203.0.113.10", "ports": [443, 8443] if nova else [443],
                                              "tags": [], "vulns": []},
        "prefix-overview": {"data": {"resource": "203.0.113.0/24", "announced": True,
                                     "asns": [{"asn": 64500, "holder": "EXEMPLO-AS — documentação RFC 5398"}]}},
        "as-overview": {"data": {"holder": "EXEMPLO-AS — documentação RFC 5398", "announced": True}},
        "announced-prefixes": {"data": {"prefixes": [{"prefix": "203.0.113.0/24"}, {"prefix": "2001:db8::/32"}]}},
        "torbulkexitlist": "198.51.100.7\n198.51.100.8\n",
    }


class ClienteOffline(Cliente):
    semana = 1

    def _buscar(self, url: str, accept: str):
        u = _universo(self.semana)
        p = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(p.query))
        if p.hostname == "dns.google":
            chave = f"dns:{q.get('name')}:{q.get('type')}"
        elif p.hostname == "web.archive.org":
            chave = f"web.archive.org/cdx:{q.get('limit')}" if q.get("url") == SEED else None
        elif p.hostname == "stat.ripe.net":
            chave = p.path.split("/")[2]
        elif p.hostname in ("crt.sh", "api.certspotter.com", "urlscan.io") and SEED != (
                q.get("domain") or q.get("q", "").replace("domain:", "").replace("%.", "")):
            vazio = {"results": [], "total": 0} if p.hostname == "urlscan.io" else []
            return 200, json.dumps(vazio).encode()
        else:
            chave = next((k for k in u if (p.hostname + p.path).startswith(k) or p.hostname == k
                          or k in (p.hostname + p.path)), None)
        if chave in u:
            dado = u[chave]
            corpo = dado.encode() if isinstance(dado, str) else json.dumps(dado, ensure_ascii=False).encode()
            return 200, corpo
        return 404, b'{"detail": "Not Found"}'


def rodar_demo(base: str = "casos") -> str:
    """Cria base/demo-anterior e base/demo; devolve o caminho do dossiê novo."""
    casos = []
    for semana, nome in ((1, "demo-anterior"), (2, "demo")):
        d = os.path.join(base, nome)
        if os.path.isdir(d):
            shutil.rmtree(d)  # só as pastas que a própria demo cria
        os.makedirs(d)

        class C(ClienteOffline):
            pass
        C.semana = semana
        caso = investigar(SEED, Orcamento(max_requisicoes=140, max_entidades=15, profundidade=2), d,
                          silencioso=True, paralelo=1, cliente_cls=lambda *a, **k: C(*a, cortesia=0, **k))
        caso["iniciado_utc"] = f"2026-10-{1 + (semana - 1) * 7:02d}T09:00:00+00:00"
        caso["ferramenta"] += " · DEMO offline (dados fictícios)"
        salvar_caso(caso, d)
        casos.append((caso, d))
    (antes, _), (depois, d) = casos
    gerar_dossie(antes, casos[0][1])
    diff = comparar(antes, depois)
    with open(os.path.join(d, "diff.json"), "w", encoding="utf-8") as f:
        json.dump(diff, f, ensure_ascii=False, indent=2)
    return gerar_dossie(depois, d, diff=diff)
