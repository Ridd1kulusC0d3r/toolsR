#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suíte de testes do GARIMPO 2.0 — 100% stdlib (unittest), roda offline.

    python3 -m unittest discover -s testes -v        # a partir da raiz do repo

Os parsers das fontes são testados contra fixtures no formato documentado
de cada API, por meio de um cliente falso (sem rede). MCP e painel são
testados de ponta a ponta (subprocesso stdio e servidor HTTP local).
"""

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
import garimpo as g  # noqa: E402  (porta de entrada: re-exporta a API da jazida)
from jazida import exportar as X, monitor as M, dossie as Dz, demo as Dm, motor as Mo  # noqa: E402
from jazida.fontes import (artefatos, brasil, dominio, ip as fip, pessoais)  # noqa: E402
from jazida.mcp import Servidor  # noqa: E402
from jazida.painel import criar_servidor  # noqa: E402


def _ler(caminho):
    with open(caminho, encoding="utf-8") as f:
        return f.read()


def _gravar(caminho, texto):
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(texto)


class ClienteFalso:
    """Imita jazida.rede.Cliente: devolve fixtures por prefixo de URL."""

    def __init__(self, respostas: dict):
        self.respostas = respostas
        self.urls = []

    def get(self, fonte, url, accept="application/json"):
        self.urls.append((fonte, url))
        for prefixo, payload in self.respostas.items():
            if url.startswith(prefixo):
                if isinstance(payload, tuple):
                    return payload
                corpo = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                return 200, corpo
        return 404, b""

    def get_json(self, fonte, url):
        st, corpo = self.get(fonte, url)
        return json.loads(corpo) if st == 200 and corpo else None

    def get_texto(self, fonte, url, accept="*/*"):
        st, corpo = self.get(fonte, url, accept)
        return corpo.decode() if st == 200 else None


class Temp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="garimpo_t_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# =========================================================== detecção
class TestDeteccao(unittest.TestCase):
    CASOS = {
        "529.982.247-25": "cpf", "52998224725": "cpf",
        "11.222.333/0001-81": "cnpj", "11222333000181": "cnpj",
        "111.111.111-11": "documento_invalido", "529.982.247-26": "documento_invalido",
        "11.111.111/1111-11": "documento_invalido",
        "+55 31 99999-8888": "telefone", "(31) 99999-8888": "telefone",
        "5531999998888": "telefone", "12345678901": "telefone",
        "01001-000": "cep", "AS15169": "asn", "as64500": "asn",
        "deivsec@gmail.com": "email", "https://exemplo.com.br/x": "url",
        "8.8.8.8": "ip", "2001:4860:4860::8888": "ip",
        "d41d8cd98f00b204e9800998ecf8427e": "hash",
        "registro.br": "dominio", "sub.dominio.com.br": "dominio",
        "Fulano de Tal": "pessoa", "torvalds": "username",
    }

    def test_matriz(self):
        for valor, esperado in self.CASOS.items():
            with self.subTest(valor=valor):
                self.assertEqual(g.detectar_tipo(valor), esperado)

    def test_cpf_nunca_vira_dominio(self):
        self.assertFalse(g.RE_DOMINIO.match("111.111.111-11"))

    def test_validadores(self):
        self.assertTrue(g.validar_cpf("529.982.247-25"))
        self.assertFalse(g.validar_cpf("000.000.000-00"))
        self.assertTrue(g.validar_cnpj("11.222.333/0001-81"))
        self.assertFalse(g.validar_cnpj("11.222.333/0001-82"))

    def test_normalizacao_deduplica(self):
        self.assertEqual(g.chave_de("cnpj", "11222333000181"), g.chave_de("cnpj", "11.222.333/0001-81"))
        self.assertEqual(g.chave_de("dominio", "Exemplo.COM.br."), g.chave_de("dominio", "exemplo.com.br"))
        self.assertEqual(g.chave_de("asn", "as64500"), "asn:as64500")


# =========================================================== custódia
class TestCustodia(Temp):
    def _popular(self, n=3):
        c = g.Custodia(self.dir)
        for i in range(n):
            c.registrar("teste", f"demo://{i}", f"corpo {i}".encode(), 200)
        return c

    def test_integra(self):
        self._popular()
        self.assertTrue(g.Custodia.verificar(self.dir)[0])

    def test_adulteracao_de_evidencia(self):
        self._popular()
        evid = os.path.join(self.dir, "evidencias")
        with open(os.path.join(evid, sorted(os.listdir(evid))[1]), "ab") as f:
            f.write(b"!")
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("linha 2" in p and "adulterada" in p for p in prob), prob)

    def test_adulteracao_do_ledger(self):
        self._popular()
        led = os.path.join(self.dir, "ledger.jsonl")
        linhas = _ler(led).splitlines()
        reg = json.loads(linhas[0])
        reg["url"] = "demo://forjado"
        linhas[0] = json.dumps(reg, ensure_ascii=False)
        _gravar(led, "\n".join(linhas) + "\n")
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("linha 1" in p for p in prob), prob)

    def test_remocao_de_registro_quebra_corrente(self):
        self._popular()
        led = os.path.join(self.dir, "ledger.jsonl")
        linhas = _ler(led).splitlines()
        del linhas[1]
        _gravar(led, "\n".join(linhas) + "\n")
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("corrente quebrada" in p for p in prob), prob)

    def test_retomar_caso_continua_corrente(self):
        self._popular(2)
        c2 = g.Custodia(self.dir)
        self.assertEqual(c2.seq, 2)
        c2.registrar("teste", "demo://3", b"x", 200)
        self.assertTrue(g.Custodia.verificar(self.dir)[0])

    def test_concorrencia_mantem_corrente(self):
        c = g.Custodia(self.dir)
        ts = [threading.Thread(target=lambda i=i: c.registrar("t", f"demo://{i}", str(i).encode(), 200)) for i in range(40)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertTrue(ok, prob)
        self.assertEqual(len(g.Custodia.ler_ledger(self.dir)), 40)


# =========================================================== rede
class ClienteContador(g.Cliente):
    chamadas = 0

    def _buscar(self, url, accept):
        type(self).chamadas += 1
        return 200, b'{"ok": true}'


class TestRede(Temp):
    def test_teto_duro_de_requisicoes(self):
        orc = g.Orcamento(max_requisicoes=0)
        cli = g.Cliente(g.Custodia(self.dir), orc, silencioso=True)
        self.assertIsNone(cli.get_json("x", "https://exemplo.invalid/"))
        self.assertEqual(orc.requisicoes, 0)

    def test_cache_e_rastreio_de_evidencia(self):
        ClienteContador.chamadas = 0
        cli = ClienteContador(g.Custodia(self.dir), g.Orcamento(10), silencioso=True, cortesia=0)
        cli.iniciar_rastreio()
        cli.get_json("x", "https://a.invalid/1")
        cli.get_json("x", "https://a.invalid/1")  # mesma URL: cache
        cli.get_json("x", "https://a.invalid/2")
        self.assertEqual(ClienteContador.chamadas, 2)
        self.assertEqual(cli.encerrar_rastreio(), [1, 2])

    def test_erro_de_rede_vai_para_custodia(self):
        class Quebrado(g.Cliente):
            def _buscar(self, url, accept):
                raise OSError("sem rede")
        cli = Quebrado(g.Custodia(self.dir), g.Orcamento(5), silencioso=True, cortesia=0)
        self.assertIsNone(cli.get_json("x", "https://a.invalid/"))
        reg = g.Custodia.ler_ledger(self.dir)[0]
        self.assertEqual(reg["status_http"], 0)
        self.assertTrue(g.Custodia.verificar(self.dir)[0])


# =========================================================== fontes
RDAP_BR = {
    "events": [{"eventAction": "registration", "eventDate": "1997-04-20T00:00:00Z"}],
    "nameservers": [{"ldhName": "a.dns.br"}],
    "entities": [{"roles": ["registrant"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Núcleo de Informação"]]],
                  "publicIds": [{"type": "cnpj", "identifier": "11.222.333/0001-81"}]},
                 {"roles": ["technical"], "publicIds": [{"type": "cpf", "identifier": "529.982.247-25"}]}],
}


def _pgp_armadura(uids):
    corpo = bytes([0x99, 0x00, 0x04]) + b"\x04abc"  # pacote de chave pública (formato antigo, tag 6)
    for u in uids:
        b = u.encode()
        corpo += bytes([0xC0 | 13, len(b)]) + b  # User ID (formato novo, tag 13)
    linhas = base64.b64encode(corpo).decode()
    return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: teste\n\n{linhas}\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"


class TestFontesDominio(unittest.TestCase):
    def test_rdap_br_pivota_cnpj_e_nunca_cpf(self):
        cli = ClienteFalso({"https://rdap.registro.br/": RDAP_BR})
        fatos, novas = dominio.rdap_dominio(cli, "registro.br")
        self.assertIn(("cnpj", "11.222.333/0001-81", "titular_do_dominio", 0.9), novas)
        self.assertFalse(any(t == "cpf" for t, *_ in novas))
        self.assertFalse(any("529" in f for f in fatos), "CPF não pode aparecer nos fatos")
        self.assertTrue(any("pessoa física" in f for f in fatos))
        self.assertIn(("dominio", "a.dns.br", "nameserver_de", 0.5), novas)

    def test_rdap_nao_br_usa_rdap_org(self):
        cli = ClienteFalso({})
        dominio.rdap_dominio(cli, "example.com")
        self.assertTrue(cli.urls[0][1].startswith("https://rdap.org/domain/"))

    def test_dns_completo(self):
        base = "https://dns.google/resolve?name=exemplo.com.br&type="
        cli = ClienteFalso({
            base + "AAAA": {"Answer": [{"type": 28, "data": "2001:db8::1"}]},  # antes de "A": casamento por prefixo
            base + "A": {"Answer": [{"type": 1, "data": "200.160.2.3"}]},
            base + "MX": {"Answer": [{"type": 15, "data": "10 mx.exemplo.com.br."}]},
            base + "TXT": {"Answer": [{"type": 16, "data": "\"v=spf1 include:_spf.google.com -all\""}]},
            base + "CAA": {"Answer": [{"type": 257, "data": "0 issue \"letsencrypt.org\""}]},
            "https://dns.google/resolve?name=_dmarc": {"Answer": [{"type": 16, "data": "\"v=DMARC1; p=reject\""}]},
        })
        fatos, novas = dominio.dns(cli, "exemplo.com.br")
        t = " | ".join(fatos)
        self.assertIn("SPF delega envio a: _spf.google.com", t)
        self.assertIn("autoridade certificadora autorizada: letsencrypt.org", t)
        self.assertIn("DMARC: v=DMARC1; p=reject", t)
        self.assertIn(("ip", "2001:db8::1", "resolve_para", 0.9), novas)
        self.assertIn(("dominio", "mx.exemplo.com.br", "servidor_de_email", 0.7), novas)

    def test_ct_crtsh_e_certspotter(self):
        cli = ClienteFalso({"https://crt.sh/": [{"name_value": "www.x.com.br\n*.x.com.br"}],
                            "https://api.certspotter.com/": [{"dns_names": ["api.x.com.br", "x.com.br"]}]})
        _, n1 = dominio.crtsh(cli, "x.com.br")
        _, n2 = dominio.certspotter(cli, "x.com.br")
        self.assertEqual([v for _, v, *_ in n1], ["www.x.com.br"])
        self.assertEqual([v for _, v, *_ in n2], ["api.x.com.br"])

    def test_urlscan_ip_nao_pivota(self):
        cli = ClienteFalso({"https://urlscan.io/": {"total": 1, "results": [
            {"task": {"time": "2026-01-01T00:00:00Z"}, "page": {"url": "https://x/", "ip": "198.51.100.1"}}]}})
        fatos, novas = dominio.urlscan(cli, "x.com.br")
        self.assertLess(novas[0][3], Mo.CONFIANCA_PIVO)
        self.assertTrue(any("varreduras públicas" in f for f in fatos))


class TestFontesIP(unittest.TestCase):
    def test_internetdb(self):
        cli = ClienteFalso({"https://internetdb.shodan.io/": {"cpes": ["cpe:/a:x"], "hostnames": ["dns.google"],
                                                              "ip": "8.8.8.8", "ports": [53, 443], "tags": ["cdn"],
                                                              "vulns": ["CVE-2099-0001"]}})
        fatos, novas = fip.internetdb(cli, "8.8.8.8")
        t = " | ".join(fatos)
        for esperado in ("[53, 443]", "CVE-2099-0001", "etiqueta Shodan: cdn", "CPE"):
            self.assertIn(esperado, t)
        self.assertIn(("dominio", "dns.google", "hospedado_em", 0.7), novas)

    def test_internetdb_sem_dados(self):
        cli = ClienteFalso({"https://internetdb.shodan.io/": {"detail": "No information available"}})
        self.assertEqual(fip.internetdb(cli, "10.0.0.1"), ([], []))

    def test_ripestat_ip_e_asn(self):
        cli = ClienteFalso({
            "https://stat.ripe.net/data/prefix-overview": {"data": {"resource": "8.8.8.0/24", "announced": True,
                                                                    "asns": [{"asn": 15169, "holder": "GOOGLE"}]}},
            "https://stat.ripe.net/data/as-overview": {"data": {"holder": "GOOGLE", "announced": True}},
            "https://stat.ripe.net/data/announced-prefixes": {"data": {"prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "2001:4860::/32"}]}},
        })
        fatos, novas = fip.ripestat_ip(cli, "8.8.8.8")
        self.assertIn(("asn", "AS15169", "anunciado_por", 0.9), novas)
        fatos_asn, _ = fip.ripestat_asn(cli, "AS15169")
        self.assertIn("prefixos anunciados: 2 (1 IPv4, 1 IPv6)", fatos_asn)

    def test_tor_lista_baixada_uma_vez(self):
        cli = ClienteFalso({fip.TOR_LISTA: "1.2.3.4\n5.6.7.8\n"})
        self.assertIn("SAÍDA TOR", fip.tor_saida(cli, "1.2.3.4")[0][0])
        self.assertIn("não consta", fip.tor_saida(cli, "9.9.9.9")[0][0])


class TestFontesPessoais(unittest.TestCase):
    def test_parser_openpgp_extrai_uids(self):
        arm = _pgp_armadura(["Fulana Exemplo <fulana@exemplo.com>", "fulana@outro.org"])
        self.assertEqual(pessoais.uids_openpgp(arm), ["Fulana Exemplo <fulana@exemplo.com>", "fulana@outro.org"])

    def test_pgp_pivota_outros_emails(self):
        arm = _pgp_armadura(["Fulana Exemplo <fulana@exemplo.com>", "Fulana <fulana@outro.org>"])
        cli = ClienteFalso({"https://keys.openpgp.org/": arm})
        fatos, novas = pessoais.pgp(cli, "fulana@exemplo.com")
        self.assertIn(("email", "fulana@outro.org", "mesma_chave_pgp", 0.85), novas)
        self.assertIn(("pessoa", "Fulana Exemplo", "nome_na_chave_pgp", 0.6), novas)

    def test_github_e_commits(self):
        cli = ClienteFalso({
            "https://api.github.com/users/exemplo/events": [
                {"type": "PushEvent", "payload": {"commits": [
                    {"author": {"email": "dev@exemplo.com", "name": "Dev"}},
                    {"author": {"email": "123+x@users.noreply.github.com", "name": "x"}}]}}],
            "https://api.github.com/users/": {"login": "exemplo", "html_url": "https://github.com/exemplo",
                                              "name": "Ex Emplo", "email": "ex@exemplo.com", "blog": "exemplo.dev",
                                              "twitter_username": "exemplo_x", "public_repos": 3, "followers": 1,
                                              "created_at": "2015-01-01T00:00:00Z"}})
        _, novas = pessoais.github(cli, "exemplo")
        self.assertIn(("email", "ex@exemplo.com", "email_publico_github", 0.9), novas)
        self.assertIn(("dominio", "exemplo.dev", "site_no_github", 0.7), novas)
        _, nc = pessoais.github_commits(cli, "exemplo")
        self.assertEqual(nc, [("email", "dev@exemplo.com", "email_de_commit", 0.8)])  # noreply filtrado

    def test_keybase_provas(self):
        cli = ClienteFalso({"https://keybase.io/": {"them": [{"profile": {"full_name": "Ex"}, "proofs_summary": {"all": [
            {"proof_type": "twitter", "nametag": "ex_tw", "service_url": "https://twitter.com/ex_tw"},
            {"proof_type": "dns", "nametag": "exemplo.org", "service_url": "dns://exemplo.org"}]}}]}})
        _, novas = pessoais.keybase(cli, "ex")
        self.assertIn(("username", "ex_tw", "provado_no_keybase_twitter", 0.85), novas)
        self.assertIn(("dominio", "exemplo.org", "provado_no_keybase", 0.85), novas)

    def test_hackernews_about(self):
        cli = ClienteFalso({"https://hacker-news.firebaseio.com/": {
            "id": "ex", "created": 1300000000, "karma": 42,
            "about": "contato: ex&#x40;exemplo.com <a href=\"https://exemplo.org\">site</a>"}})
        fatos, novas = pessoais.hackernews(cli, "ex")
        self.assertIn(("email", "ex@exemplo.com", "email_no_perfil_hn", 0.7), novas)
        self.assertTrue(fatos[0].startswith("conta no Hacker News desde 2011"))

    def test_email_local_e_gravatar(self):
        _, novas = pessoais.email_local(None, "fulano@exemplo.com.br")
        self.assertIn(("dominio", "exemplo.com.br", "dominio_do_email", 1.0), novas)
        cli = ClienteFalso({"https://en.gravatar.com/": {"entry": [{"displayName": "Fulano", "preferredUsername": "fulano",
                                                                    "accounts": [{"shortname": "github", "url": "u", "username": "fulano-gh"}]}]}})
        _, ng = pessoais.gravatar(cli, "fulano@exemplo.com.br")
        self.assertIn(("username", "fulano-gh", "conta_github", 0.7), ng)


class TestFontesBrasil(unittest.TestCase):
    BRASILAPI = {"razao_social": "EMPRESA EXEMPLO LTDA", "descricao_situacao_cadastral": "ATIVA",
                 "data_inicio_atividade": "2010-01-01", "municipio": "BELO HORIZONTE", "uf": "MG",
                 "cep": "30130110", "email": "contato@exemplo.com.br", "ddd_telefone_1": "3130000000",
                 "opcao_pelo_simples": True,
                 "qsa": [{"nome_socio": "FULANO DE TAL", "qualificacao_socio": "Sócio-Administrador"}]}

    def test_cnpj_completo(self):
        cli = ClienteFalso({"https://brasilapi.com.br/api/cnpj": self.BRASILAPI})
        fatos, novas = brasil.brasilapi_cnpj(cli, "11.222.333/0001-81")
        self.assertTrue(cli.urls[0][1].endswith("/11222333000181"))
        for n in [("organizacao", "EMPRESA EXEMPLO LTDA", "razao_social", 0.9),
                  ("pessoa", "FULANO DE TAL", "socio_de", 0.9), ("cep", "30130-110", "endereco_da_empresa", 0.7),
                  ("email", "contato@exemplo.com.br", "email_cadastral", 0.8)]:
            self.assertIn(n, novas)
        self.assertIn("optante pelo Simples Nacional", fatos)

    def test_cep(self):
        cli = ClienteFalso({"https://brasilapi.com.br/api/cep/v2/": {"city": "Belo Horizonte", "state": "MG",
                                                                     "street": "Av. Afonso Pena", "neighborhood": "Centro",
                                                                     "location": {"coordinates": {"latitude": "-19.9", "longitude": "-43.9"}}}})
        fatos, _ = brasil.brasilapi_cep(cli, "30130-110")
        self.assertIn("coordenadas aproximadas: -19.9, -43.9", fatos)

    def test_cpf_e_telefone_offline(self):
        cli = ClienteFalso({})
        fatos, novas = brasil.cpf_offline(cli, "529.982.247-25")
        self.assertEqual((cli.urls, novas), ([], []))
        ft, _ = brasil.telefone_offline(cli, "+55 31 99999-8888")
        self.assertIn("Brasil · DDD 31 (MG)", ft)
        self.assertTrue(any("celular" in f for f in ft))


class TestFontesArtefatos(unittest.TestCase):
    def test_hashlookup_conhecido_e_desconhecido(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        cli = ClienteFalso({"https://hashlookup.circl.lu/": {"FileName": "vazio.txt", "FileSize": "0"}})
        self.assertTrue(any("CONHECIDO" in f for f in artefatos.circl_hashlookup(cli, h)[0]))
        cli2 = ClienteFalso({"https://hashlookup.circl.lu/": (404, b'{"message":"Non existing"}')})
        self.assertTrue(any("NÃO significa malicioso" in f for f in artefatos.circl_hashlookup(cli2, h)[0]))

    def test_registro_tem_tabela_de_ruido_completa(self):
        nomes = [f.nome for f in g.REGISTRO]
        self.assertEqual(len(nomes), len(set(nomes)))
        self.assertGreaterEqual(len(nomes), 28)
        for f in g.REGISTRO:
            self.assertTrue(f.destino and f.descricao)


# =========================================================== motor, dossiê, demo
class TestMotor(Temp):
    def test_bfs_profundidade_confianca_e_fronteira(self):
        originais = list(g.REGISTRO)
        try:
            g.REGISTRO.clear()
            from jazida.fontes import Fonte
            g.REGISTRO.append(Fonte("falsa_dom", ("dominio",), "offline", "-", "-", lambda c, v: (
                [f"visto {v}"], [("ip", "203.0.113.1", "resolve_para", 0.9), ("dominio", "fraco.exemplo.com", "palpite", 0.3)])))
            g.REGISTRO.append(Fonte("falsa_ip", ("ip",), "offline", "-", "-", lambda c, v: (
                ["ip ok"], [("dominio", "nivel2.exemplo.com", "hospedado_em", 0.9)])))
            caso = g.investigar("seed.exemplo.com", g.Orcamento(30, 10, 1), self.dir, silencioso=True)
            nos = caso["grafo"]["nos"]
            self.assertTrue(nos["ip:203.0.113.1"]["investigado"])
            self.assertFalse(nos["dominio:nivel2.exemplo.com"]["investigado"])  # fronteira (prof 2)
            self.assertFalse(nos["dominio:fraco.exemplo.com"]["investigado"])   # confiança baixa
            html = _ler(Dz.gerar_dossie(caso, self.dir))
            self.assertIn("<svg", html)
            self.assertIn(f"verificar {self.dir}", html)
            self.assertIn("Fronteira (2)", html)
        finally:
            g.REGISTRO[:] = originais

    def test_fonte_quebrada_nao_derruba(self):
        originais = list(g.REGISTRO)
        try:
            g.REGISTRO.clear()
            from jazida.fontes import Fonte

            def quebra(c, v):
                raise RuntimeError("bum")
            g.REGISTRO.append(Fonte("quebrada", ("dominio",), "offline", "-", "-", quebra))
            caso = g.investigar("x.exemplo.com", g.Orcamento(5, 5, 1), self.dir, silencioso=True)
            self.assertIn("falha interna da fonte", caso["grafo"]["nos"]["dominio:x.exemplo.com"]["fatos"][0]["fato"])
        finally:
            g.REGISTRO[:] = originais

    def test_migracao_de_caso_1x(self):
        antigo = {"seed": "a.com", "tipo_seed": "dominio", "iniciado_utc": "2026-10-15T00:00:00+00:00",
                  "grafo": {"nos": {"dominio:a.com": {"tipo": "dominio", "valor": "a.com", "profundidade": 0,
                                                      "fatos": [{"fonte": "dns", "fato": "A: 1.2.3.4"}]}}, "arestas": []}}
        c = Mo.migrar(antigo)
        self.assertEqual(c["versao_esquema"], 2)
        self.assertTrue(c["grafo"]["nos"]["dominio:a.com"]["investigado"])

    def test_dossie_escapa_html(self):
        caso = {"seed": "<script>x</script>", "tipo_seed": "username", "iniciado_utc": "2026-10-15T00:00:00+00:00",
                "duracao_s": 0, "orcamento": {"requisicoes_feitas": 0, "max_requisicoes": 0},
                "grafo": {"no_seed": "username:<script>x</script>", "nos": {"username:<script>x</script>": {
                    "tipo": "username", "valor": "<script>x</script>", "profundidade": 0, "investigado": True,
                    "fatos": [{"fonte": "t", "fato": "<img src=x onerror=alert(1)>", "evidencias": []}]}}, "arestas": []}}
        html = _ler(Dz.gerar_dossie(caso, self.dir))
        self.assertNotIn("<script>x</script>", html)
        self.assertNotIn("<img src=x", html)


class TestDemo(Temp):
    def test_demo_motor_real_com_diff(self):
        caminho = Dm.rodar_demo(self.dir)
        Dm.rodar_demo(self.dir)  # idempotente
        d = os.path.join(self.dir, "demo")
        self.assertTrue(g.Custodia.verificar(d)[0])
        caso = g.carregar_caso(d)
        nos = caso["grafo"]["nos"]
        self.assertTrue(nos["cnpj:11.222.333/0001-81"]["investigado"])  # pivô RDAP .br → CNPJ
        self.assertIn("asn:as64500", nos)
        diff = json.loads(_ler(os.path.join(d, "diff.json")))
        self.assertIn("dominio:staging.exemplo.com.br", diff["entidades_novas"])
        self.assertIn("pessoa:beltrano exemplo", diff["entidades_novas"])
        self.assertIn("Mudanças desde", _ler(caminho))
        # cada fato aponta para evidência real do ledger
        seqs = {r["seq"] for r in g.Custodia.ler_ledger(d)}
        for n in nos.values():
            for f in n["fatos"]:
                self.assertTrue(set(f["evidencias"]) <= seqs)


# =========================================================== exportações e diff
class TestExportar(Temp):
    def setUp(self):
        super().setUp()
        Dm.rodar_demo(self.dir)
        self.d = os.path.join(self.dir, "demo")
        self.caso = g.carregar_caso(self.d)

    def test_stix21(self):
        b = X.stix(self.caso)
        self.assertEqual(b["type"], "bundle")
        tipos = {o["type"] for o in b["objects"]}
        for t in ("identity", "domain-name", "ipv4-addr", "autonomous-system", "email-addr", "location",
                  "relationship", "note", "grouping"):
            self.assertIn(t, tipos)
        ids = {o["id"] for o in b["objects"]}
        for o in b["objects"]:
            self.assertRegex(o["id"], r"^[a-z0-9-]+--[0-9a-f-]{36}$")
            self.assertEqual(o.get("spec_version", "2.1"), "2.1")
            if o["type"] == "relationship":
                self.assertIn(o["source_ref"], ids)
                self.assertIn(o["target_ref"], ids)
        dom = next(o for o in b["objects"] if o["type"] == "domain-name" and o["value"] == "exemplo.com.br")
        self.assertEqual(dom["id"], X.stix(self.caso)["objects"][[o.get("value") for o in X.stix(self.caso)["objects"]].index("exemplo.com.br")]["id"])

    def test_stix_nunca_exporta_cpf(self):
        caso = json.loads(json.dumps(self.caso))
        caso["grafo"]["nos"]["cpf:529.982.247-25"] = {"tipo": "cpf", "valor": "529.982.247-25", "profundidade": 1,
                                                      "investigado": True, "fatos": []}
        self.assertNotIn("529.982.247-25", json.dumps(X.stix(caso)))
        self.assertNotIn("529.982.247-25", X.graphml(caso))

    def test_graphml_e_csv(self):
        raiz = ET.fromstring(X.graphml(self.caso).split("\n", 1)[1])
        ns = "{http://graphml.graphdrawing.org/xmlns}"
        self.assertEqual(len(raiz.findall(f".//{ns}node")), len(self.caso["grafo"]["nos"]))
        ent, vin = X.exportar(self.caso, self.d, "csv")
        self.assertIn("chave,tipo,valor", _ler(ent).lstrip("﻿"))
        self.assertGreater(len(_ler(vin).splitlines()), 5)

    def test_diff_sem_mudancas(self):
        d = M.comparar(self.caso, self.caso)
        self.assertEqual(d["total_mudancas"], 0)
        self.assertIn("nada mudou", M.relatorio_texto(d))


# =========================================================== MCP
class TestMCP(Temp):
    def test_protocolo_stdio(self):
        Dm.rodar_demo(self.dir)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "garimpo_verificar", "arguments": {"caso": "demo"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "garimpo_caso", "arguments": {"caso": "../../etc"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "garimpo_comparar",
                                                                          "arguments": {"caso_antes": "demo-anterior", "caso_depois": "demo"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "metodo/inexistente"},
        ]
        entrada = "\n".join(json.dumps(m) for m in msgs) + "\nlixo\n"
        p = subprocess.run([sys.executable, os.path.join(RAIZ, "garimpo.py"), "mcp", "--casos", self.dir],
                           input=entrada, capture_output=True, text=True, timeout=60)
        resp = [json.loads(linha) for linha in p.stdout.splitlines()]  # stdout só tem JSON-RPC
        por_id = {r.get("id"): r for r in resp}
        self.assertEqual(len(resp), 7)  # notificação não responde
        self.assertEqual(por_id[1]["result"]["serverInfo"]["name"], "garimpo")
        self.assertGreaterEqual(len(por_id[2]["result"]["tools"]), 8)
        self.assertIn("ÍNTEGRA", por_id[3]["result"]["content"][0]["text"])
        self.assertTrue(por_id[4]["result"]["isError"])
        self.assertIn("staging.exemplo.com.br", por_id[5]["result"]["content"][0]["text"])
        self.assertEqual(por_id[6]["error"]["code"], -32601)
        self.assertEqual(por_id[None]["error"]["code"], -32700)
        self.assertIn("servidor MCP pronto", p.stderr)

    def test_resumo_trunca(self):
        Dm.rodar_demo(self.dir)
        s = Servidor(self.dir)
        texto = s._resumo(g.carregar_caso(os.path.join(self.dir, "demo")), limite=3)
        self.assertIn("truncados", texto)


# =========================================================== painel
class TestPainel(Temp):
    def setUp(self):
        super().setUp()
        Dm.rodar_demo(self.dir)
        self.srv = criar_servidor(self.dir, 0)
        self.porta = self.srv.estado.porta
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def req(self, caminho, metodo="GET", corpo=None, cab=None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.porta}{caminho}", data=corpo, method=metodo,
                                   headers=cab or {})
        try:
            with self.op.open(r, timeout=10) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def test_pagina_e_api(self):
        st, corpo, cab = self.req("/")
        self.assertEqual(st, 200)
        self.assertIn(b"GARIMPO", corpo)
        self.assertIn("frame-ancestors 'none'", cab["Content-Security-Policy"])
        st, corpo, _ = self.req("/api/casos")
        self.assertEqual({c["id"] for c in json.loads(corpo)}, {"demo", "demo-anterior"})
        st, corpo, _ = self.req("/api/casos/demo")
        caso = json.loads(corpo)
        self.assertIn("diff", caso)
        self.assertTrue(caso["ledger"])
        st, corpo, _ = self.req("/api/casos/demo/verificar")
        self.assertTrue(json.loads(corpo)["ok"])
        st, corpo, cab = self.req("/api/casos/demo/exportar/csv")
        self.assertEqual((st, cab["Content-Type"]), (200, "application/zip"))
        st, corpo, cab = self.req("/api/casos/demo/dossie")
        self.assertIn(b"/api/casos/demo/evidencias/", corpo)
        arq = g.Custodia.ler_ledger(os.path.join(self.dir, "demo"))[0]["arquivo"]
        st, _, _ = self.req(f"/api/casos/demo/evidencias/{arq}")
        self.assertEqual(st, 200)

    def test_defesas(self):
        st, _, _ = self.req("/api/casos", cab={"Host": "atacante.example"})
        self.assertEqual(st, 403)  # anti DNS rebinding
        st, _, _ = self.req("/api/investigar", "POST", b'{"alvo":"x.com"}', {"Content-Type": "application/json"})
        self.assertEqual(st, 403)  # anti CSRF: falta X-Garimpo
        st, _, _ = self.req("/api/investigar", "POST", b"alvo=x.com",
                            {"Content-Type": "application/x-www-form-urlencoded", "X-Garimpo": "1"})
        self.assertEqual(st, 403)  # formulário HTML simples não passa
        for caminho in ("/api/casos/..%2F..%2Fetc", "/api/casos/demo/evidencias/..%2Fcaso.json",
                        "/api/casos/demo/evidencias/%2Fetc%2Fpasswd", "/api/casos/demo/exportar/exe"):
            st, _, _ = self.req(caminho)
            self.assertEqual(st, 404, caminho)

    def test_investigar_assincrono(self):
        st, corpo, _ = self.req("/api/investigar", "POST", json.dumps({"alvo": "529.982.247-25", "profundidade": 0}).encode(),
                                {"Content-Type": "application/json", "X-Garimpo": "1"})
        self.assertEqual(st, 202)
        cid = json.loads(corpo)["id"]
        import time
        for _ in range(50):
            caso = json.loads(self.req(f"/api/casos/{cid}")[1])
            if caso.get("status") == "pronto" and "grafo" in caso:
                break
            time.sleep(0.1)
        self.assertEqual(caso["tipo_seed"], "cpf")
        self.assertEqual(caso["orcamento"]["requisicoes_feitas"], 0)  # CPF: zero rede


# =========================================================== CLI
class TestCLI(Temp):
    def rodar(self, *args):
        return subprocess.run([sys.executable, os.path.join(RAIZ, "garimpo.py"), *args], capture_output=True,
                              text=True, timeout=60, cwd=self.dir, env={**os.environ, "PYTHONIOENCODING": "cp1252"})

    def test_fontes_versao_demo_exportar_diff(self):
        self.assertIn("GARIMPO 2.", self.rodar("versao").stdout)
        self.assertIn("passiva*", self.rodar("fontes").stdout)
        p = self.rodar("demo")
        self.assertEqual(p.returncode, 0, p.stderr)  # saída UTF-8 mesmo com cp1252 pedido
        self.assertEqual(self.rodar("verificar", "casos/demo").returncode, 0)
        self.assertIn("stix", self.rodar("exportar", "casos/demo", "stix", "graphml").stdout)
        self.assertIn("+ entidade dominio:staging", self.rodar("diff", "casos/demo-anterior", "casos/demo").stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
