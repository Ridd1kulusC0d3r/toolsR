#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suíte de testes do GARIMPO — 100% stdlib (unittest), roda offline.

    python3 -m unittest discover -s testes -v        # a partir da raiz do repo
    python3 testes/test_garimpo.py                    # ou direto

Os parsers das fontes são testados contra payloads-fixture no formato
documentado de cada API (sem rede), por meio de um cliente falso.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(AQUI))
import garimpo as g  # noqa: E402


def _ler(caminho):
    with open(caminho, encoding="utf-8") as f:
        return f.read()


def _gravar(caminho, texto):
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(texto)


class ClienteFalso:
    """Substitui o Cliente HTTP: devolve fixtures por prefixo de URL."""

    def __init__(self, respostas: dict):
        self.respostas = respostas
        self.urls = []

    def get_json(self, fonte, url):
        self.urls.append((fonte, url))
        for prefixo, payload in self.respostas.items():
            if url.startswith(prefixo):
                return payload
        return None


# ---------------------------------------------------------------------------
class TestDeteccao(unittest.TestCase):
    CASOS = {
        "529.982.247-25": "cpf",
        "52998224725": "cpf",
        "11.222.333/0001-81": "cnpj",
        "11222333000181": "cnpj",
        "111.111.111-11": "documento_invalido",
        "529.982.247-26": "documento_invalido",
        "11.111.111/1111-11": "documento_invalido",
        "+55 31 99999-8888": "telefone",
        "(31) 99999-8888": "telefone",
        "5531999998888": "telefone",
        "12345678901": "telefone",  # 11 dígitos crus, DV inválido → celular c/ DDD
        "deivsec@gmail.com": "email",
        "https://exemplo.com.br/x": "url",
        "8.8.8.8": "ip",
        "2001:4860:4860::8888": "ip",
        "d41d8cd98f00b204e9800998ecf8427e": "hash",
        "registro.br": "dominio",
        "sub.dominio.com.br": "dominio",
        "Fulano de Tal": "pessoa",
        "torvalds": "username",
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


# ---------------------------------------------------------------------------
class TestCustodia(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="garimpo_teste_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _popular(self, n=3):
        c = g.Custodia(self.dir)
        for i in range(n):
            c.registrar("teste", f"demo://{i}", f"corpo {i}".encode(), 200)
        return c

    def test_integra(self):
        self._popular()
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertTrue(ok, prob)

    def test_adulteracao_de_evidencia(self):
        self._popular()
        evid = os.path.join(self.dir, "evidencias")
        arq = os.path.join(evid, sorted(os.listdir(evid))[1])
        with open(arq, "ab") as f:
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
        ok, prob = g.Custodia.verificar(self.dir)
        self.assertTrue(ok, prob)


# ---------------------------------------------------------------------------
class TestOrcamento(unittest.TestCase):
    def test_teto_duro_de_requisicoes(self):
        d = tempfile.mkdtemp(prefix="garimpo_orc_")
        try:
            orc = g.Orcamento(max_requisicoes=0, max_entidades=5, profundidade=1)
            cli = g.Cliente(g.Custodia(d), orc, silencioso=True)
            self.assertIsNone(cli.get_json("x", "https://exemplo.invalid/"))
            self.assertEqual(orc.requisicoes, 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Fixtures no formato documentado de cada API
RDAP_BR = {
    "events": [{"eventAction": "registration", "eventDate": "1997-04-20T00:00:00Z"}],
    "nameservers": [{"ldhName": "a.dns.br"}, {"ldhName": "b.dns.br"}],
    "entities": [{"roles": ["registrant"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                           ["fn", {}, "text", "Núcleo de Informação"]]]}],
}
DOH_A = {"Status": 0, "Answer": [{"name": "registro.br.", "type": 1, "data": "200.160.2.3"}]}
CRTSH = [{"name_value": "www.registro.br\n*.registro.br"},
         {"name_value": "rdap.registro.br"}]
WAYBACK_CDX = [["timestamp", "original"], ["19970101000000", "http://registro.br/"]]
INTERNETDB = {"cpes": [], "hostnames": ["dns.google"], "ip": "8.8.8.8",
              "ports": [53, 443], "tags": [], "vulns": ["CVE-2099-0001"]}
BRASILAPI = {"razao_social": "EMPRESA EXEMPLO LTDA", "nome_fantasia": "EXEMPLO",
             "descricao_situacao_cadastral": "ATIVA", "data_inicio_atividade": "2010-01-01",
             "municipio": "BELO HORIZONTE", "uf": "MG",
             "cnae_fiscal_descricao": "Desenvolvimento de software",
             "qsa": [{"nome_socio": "FULANO DE TAL", "qualificacao_socio": "Sócio-Administrador"}]}
GITHUB = {"login": "exemplo", "html_url": "https://github.com/exemplo", "name": "Ex Emplo",
          "email": "ex@exemplo.com", "blog": "", "company": None, "location": "BH",
          "public_repos": 3, "followers": 1, "created_at": "2015-01-01T00:00:00Z"}


class TestFontes(unittest.TestCase):
    def test_dominio_br_usa_registro_br_e_extrai_pivos(self):
        cli = ClienteFalso({
            "https://rdap.registro.br/": RDAP_BR,
            "https://dns.google/resolve?name=registro.br&type=A": DOH_A,
            "https://crt.sh/": CRTSH,
            "https://web.archive.org/cdx": WAYBACK_CDX,
        })
        fatos, novas = g.fonte_dominio(cli, "registro.br")
        self.assertEqual(cli.urls[0][0], "rdap_registro_br")
        textos = " | ".join(t for _, t in fatos)
        self.assertIn("registration: 1997-04-20", textos)
        self.assertIn("registrant: Núcleo de Informação", textos)
        self.assertIn("primeiro snapshot no Internet Archive: 1997-01-01", textos)
        valores = {(t, v) for t, v, _, _ in novas}
        self.assertIn(("ip", "200.160.2.3"), valores)
        self.assertIn(("dominio", "a.dns.br"), valores)
        self.assertIn(("dominio", "www.registro.br"), valores)
        self.assertIn(("dominio", "rdap.registro.br"), valores)
        self.assertNotIn(("dominio", "registro.br"), valores)  # o seed não é sub de si

    def test_dominio_nao_br_usa_rdap_org(self):
        cli = ClienteFalso({})
        g.fonte_dominio(cli, "example.com")
        self.assertTrue(cli.urls[0][1].startswith("https://rdap.org/domain/"))

    def test_ip_internetdb(self):
        cli = ClienteFalso({"https://internetdb.shodan.io/": INTERNETDB})
        fatos, novas = g.fonte_ip(cli, "8.8.8.8")
        textos = " | ".join(t for _, t in fatos)
        self.assertIn("[53, 443]", textos)
        self.assertIn("CVE-2099-0001", textos)
        self.assertIn(("dominio", "dns.google", "hospedado_em", 0.7), novas)

    def test_ip_internetdb_sem_dados(self):
        cli = ClienteFalso({"https://internetdb.shodan.io/": {"detail": "No information available"}})
        fatos, _ = g.fonte_ip(cli, "10.0.0.1")
        self.assertFalse(any(f == "internetdb" for f, _ in fatos))

    def test_cnpj_brasilapi_gera_organizacao_e_socios(self):
        cli = ClienteFalso({"https://brasilapi.com.br/": BRASILAPI})
        fatos, novas = g.fonte_cnpj(cli, "11.222.333/0001-81")
        self.assertTrue(cli.urls[0][1].endswith("/11222333000181"))
        self.assertIn(("organizacao", "EMPRESA EXEMPLO LTDA", "razao_social", 0.9), novas)
        self.assertIn(("pessoa", "FULANO DE TAL", "socio_de", 0.9), novas)

    def test_cpf_nao_faz_nenhuma_requisicao(self):
        cli = ClienteFalso({})
        fatos, novas = g.fonte_cpf(cli, "529.982.247-25")
        self.assertEqual(cli.urls, [])
        self.assertEqual(novas, [])
        self.assertTrue(any("RS" in t or "PR" in t or "SP" in t or "/" in t for _, t in fatos))

    def test_username_github(self):
        cli = ClienteFalso({"https://api.github.com/users/": GITHUB})
        fatos, novas = g.fonte_username(cli, "exemplo")
        self.assertIn(("email", "ex@exemplo.com", "email_publico_github", 0.9), novas)

    def test_email_pivota_dominio(self):
        cli = ClienteFalso({})
        _, novas = g.fonte_email(cli, "fulano@exemplo.com.br")
        self.assertIn(("dominio", "exemplo.com.br", "dominio_do_email", 1.0), novas)

    def test_telefone_br_formatado(self):
        fatos, _ = g.fonte_telefone(ClienteFalso({}), "+55 31 99999-8888")
        textos = " | ".join(t for _, t in fatos)
        self.assertIn("DDD 31", textos)
        self.assertIn("celular", textos)


# ---------------------------------------------------------------------------
class TestPivoEDossie(unittest.TestCase):
    def test_bfs_com_fontes_falsas_respeita_profundidade(self):
        d = tempfile.mkdtemp(prefix="garimpo_bfs_")
        originais = dict(g.FONTES)
        try:
            g.FONTES["dominio"] = lambda c, v: (
                [("falsa", f"visto {v}")],
                [("ip", "203.0.113.1", "resolve_para", 0.9),
                 ("dominio", "fraco.exemplo", "palpite", 0.3)])
            g.FONTES["ip"] = lambda c, v: (
                [("falsa", "ip ok")], [("dominio", "nivel2.exemplo", "hospedado_em", 0.9)])
            orc = g.Orcamento(30, 10, profundidade=1)
            caso = g.investigar("seed.exemplo.com", orc, d, silencioso=True)
            nos = caso["grafo"]["nos"]
            self.assertIn("ip:203.0.113.1", nos)
            self.assertNotIn("dominio:nivel2.exemplo", nos)   # profundidade 2 barrada
            self.assertNotIn("dominio:fraco.exemplo", nos)    # confiança < 0.6 não pivota
            caminho = g.gerar_dossie(caso, d)
            html = _ler(caminho)
            self.assertIn("<svg", html)
            self.assertIn("seed.exemplo.com", html)
            self.assertIn(f"verificar {d}", html)
        finally:
            g.FONTES.clear()
            g.FONTES.update(originais)
            shutil.rmtree(d, ignore_errors=True)

    def test_demo_idempotente(self):
        d = tempfile.mkdtemp(prefix="garimpo_demo_")
        try:
            g.rodar_demo(d)
            g.rodar_demo(d)
            with open(os.path.join(d, "ledger.jsonl"), encoding="utf-8") as f:
                self.assertEqual(sum(1 for _ in f), 2)
            ok, prob = g.Custodia.verificar(d)
            self.assertTrue(ok, prob)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dossie_escapa_html(self):
        d = tempfile.mkdtemp(prefix="garimpo_xss_")
        try:
            caso = {"seed": "<script>x</script>", "tipo_seed": "username",
                    "iniciado_utc": "2026-10-15T00:00:00+00:00", "duracao_s": 0,
                    "orcamento": {"requisicoes_feitas": 0, "max_requisicoes": 0},
                    "grafo": {"nos": {"username:<script>x</script>": {
                        "tipo": "username", "valor": "<script>x</script>", "profundidade": 0,
                        "fatos": [{"fonte": "t", "fato": "<img src=x onerror=alert(1)>"}]}},
                        "arestas": []}}
            html = _ler(g.gerar_dossie(caso, d))
            self.assertNotIn("<script>x</script>", html)
            self.assertNotIn("<img src=x", html)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
