# -*- coding: utf-8 -*-
"""Fontes brasileiras: CNPJ (Receita via BrasilAPI), CEP, CPF e telefone
(estes dois só offline, por decisão de projeto)."""

from __future__ import annotations

from ..deteccao import RE_EMAIL, so_digitos
from . import fonte
from ._util import DDD_UF


@fonte("brasilapi_cnpj", ["cnpj"], "passiva", "brasilapi.com.br",
       "dados públicos da Receita Federal (QSA, CNAE, endereço)")
def brasilapi_cnpj(c, cnpj):
    fatos, novas = [], []
    r = c.get_json("brasilapi_cnpj", f"https://brasilapi.com.br/api/cnpj/v1/{so_digitos(cnpj)}")
    if not r or not r.get("razao_social"):
        return fatos, novas
    fatos.append(f"razão social: {r['razao_social']}")
    novas.append(("organizacao", r["razao_social"], "razao_social", 0.9))
    if r.get("nome_fantasia"):
        fatos.append(f"nome fantasia: {r['nome_fantasia']}")
    fatos.append(f"situação: {r.get('descricao_situacao_cadastral')} · abertura: {r.get('data_inicio_atividade')}")
    for campo, rotulo in (("natureza_juridica", "natureza jurídica"), ("porte", "porte"),
                          ("cnae_fiscal_descricao", "CNAE principal"), ("capital_social", "capital social")):
        if r.get(campo) not in (None, ""):
            fatos.append(f"{rotulo}: {r[campo]}")
    if r.get("opcao_pelo_mei"):
        fatos.append("optante pelo MEI")
    elif r.get("opcao_pelo_simples"):
        fatos.append("optante pelo Simples Nacional")
    end = " ".join(str(r.get(k) or "") for k in ("descricao_tipo_de_logradouro", "logradouro", "numero")).strip()
    if end:
        fatos.append(f"endereço: {end} · {r.get('bairro', '')} · {r.get('municipio')}/{r.get('uf')}")
    cep = so_digitos(str(r.get("cep") or ""))
    if len(cep) == 8:
        novas.append(("cep", f"{cep[:5]}-{cep[5:]}", "endereco_da_empresa", 0.7))
    em = str(r.get("email") or "").strip().lower()
    if em and RE_EMAIL.match(em):
        fatos.append(f"e-mail no cadastro: {em}")
        novas.append(("email", em, "email_cadastral", 0.8))
    tel = so_digitos(str(r.get("ddd_telefone_1") or ""))
    if len(tel) >= 10:
        fatos.append(f"telefone no cadastro: ({tel[:2]}) {tel[2:]}")
        novas.append(("telefone", tel, "telefone_cadastral", 0.6))
    for socio in (r.get("qsa") or [])[:15]:
        nome = socio.get("nome_socio")
        if nome:
            fatos.append(f"sócio ({socio.get('qualificacao_socio', '?')}): {nome}")
            novas.append(("pessoa", nome, "socio_de", 0.9))
    return fatos, novas


@fonte("brasilapi_cep", ["cep"], "passiva", "brasilapi.com.br",
       "logradouro e coordenadas do CEP (Correios e bases abertas)")
def brasilapi_cep(c, cep):
    fatos = []
    r = c.get_json("brasilapi_cep", f"https://brasilapi.com.br/api/cep/v2/{so_digitos(cep)}")
    if r and r.get("city"):
        fatos.append(f"{r.get('street', '')} · {r.get('neighborhood', '')} · {r.get('city')}/{r.get('state')}".strip(" ·"))
        coords = ((r.get("location") or {}).get("coordinates") or {})
        if coords.get("latitude") and coords.get("longitude"):
            fatos.append(f"coordenadas aproximadas: {coords['latitude']}, {coords['longitude']}")
    return fatos, []


@fonte("cpf_offline", ["cpf"], "offline", "nenhum",
       "SÓ valida dígitos e região fiscal — CPF nunca é consultado nem pivotado")
def cpf_offline(c, cpf):
    _ = c
    d = so_digitos(cpf)
    regiao = {"0": "RS", "1": "DF/GO/MT/MS/TO", "2": "AC/AM/AP/PA/RO/RR", "3": "CE/MA/PI",
              "4": "AL/PB/PE/RN", "5": "BA/SE", "6": "MG", "7": "ES/RJ", "8": "SP", "9": "PR/SC"}[d[8]]
    return ["dígitos verificadores: VÁLIDOS (cálculo offline)",
            f"região fiscal de emissão (9º dígito): {regiao}",
            "nenhuma consulta externa para CPF — decisão ética de projeto"], []


@fonte("telefone_offline", ["telefone"], "offline", "nenhum",
       "país, DDD/UF e tipo de linha por regra de numeração")
def telefone_offline(c, tel):
    _ = c
    d = so_digitos(tel)
    if d.startswith("55") and len(d) in (12, 13):
        d = d[2:]
    elif len(d) not in (10, 11):
        return ["código de país diferente de +55: só análise de formato", "nenhuma consulta externa"], []
    ddd, resto = d[:2], d[2:]
    uf = DDD_UF.get(ddd)
    fatos = [f"Brasil · DDD {ddd}" + (f" ({uf})" if uf else " (DDD inexistente na tabela Anatel)")]
    fatos.append("celular (9 dígitos, começa com 9)" if len(resto) == 9 and resto[0] == "9" else "fixo ou formato antigo")
    fatos.append("nenhuma consulta externa — fontes keyless de telefone não são confiáveis")
    return fatos, []


@fonte("documento_invalido", ["documento_invalido"], "offline", "nenhum",
       "formato de CPF/CNPJ com DV errado — nada é consultado")
def documento_invalido(c, v):
    _ = c, v
    return ["formato de CPF/CNPJ com dígitos verificadores INVÁLIDOS — nenhuma consulta feita; "
            "confira se houve erro de digitação"], []
