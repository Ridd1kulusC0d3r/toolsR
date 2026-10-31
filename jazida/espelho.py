# -*- coding: utf-8 -*-
"""Modo ESPELHO — auto-auditoria OPSEC.

Mesma coleta passiva do GARIMPO, mas o relatório é invertido: em vez de
"o que descobri sobre o alvo", responde "o que um observador passivo vê de
VOCÊ", organizado em classes defensivas de exposição, com recomendações.

É o produto E.S.P.E.L.H.O. da família: puramente defensivo. Use só no seu
próprio domínio/marca (ou de quem te autorizou).
"""

from __future__ import annotations

import html as _h
import os

from . import VERSAO
from .analise import exposicao, linha_do_tempo
from .custodia import Custodia

E = _h.escape

_COR_EXPOSTO = {True: "#f59e0b", False: "#10b981"}


def _barra(pontos: int) -> str:
    cor = "#ef4444" if pontos >= 55 else ("#f59e0b" if pontos >= 30 else "#10b981")
    return (f'<div style="background:#0f172a;border:1px solid #1e293b;border-radius:999px;height:16px;overflow:hidden">'
            f'<div style="width:{min(pontos, 100)}%;height:100%;background:{cor}"></div></div>')


def gerar_relatorio(caso: dict, caso_dir: str) -> str:
    exp = exposicao(caso)
    ledger = {r["seq"]: r for r in Custodia.ler_ledger(caso_dir)}
    linha = linha_do_tempo(caso)

    classes_html = []
    for c in exp["classes"]:
        cor = _COR_EXPOSTO[c["exposto"]]
        itens = "".join(f"<li>{E(a)}</li>" for a in c["achados"])
        classes_html.append(f"""
<div class="classe">
<div class="ch"><span class="bolha" style="background:{cor}"></span><b>{E(c['titulo'])}</b>
<span class="tag">{'EXPOSTO' if c['exposto'] else 'ok'}</span></div>
<ul>{itens}</ul>
<p class="rec">→ {E(c['recomendacao'])}</p></div>""")

    linha_html = ""
    if linha:
        itens = "".join(f'<tr><td class="d">{E(e["data"])}</td><td>{E(e["valor"])}</td>'
                        f'<td class="f">{E(e["fonte"])}</td><td>{E(e["fato"])}</td></tr>' for e in linha)
        linha_html = f"<h2>Linha do tempo da pegada</h2><table class='tl'>{itens}</table>"

    doc = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ESPELHO — exposição de {E(caso['seed'])}</title>
<style>
:root{{color-scheme:dark}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0b1220;color:#e2e8f0;max-width:900px;margin:0 auto;padding:24px 16px}}
h1{{font-size:1.5rem}}h1 small{{color:#60a5fa;font-weight:400}}h2{{font-size:1.1rem;margin-top:26px}}
.placar{{background:#111a2e;border:1px solid #1e293b;border-radius:14px;padding:18px 20px;margin:14px 0}}
.placar .n{{font-size:2.2rem;font-weight:800}}
.resumo{{color:#fbbf24;margin-top:8px}}
.classe{{background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:12px 16px;margin:10px 0}}
.ch{{display:flex;align-items:center;gap:8px}}
.bolha{{width:11px;height:11px;border-radius:50%;display:inline-block}}
.tag{{margin-left:auto;font-size:.68rem;text-transform:uppercase;color:#94a3b8;border:1px solid #1e293b;border-radius:999px;padding:1px 9px}}
ul{{margin:8px 0;font-size:.88rem}}li{{margin:2px 0;overflow-wrap:anywhere}}
.rec{{color:#93c5fd;font-size:.86rem;margin:6px 0 0}}
table{{width:100%;border-collapse:collapse;font-size:.84rem;margin-top:8px}}
td{{padding:6px 8px;border-top:1px solid #1e293b;vertical-align:top;overflow-wrap:anywhere}}
td.d{{white-space:nowrap;color:#60a5fa;font-family:ui-monospace,monospace}}td.f{{color:#94a3b8;font-family:ui-monospace,monospace;white-space:nowrap}}
.aviso{{border-left:3px solid #f59e0b;background:#1c1917;padding:10px 14px;border-radius:8px;font-size:.84rem;color:#fbbf24;margin:18px 0}}
footer{{color:#475569;font-size:.78rem;margin-top:28px;border-top:1px solid #1e293b;padding-top:12px}}
</style></head><body>
<h1>🪞 ESPELHO <small>· o que um observador passivo vê de você · DEIVOSINT</small></h1>
<div class="placar">
<div><b>Alvo:</b> {E(caso['seed'])} · <b>coletado (UTC):</b> {E(caso['iniciado_utc'][:19])}</div>
<div class="n">{exp['pontuacao']}/100</div>
<div>exposição passiva observada (mais alto = mais à mostra)</div>
{_barra(exp['pontuacao'])}
<div class="resumo">{E(exp['resumo'])}</div>
</div>
<h2>Classes de exposição</h2>
{''.join(classes_html)}
{linha_html}
<div class="aviso"><b>Como ler:</b> isto é um retrato do que está público e visível passivamente — não um teste de invasão nem um veredito de risco. "EXPOSTO" quer dizer "observável de fora", não "vulnerável". Use para priorizar higiene de OPSEC. Coleta 100% passiva; evidências em <code>evidencias/</code>, verificáveis com <code>python3 garimpo.py verificar {E(os.path.basename(os.path.normpath(caso_dir)))}</code>.</div>
<footer>GARIMPO {VERSAO} · modo ESPELHO · família DEIVOSINT · uso legal e autorizado apenas (rode no seu próprio ativo)</footer>
</body></html>"""
    caminho = os.path.join(caso_dir, "espelho.html")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(doc)
    return caminho
