# -*- coding: utf-8 -*-
"""Dossiê HTML pt-BR standalone: grafo SVG, fatos com fonte E evidência
(#seq → arquivo bruto + SHA-256), uso de fontes e, se houver, mudanças desde a
coleta anterior."""

from __future__ import annotations

import html as _h
import math
import os

from . import VERSAO
from .custodia import Custodia

CORES = {"dominio": "#3b82f6", "ip": "#f59e0b", "email": "#10b981", "username": "#8b5cf6",
         "cnpj": "#ef4444", "cpf": "#ef4444", "pessoa": "#ec4899", "organizacao": "#f97316",
         "url": "#06b6d4", "hash": "#64748b", "telefone": "#eab308", "asn": "#14b8a6",
         "cep": "#a3e635", "documento_invalido": "#475569"}

E = _h.escape


def svg_grafo(grafo: dict, largura: int = 900, altura: int = 560) -> str:
    nos = grafo["nos"]
    if not nos:
        return "<p>Grafo vazio.</p>"
    cx, cy = largura / 2, altura / 2
    seed = grafo.get("no_seed") if grafo.get("no_seed") in nos else next(iter(nos))
    pos = {seed: (cx, cy)}
    por_prof: dict[int, list] = {}
    for k, n in nos.items():
        if k != seed:
            por_prof.setdefault(n["profundidade"], []).append(k)
    maxp = max(por_prof) if por_prof else 1
    for p, grupo in por_prof.items():
        raio = (min(cx, cy) - 40) * p / maxp
        grupo.sort(key=lambda k: (nos[k]["tipo"], k))
        for i, k in enumerate(grupo):
            a = 2 * math.pi * i / len(grupo) - math.pi / 2 + p * 0.35
            pos[k] = (cx + raio * 1.45 * math.cos(a), cy + raio * math.sin(a))
    denso = len(nos) > 30
    out = []
    for a in grafo["arestas"]:
        if a["de"] in pos and a["para"] in pos:
            (x1, y1), (x2, y2) = pos[a["de"]], pos[a["para"]]
            traco = ' stroke-dasharray="4 3"' if a["confianca"] < 0.6 else ""
            out.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="#94a3b8" '
                       f'stroke-width="1.2" opacity="{0.25 + 0.6 * a["confianca"]:.2f}"{traco}>'
                       f'<title>{E(a["relacao"])} ({a["confianca"]}) · {E(a.get("fonte", ""))}</title></line>')
    for k, (x, y) in pos.items():
        n = nos[k]
        cor = CORES.get(n["tipo"], "#64748b")
        r = 22 if k == seed else (12 if n["investigado"] else 7)
        rot = n["valor"] if len(n["valor"]) <= 26 else n["valor"][:23] + "…"
        borda = '#e2e8f0" stroke-dasharray="2 2' if not n["investigado"] else "#0f172a"
        out.append(f'<g><title>{E(n["tipo"])}: {E(n["valor"])} · prof {n["profundidade"]}'
                   f'{"" if n["investigado"] else " · fronteira (não consultado)"}</title>'
                   f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r}" fill="{cor}" opacity="{0.95 if n["investigado"] else 0.55}" '
                   f'stroke="{borda}" stroke-width="1.5"/>')
        if not denso or n["investigado"]:
            out.append(f'<text x="{x:.0f}" y="{y + r + 11:.0f}" font-size="{9 if denso else 10.5}" '
                       f'fill="#cbd5e1" text-anchor="middle">{E(rot)}</text>')
        out.append("</g>")
    return (f'<svg viewBox="0 0 {largura} {altura}" role="img" aria-label="Grafo de vínculos" '
            f'style="width:100%;background:#0f172a;border-radius:12px">{"".join(out)}</svg>')


def gerar_dossie(caso: dict, caso_dir: str, diff: dict | None = None) -> str:
    g = caso["grafo"]
    ledger = {r["seq"]: r for r in Custodia.ler_ledger(caso_dir)}

    def evid(seqs):
        links = []
        for s in seqs:
            r = ledger.get(s)
            if r:
                links.append(f'<a href="evidencias/{E(r["arquivo"])}" title="SHA-256 {r["sha256_evidencia"]} · '
                             f'HTTP {r["status_http"]} · {E(r["url"])}">#{s}</a>')
        return " ".join(links)

    secoes = []
    ordem = sorted(g["nos"].items(), key=lambda kv: (not kv[1]["investigado"], kv[1]["profundidade"], kv[0]))
    for chave, n in ordem:
        if not n["investigado"]:
            continue
        linhas = "".join(f'<tr><td class="fonte">{E(f["fonte"])}</td><td>{E(f["fato"])}</td>'
                         f'<td class="ev">{evid(f.get("evidencias", []))}</td></tr>' for f in n["fatos"]) \
            or '<tr><td colspan="3">Nenhum fato coletado.</td></tr>'
        secoes.append(f'<details {"open" if n["profundidade"] == 0 else ""}><summary>'
                      f'<span class="pill" style="background:{CORES.get(n["tipo"], "#64748b")}">{E(n["tipo"])}</span>'
                      f'<b>{E(n["valor"])}</b> <span class="prof">prof {n["profundidade"]} · {len(n["fatos"])} fatos</span>'
                      f'</summary><table>{linhas}</table></details>')
    fronteira = [n for n in g["nos"].values() if not n["investigado"]]
    front_html = ""
    if fronteira:
        itens = "".join(f'<li><span class="pill" style="background:{CORES.get(n["tipo"], "#64748b")}">{E(n["tipo"])}</span>'
                        f'{E(n["valor"])}</li>' for n in sorted(fronteira, key=lambda n: (n["tipo"], n["valor"])))
        front_html = (f'<h2>Fronteira ({len(fronteira)})</h2><p class="nota">Descobertos, mas <b>não consultados</b> '
                      f'(limite de profundidade/entidades ou confiança &lt; 0,6). Bons pontos de partida para a próxima coleta.</p>'
                      f'<ul class="front">{itens}</ul>')
    uso = "".join(f"<tr><td class='fonte'>{E(k)}</td><td>{v}</td></tr>"
                  for k, v in sorted(caso.get("fontes_usadas", {}).items()))
    diff_html = ""
    if diff:
        from .monitor import diff_html as _dh
        diff_html = _dh(diff)
    caminho_rel = caso_dir
    doc = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self'">
<title>Dossiê GARIMPO — {E(caso['seed'])}</title>
<style>
:root{{color-scheme:dark}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0b1220;color:#e2e8f0;max-width:1000px;margin:0 auto;padding:24px 16px}}
h1{{font-size:1.5rem}}h1 small{{color:#60a5fa;font-weight:400}}h2{{font-size:1.15rem;margin-top:28px}}
a{{color:#93c5fd}}
.meta{{display:flex;gap:14px;flex-wrap:wrap;font-size:.84rem;color:#94a3b8;background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:12px 16px}}
.pill{{color:#fff;border-radius:999px;padding:2px 9px;font-size:.7rem;text-transform:uppercase;margin-right:8px}}
.prof{{color:#64748b;font-size:.78rem;margin-left:8px}}
details{{background:#111a2e;border:1px solid #1e293b;border-radius:12px;margin:10px 0;padding:4px 14px}}
summary{{cursor:pointer;padding:10px 0}}
table{{width:100%;border-collapse:collapse;margin:6px 0 14px;font-size:.85rem}}
td{{padding:6px 8px;border-top:1px solid #1e293b;vertical-align:top;overflow-wrap:anywhere}}
td.fonte{{color:#60a5fa;white-space:nowrap;width:130px;font-family:ui-monospace,monospace}}
td.ev{{white-space:nowrap;width:80px;font-family:ui-monospace,monospace;font-size:.78rem}}
.nota{{color:#94a3b8;font-size:.86rem}}
ul.front{{columns:2;font-size:.84rem;padding-left:18px}}ul.front li{{margin:3px 0;break-inside:avoid}}
.aviso{{border-left:3px solid #f59e0b;background:#1c1917;padding:10px 14px;border-radius:8px;font-size:.84rem;color:#fbbf24;margin:18px 0}}
.mud{{background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:6px 16px}}
.mais{{color:#4ade80}}.menos{{color:#f87171}}
footer{{color:#475569;font-size:.78rem;margin-top:28px;border-top:1px solid #1e293b;padding-top:12px}}
</style></head><body>
<h1>⛏️ GARIMPO <small>· dossiê de investigação passiva · DEIVOSINT</small></h1>
<div class="meta">
<span><b>Seed:</b> {E(caso['seed'])} ({E(caso['tipo_seed'])})</span>
<span><b>Início (UTC):</b> {E(caso['iniciado_utc'][:19])}</span>
<span><b>Duração:</b> {caso['duracao_s']}s</span>
<span><b>Investigadas:</b> {sum(1 for n in g['nos'].values() if n['investigado'])}</span>
<span><b>Fronteira:</b> {len(fronteira)}</span>
<span><b>Vínculos:</b> {len(g['arestas'])}</span>
<span><b>Requisições:</b> {caso['orcamento']['requisicoes_feitas']}/{caso['orcamento']['max_requisicoes']}</span>
</div>
{diff_html}
<h2>Grafo de vínculos</h2>
{svg_grafo(g)}
<p class="nota">Círculo cheio: entidade consultada. Pontilhado e menor: fronteira. Linha tracejada: vínculo fraco (confiança &lt; 0,6, não pivotado). Passe o mouse para detalhes.</p>
<h2>Entidades e fatos</h2>
<p class="nota">Cada fato traz a fonte e a(s) evidência(s) que o sustentam: <b>#n</b> abre a resposta bruta guardada; o título mostra SHA-256, status HTTP e URL.</p>
{''.join(secoes)}
{front_html}
<h2>Uso de fontes</h2><table>{uso}</table>
<div class="aviso"><b>Cadeia de custódia:</b> respostas brutas em <code>evidencias/</code>, registradas em
<code>ledger.jsonl</code> com SHA-256 encadeado. Verifique com
<code>python3 garimpo.py verificar {E(caminho_rel)}</code> (a partir da pasta do GARIMPO).
Fatos vêm de execuções reais das fontes listadas; são pistas a confirmar, não prova. Uso legal e autorizado apenas.</div>
<footer>GARIMPO {VERSAO} · família DEIVOSINT · Deivison Lourenço (@Ridd1kulusC0d3r) · 100% Python stdlib · sempre passivo</footer>
</body></html>"""
    caminho = os.path.join(caso_dir, "dossie.html")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(doc)
    return caminho
