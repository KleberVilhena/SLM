#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gera os gráficos da campanha de testes a partir de resultados/*.json.

Saída: resultados/graficos/*.png (150 dpi) e painel.png com todos os gráficos.
Uso: python3 gerar_graficos.py
"""
import json
import os
import re

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
import numpy as np  # noqa: E402

RES = "resultados"
OUT = os.path.join(RES, "graficos")

# Paleta de referência validada (slots 1 a 3) e tokens de texto e superfície
SUPERFICIE = "#fcfcfb"
TEXTO = "#0b0b0b"
TEXTO_2 = "#52514e"
GRADE = "#e4e3df"
COR = {"b2": "#2a78d6", "zero": "#eb6834", "b3": "#1baf7a"}
MOTORES = [("b2", "b2_regras", "B2 regras estilo fail2ban"),
           ("zero", "base_zeroshot", "Qwen 2.5 1.5B sem exemplos"),
           ("b3", "b3_fewshot", "B3 Qwen 2.5 1.5B com exemplos")]
CONJUNTOS = [("teste", "Formatos vistos"), ("teste_nao_visto", "Formatos não vistos"),
             ("adversarial", "Adversarial")]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10, "text.color": TEXTO,
    "axes.labelcolor": TEXTO_2, "axes.edgecolor": GRADE, "axes.facecolor": SUPERFICIE,
    "figure.facecolor": SUPERFICIE, "xtick.color": TEXTO_2, "ytick.color": TEXTO_2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.titlesize": 12,
    "axes.titleweight": "bold", "axes.formatter.use_locale": False, "axes.titlelocation": "left", "axes.titlepad": 12,
})


def carregar(prefixo, conjunto):
    with open(os.path.join(RES, f"{prefixo}_{conjunto}_metricas.json"), encoding="utf-8") as f:
        return json.load(f)


def br(s):
    """Converte separador decimal para vírgula, como no português."""
    return s.replace(".", ",")


def milhar(v):
    return f"{v:,.0f}".replace(",", ".")


def grade(ax, eixo="y"):
    ax.grid(axis=eixo, color=GRADE, linewidth=0.8)
    ax.set_axisbelow(True)


def barras_agrupadas(ax, chave, titulo, rotulo_y, formato="{:.0f}", limite=None, meta=None, meta_txt=""):
    x = np.arange(len(CONJUNTOS))
    larg = 0.26
    for i, (k, prefixo, nome) in enumerate(MOTORES):
        vals = [chave(carregar(prefixo, c)) for c, _ in CONJUNTOS]
        barras = ax.bar(x + (i - 1) * larg, vals, larg, color=COR[k], label=nome,
                        edgecolor=SUPERFICIE, linewidth=2)
        for b, v in zip(barras, vals):
            perto = meta is not None and v <= meta and (meta - v) < 0.05 * (limite or 1)
            dy = 10 if perto else 3   # afasta da linha de meta apenas os rótulos colados nela
            ax.annotate(br(formato.format(v)), (b.get_x() + b.get_width() / 2, b.get_height()),
                        xytext=(0, dy), textcoords="offset points", ha="center", va="bottom",
                        fontsize=8.5, color=TEXTO_2)
    if meta is not None:
        ax.axhline(meta, color=TEXTO_2, linewidth=1.2, linestyle=(0, (4, 3)))
        ax.text(1.0, 1.02, f"linha tracejada: {meta_txt}", transform=ax.transAxes,
                ha="right", va="bottom", fontsize=8.5, color=TEXTO_2)
    ax.set_xticks(x, [n for _, n in CONJUNTOS])
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: br(f"{v:g}")))
    ax.set_ylabel(rotulo_y)
    if limite:
        ax.set_ylim(0, limite)
    ax.set_title(titulo)
    grade(ax)


def legenda(fig):
    alcas = [plt.Rectangle((0, 0), 1, 1, color=COR[k]) for k, _, _ in MOTORES]
    fig.legend(alcas, [n for _, _, n in MOTORES], loc="upper center", ncol=3, frameon=False,
               bbox_to_anchor=(0.5, 1.0), fontsize=9.5)


def salvar(fig, nome):
    os.makedirs(OUT, exist_ok=True)
    fig.savefig(os.path.join(OUT, nome), dpi=150, bbox_inches="tight")
    plt.close(fig)


def g_exatidao():
    fig, axs = plt.subplots(1, 2, figsize=(12, 4.6))
    barras_agrupadas(axs[0], lambda m: m["exatidao_media_campos_pct"], "Exatidão média por campo",
                     "% de campos corretos", limite=110, meta=90, meta_txt="meta M2: 90%")
    barras_agrupadas(axs[1], lambda m: m["exatidao_diretiva_completa_pct"], "Diretiva completamente correta",
                     "% de diretivas", limite=110)
    legenda(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    salvar(fig, "1_exatidao.png")


def g_f1():
    fig, axs = plt.subplots(1, 2, figsize=(12, 4.6))
    barras_agrupadas(axs[0], lambda m: m["f1_macro"], "F1 macro por tipo de evento", "F1",
                     formato="{:.2f}", limite=1.15, meta=0.9, meta_txt="meta M2: 0,90")
    barras_agrupadas(axs[1], lambda m: m["f1_deteccao_binaria"], "F1 da detecção ataque ou benigno", "F1",
                     formato="{:.2f}", limite=1.15)
    legenda(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    salvar(fig, "2_f1.png")


def g_seguranca():
    fig, axs = plt.subplots(1, 2, figsize=(12, 4.6))
    barras_agrupadas(axs[0], lambda m: m["taxa_falsos_positivos_pct"], "Falsos positivos após os guardrails",
                     "% de eventos benignos bloqueados", formato="{:.1f}", limite=25, meta=1,
                     meta_txt="meta M4: 1%")
    barras_agrupadas(axs[1], lambda m: m["ataques_bloqueados_pct"], "Ataques bloqueados",
                     "% dos ataques com bloqueio", limite=115)
    legenda(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    salvar(fig, "3_falsos_positivos_e_bloqueios.png")


def g_adversarial():
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    nomes, tentativas, totais = [], [], []
    for k, prefixo, nome in MOTORES:
        m = carregar(prefixo, "adversarial")
        nomes.append(nome)
        tentativas.append(100 * m["tentativas_modelo_bloquear_excecao"] / m["itens"])
        totais.append((m["tentativas_modelo_bloquear_excecao"], m["itens"], m["violacoes_lista_excecoes"]))
    y = np.arange(len(nomes))[::-1]
    for yi, (k, _, _), t, (n, tot, v) in zip(y, MOTORES, tentativas, totais):
        ax.barh(yi, t, 0.55, color=COR[k], edgecolor=SUPERFICIE, linewidth=2)
        ax.annotate(f"{n} de {tot} tentativas, {v} bloqueios efetivados", (t, yi), xytext=(6, 0),
                    textcoords="offset points", va="center", fontsize=9, color=TEXTO_2)
    ax.set_yticks(y, nomes)
    ax.set_xlim(0, 140)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xlabel("% dos casos adversariais em que o motor tentou bloquear um IP de exceção")
    ax.set_title("Casos adversariais: tentativas de bloquear IP de exceção")
    grade(ax, "x")
    fig.tight_layout()
    salvar(fig, "4_adversarial_excecoes.png")


def g_latencia():
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    nomes, meds, p95s = [], [], []
    for k, prefixo, nome in MOTORES:
        m = carregar(prefixo, "teste")["latencia_ms"]
        nomes.append(nome)
        meds.append(max(m["mediana"], 0.01))
        p95s.append(max(m["p95"], 0.01))
    y = np.arange(len(nomes))[::-1]
    for yi, (k, _, _), md, p in zip(y, MOTORES, meds, p95s):
        ax.barh(yi, md, 0.55, color=COR[k], edgecolor=SUPERFICIE, linewidth=2)
        txt = "menos de 1 ms" if md < 1 else f"mediana {milhar(md)} ms, p95 {milhar(p)} ms"
        ax.annotate(txt, (md, yi), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=9, color=TEXTO_2)
    ax.axvline(500, color=TEXTO_2, linewidth=1.2, linestyle=(0, (4, 3)))
    ax.annotate("meta M2: 500 ms", (500, y[-1] - 0.42), xytext=(-4, 0), textcoords="offset points",
                ha="right", va="center", fontsize=8.5, color=TEXTO_2)
    ax.set_xscale("log")
    ax.set_xlim(0.005, 60000)
    ax.set_ylim(y[-1] - 0.6, y[0] + 0.5)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
        lambda v, _: br(f"{v:g}") if v < 1 else milhar(v)))
    ax.set_yticks(y, nomes)
    ax.set_xlabel("Latência de decisão por log, ms, escala logarítmica; SLM em GPU RTX 3050")
    ax.set_title("Latência de inferência, formatos vistos")
    grade(ax, "x")
    fig.tight_layout()
    salvar(fig, "5_latencia.png")


def g_vazao():
    with open(os.path.join(RES, "vazao_regras.json"), encoding="utf-8") as f:
        v = json.load(f)
    fig, axs = plt.subplots(1, 2, figsize=(12, 4.2))
    taxas = [f"{int(r['taxa_alvo']):,} logs/s".replace(",", ".") for r in v]
    x = np.arange(len(v))
    ax = axs[0]
    ax.bar(x, [r["vazao_processamento_logs_s"] for r in v], 0.5, color=COR["b2"],
           edgecolor=SUPERFICIE, linewidth=2)
    for xi, r in zip(x, v):
        ax.annotate(f"{milhar(r['vazao_processamento_logs_s'])} logs/s, {r['perdidos']} perdidos",
                    (xi, r["vazao_processamento_logs_s"]), xytext=(0, 3), textcoords="offset points",
                    ha="center", fontsize=9, color=TEXTO_2)
    ax.set_yscale("log")
    ax.set_ylim(1, 5000)
    ax.set_xticks(x, taxas)
    ax.set_xlabel("Taxa de eventos enviada pelo simulador")
    ax.set_ylabel("Logs processados por segundo, escala log")
    ax.set_title("Vazão do pipeline, motor de regras")
    grade(ax)
    ax = axs[1]
    ms = [1000 * r["mitigacao_mediana_s"] for r in v]
    ax.bar(x, ms, 0.5, color=COR["b2"], edgecolor=SUPERFICIE, linewidth=2)
    for xi, val in zip(x, ms):
        ax.annotate(f"{val:.0f} ms", (xi, val), xytext=(0, 3), textcoords="offset points",
                    ha="center", fontsize=9, color=TEXTO_2)
    ax.set_xticks(x, taxas)
    ax.set_ylim(0, max(ms) * 1.6)
    ax.set_xlabel("Taxa de eventos enviada pelo simulador")
    ax.set_ylabel("ms do recebimento à regra registrada")
    ax.set_title("Tempo mediano até a mitigação, modo sugestão")
    grade(ax)
    fig.tight_layout()
    salvar(fig, "6_vazao.png")


def g_treino():
    with open(os.path.join(RES, "treino_lora.log"), encoding="utf-8", errors="replace") as f:
        pts = [(int(a), float(b)) for a, b in re.findall(r"passo (\d+)/\d+ perda ([\d.]+)", f.read())]
    if not pts:
        return
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    xs, ys = zip(*pts)
    ax.plot(xs, ys, color=COR["b2"], linewidth=2, marker="o", markersize=8,
            markeredgecolor=SUPERFICIE, markeredgewidth=2)
    for a, b in pts:
        ax.annotate(br(f"{b:.4f}"), (a, b), xytext=(0, 8 if b != min(ys) else -16), textcoords="offset points", ha="center",
                    fontsize=9, color=TEXTO_2)
    ax.axvline(237, color=TEXTO_2, linewidth=1.2, linestyle=(0, (4, 3)))
    ax.annotate("fim previsto da época: passo 237", (237, max(ys)), xytext=(-4, 0),
                textcoords="offset points", ha="right", fontsize=8.5, color=TEXTO_2)
    ax.annotate("interrompido no passo 60\npor falta de memória", (xs[-1], ys[-1]), xytext=(14, -22),
                textcoords="offset points", fontsize=8.5, color=TEXTO_2)
    ax.set_xlim(0, 250)
    ax.set_ylim(0, max(ys) * 1.5)
    ax.set_xlabel("Passo de otimização")
    ax.set_ylabel("Perda de treino")
    ax.set_title("Ajuste fino LoRA do Qwen 2.5 1.5B, RTX 3050")
    grade(ax)
    fig.tight_layout()
    salvar(fig, "7_treino_lora.png")


def painel():
    from matplotlib.image import imread
    arquivos = sorted(f for f in os.listdir(OUT) if f[0].isdigit())
    imgs = [imread(os.path.join(OUT, f)) for f in arquivos]
    fig, axs = plt.subplots(len(imgs), 1, figsize=(12, 4.3 * len(imgs)))
    for ax, im in zip(axs, imgs):
        ax.imshow(im)
        ax.axis("off")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "painel.png"), dpi=110)
    plt.close(fig)


if __name__ == "__main__":
    for g in (g_exatidao, g_f1, g_seguranca, g_adversarial, g_latencia, g_vazao, g_treino):
        g()
    painel()
    print("Gráficos em", os.path.abspath(OUT))
    for f in sorted(os.listdir(OUT)):
        print("  ", f)
