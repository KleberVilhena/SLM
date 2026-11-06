#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Avaliação de um motor de decisão sobre um conjunto rotulado (relatório, seções 3.7 a 3.9).

Métricas:
  tradução   : taxa de diretivas válidas e exatidão por campo
  detecção   : precisão, revocação e F1 por tipo de evento; F1 binário ataque x benigno
  segurança  : bloqueios indevidos de eventos benignos, taxa de falsos positivos e
               violações da lista de exceções, antes e depois dos guardrails
  desempenho : latência de inferência, mediana, p95 e média, em ms

Uso:
  python3 avaliar.py --motor regras  --conjunto dados/teste.jsonl
  python3 avaliar.py --motor ollama  --modelo qwen2.5:1.5b --few-shot --conjunto dados/teste.jsonl --limite 200
  python3 avaliar.py --motor hf --adaptador lora/adaptador --conjunto dados/teste_nao_visto.jsonl
  python3 avaliar.py --comparar resultados/a.jsonl resultados/b.jsonl      # McNemar e Wilcoxon
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import os
import random
import statistics
import time

from pydantic import ValidationError

from diretiva import DiretivaSeguranca, TIPOS_EVENTO, para_dict
from guardrails import Config, Firewall
from slm import criar_motor

CAMPOS = ["tipo_evento", "severidade", "ip_origem", "servico", "acao", "duracao_min"]
EXCECOES_LAB = ["10.0.0.1", "10.0.0.10"]


def carregar(caminho: str, limite: int = 0, semente: int = 7) -> list:
    with open(caminho, encoding="utf-8") as f:
        itens = [json.loads(l) for l in f if l.strip()]
    if limite and limite < len(itens):
        itens = random.Random(semente).sample(itens, limite)
    return itens


def percentil(v: list, p: float) -> float:
    if not v:
        return float("nan")
    s = sorted(v)
    k = (len(s) - 1) * p
    i = int(k)
    return s[i] + (s[min(i + 1, len(s) - 1)] - s[i]) * (k - i)


def avaliar(motor, itens: list, saida: str = "") -> dict:
    resultados = []
    for i, it in enumerate(itens, 1):
        # firewall novo a cada item: avalia a decisão isolada, sem efeito de agregação
        fw = Firewall(Config(modo="sugestao", excecoes=EXCECOES_LAB, max_bloqueios_min=10 ** 9,
                             arquivo_estado=os.devnull, detectar_redes_locais=False))
        fw._salvar = lambda: None
        r = {"id": it["id"], "rotulo": it["diretiva"]}
        try:
            bruto, ms = motor.decidir(it["log"])
            r["latencia_ms"] = ms
            r["predicao"] = para_dict(DiretivaSeguranca(**bruto))
            r["valida"] = True
        except ValidationError as e:
            r.update(valida=False, erro=f"esquema: {e.error_count()} erro(s)", predicao=None)
        except Exception as e:
            r.update(valida=False, erro=f"{type(e).__name__}: {e}", predicao=None)
        if r["valida"]:
            bloqueia, motivo = fw.aplicar(r["predicao"], it["log"])
            r["bloqueio_aprovado"], r["motivo"] = bloqueia, motivo
        else:
            r["bloqueio_aprovado"], r["motivo"] = False, "diretiva rejeitada"
        resultados.append(r)
        if i % 25 == 0:
            print(f"  {i}/{len(itens)} itens", flush=True)
    if saida:
        os.makedirs(os.path.dirname(saida) or ".", exist_ok=True)
        with open(saida, "w", encoding="utf-8") as f:
            for r in resultados:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return metricas(resultados)


def metricas(res: list) -> dict:
    n = len(res)
    validos = [r for r in res if r["valida"]]
    m = {"itens": n, "diretivas_validas_pct": round(100 * len(validos) / n, 2) if n else 0}

    # exatidão por campo, sobre todos os itens; diretiva inválida conta como erro
    acertos = {c: sum(1 for r in validos if r["predicao"][c] == r["rotulo"][c]) for c in CAMPOS}
    m["exatidao_por_campo_pct"] = {c: round(100 * acertos[c] / n, 2) for c in CAMPOS}
    m["exatidao_media_campos_pct"] = round(statistics.mean(m["exatidao_por_campo_pct"].values()), 2)
    m["exatidao_diretiva_completa_pct"] = round(
        100 * sum(1 for r in validos if all(r["predicao"][c] == r["rotulo"][c] for c in CAMPOS)) / n, 2)

    # detecção por tipo de evento
    por_tipo = {}
    for t in TIPOS_EVENTO:
        tp = sum(1 for r in validos if r["predicao"]["tipo_evento"] == t and r["rotulo"]["tipo_evento"] == t)
        fp = sum(1 for r in validos if r["predicao"]["tipo_evento"] == t and r["rotulo"]["tipo_evento"] != t)
        fn = sum(1 for r in res if r["rotulo"]["tipo_evento"] == t and
                 (not r["valida"] or r["predicao"]["tipo_evento"] != t))
        p = tp / (tp + fp) if tp + fp else 0.0
        rc = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
        por_tipo[t] = {"precisao": round(p, 3), "revocacao": round(rc, 3), "f1": round(f1, 3),
                       "suporte": tp + fn}
    m["deteccao_por_tipo"] = por_tipo
    com_suporte = [v["f1"] for v in por_tipo.values() if v["suporte"]]
    m["f1_macro"] = round(statistics.mean(com_suporte), 3) if com_suporte else 0.0

    # detecção binária ataque x benigno
    def ataque(d):
        return d is not None and d["tipo_evento"] != "benigno"
    tp = sum(1 for r in res if ataque(r["rotulo"]) and ataque(r["predicao"]))
    fp = sum(1 for r in res if not ataque(r["rotulo"]) and ataque(r["predicao"]))
    fn = sum(1 for r in res if ataque(r["rotulo"]) and not ataque(r["predicao"]))
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    m["f1_deteccao_binaria"] = round(2 * p * rc / (p + rc), 3) if p + rc else 0.0

    # segurança: bloqueios aprovados pelos guardrails
    benignos = [r for r in res if r["rotulo"]["acao"] != "bloquear"]
    indevidos = [r for r in benignos if r["bloqueio_aprovado"]]
    m["bloqueios_indevidos"] = len(indevidos)
    m["taxa_falsos_positivos_pct"] = round(100 * len(indevidos) / len(benignos), 2) if benignos else 0.0
    ataques_bloq = [r for r in res if r["rotulo"]["acao"] == "bloquear"
                    and r["rotulo"]["ip_origem"] not in EXCECOES_LAB]
    m["ataques_bloqueados_pct"] = round(
        100 * sum(1 for r in ataques_bloq if r["bloqueio_aprovado"]) / len(ataques_bloq), 2) if ataques_bloq else 0.0
    m["tentativas_modelo_bloquear_excecao"] = sum(
        1 for r in validos if r["predicao"]["acao"] == "bloquear" and r["predicao"]["ip_origem"] in EXCECOES_LAB)
    m["violacoes_lista_excecoes"] = sum(
        1 for r in res if r["bloqueio_aprovado"] and r["predicao"]["ip_origem"] in EXCECOES_LAB)

    lat = [r["latencia_ms"] for r in res if "latencia_ms" in r]
    if lat:
        m["latencia_ms"] = {"mediana": round(statistics.median(lat), 1), "p95": round(percentil(lat, 0.95), 1),
                            "media": round(statistics.mean(lat), 1), "min": round(min(lat), 1),
                            "max": round(max(lat), 1)}
    m["erros"] = collections.Counter(r.get("erro", "")[:60] for r in res if not r["valida"]).most_common(3)
    return m


# ---------------------------------------------------------------------------
# Comparação estatística entre dois motores
# ---------------------------------------------------------------------------
def mcnemar_exato(b: int, c: int) -> float:
    """Teste de McNemar exato, bicaudal: b e c são os pares discordantes."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def comparar(a_path: str, b_path: str) -> dict:
    a = {r["id"]: r for r in carregar(a_path)}
    b = {r["id"]: r for r in carregar(b_path)}
    ids = sorted(set(a) & set(b))

    def correto(r):
        return r["valida"] and r["predicao"]["tipo_evento"] == r["rotulo"]["tipo_evento"] \
            and r["predicao"]["acao"] == r["rotulo"]["acao"]
    b_only = sum(1 for i in ids if correto(a[i]) and not correto(b[i]))
    c_only = sum(1 for i in ids if not correto(a[i]) and correto(b[i]))
    out = {"pares": len(ids), "acerta_so_A": b_only, "acerta_so_B": c_only,
           "mcnemar_p": round(mcnemar_exato(b_only, c_only), 6)}
    la = [a[i]["latencia_ms"] for i in ids if "latencia_ms" in a[i] and "latencia_ms" in b[i]]
    lb = [b[i]["latencia_ms"] for i in ids if "latencia_ms" in a[i] and "latencia_ms" in b[i]]
    try:
        from scipy.stats import wilcoxon
        if la and any(x != y for x, y in zip(la, lb)):
            out["wilcoxon_latencia_p"] = float(wilcoxon(la, lb).pvalue)
    except ImportError:
        out["wilcoxon_latencia_p"] = "scipy indisponível"
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--motor", default="regras", choices=["ollama", "regras", "hf"])
    ap.add_argument("--modelo", default="")
    ap.add_argument("--adaptador", default="")
    ap.add_argument("--few-shot", action="store_true")
    ap.add_argument("--conjunto", default="dados/teste.jsonl")
    ap.add_argument("--limite", type=int, default=0, help="amostra aleatória de N itens")
    ap.add_argument("--saida", default="", help="arquivo JSONL com as predições item a item")
    ap.add_argument("--comparar", nargs=2, metavar=("A", "B"))
    args = ap.parse_args()

    if args.comparar:
        print(json.dumps(comparar(*args.comparar), ensure_ascii=False, indent=2))
        return
    motor = criar_motor(args.motor, modelo=args.modelo, adaptador=args.adaptador, few_shot=args.few_shot)
    if hasattr(motor, "aquecer"):
        motor.aquecer()
    itens = carregar(args.conjunto, args.limite)
    print(f"Avaliando {motor.nome} / {getattr(motor, 'modelo', '')} em {args.conjunto} ({len(itens)} itens)")
    t0 = time.time()
    m = avaliar(motor, itens, args.saida)
    m.update(motor=motor.nome, modelo=getattr(motor, "modelo", ""), conjunto=args.conjunto,
             few_shot=args.few_shot, duracao_total_s=round(time.time() - t0, 1))
    print(json.dumps(m, ensure_ascii=False, indent=2))
    if args.saida:
        with open(args.saida.replace(".jsonl", "_metricas.json"), "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
