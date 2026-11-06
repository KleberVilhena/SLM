#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste de vazão do pipeline (relatório, seção 3.6: 10, 100 e 1.000 logs/s).

Sobe o agente em modo sugestão, dispara o simulador em cada taxa e mede quantos
eventos foram processados, perdidos e a vazão efetiva de processamento.

Uso: python3 tests/teste_vazao.py [--motor regras] [--taxas 10 100 1000] [--segundos 10]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def contar(caminho):
    try:
        with open(caminho, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def rodada(motor, modelo, taxa, segundos, porta, espera_max):
    tmp = tempfile.mkdtemp()
    audit = os.path.join(tmp, "audit.jsonl")
    env = {**os.environ, "NSA_AUDIT_FILE": audit, "NSA_ESTADO_FILE": os.path.join(tmp, "estado.json"),
           "NSA_UFW_MODE": "sugestao", "TELEGRAM_BOT_TOKEN": "", "PYTHONIOENCODING": "utf-8",
           "NSA_MAX_BLOCKS_MIN": os.getenv("NSA_MAX_BLOCKS_MIN", "10")}
    cmd = [sys.executable, os.path.join(RAIZ, "syslog_listener.py"), "--motor", motor, "--porta", str(porta)]
    if modelo:
        cmd += ["--modelo", modelo]
    ag = subprocess.Popen(cmd, cwd=tmp, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3 if motor == "regras" else 8)
    total = int(taxa * segundos)
    t0 = time.time()
    subprocess.run([sys.executable, os.path.join(RAIZ, "syslog_simulator.py"), "--porta", str(porta),
                    "--taxa", str(taxa), "--total", str(total), "--semente", "1"],
                   cwd=RAIZ, env=env, stdout=subprocess.DEVNULL)
    t_envio = time.time() - t0
    anterior, parado = -1, 0
    while time.time() - t0 < espera_max:
        n = len(contar(audit))
        if n >= total:
            break
        parado = parado + 1 if n == anterior else 0
        if parado >= 6:          # sem progresso por 3 s: assume fim do processamento
            break
        anterior = n
        time.sleep(0.5)
    linhas = contar(audit)
    t_total = time.time() - t0
    ag.terminate()
    ag.wait(5)
    agregados = sum(1 for l in linhas if l.get("agregado"))
    mit = sorted(l["tempo_ate_mitigacao_s"] for l in linhas if "tempo_ate_mitigacao_s" in l)
    return {"taxa_alvo": taxa, "enviados": total, "tempo_envio_s": round(t_envio, 2),
            "processados": len(linhas), "perdidos": total - len(linhas),
            "perda_pct": round(100 * (total - len(linhas)) / total, 2),
            "agregados_sem_slm": agregados,
            "vazao_processamento_logs_s": round(len(linhas) / t_total, 1),
            "mitigacao_mediana_s": round(mit[len(mit) // 2], 3) if mit else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--motor", default="regras")
    ap.add_argument("--modelo", default="")
    ap.add_argument("--taxas", type=float, nargs="+", default=[10, 100, 1000])
    ap.add_argument("--segundos", type=float, default=10)
    ap.add_argument("--espera-max", type=float, default=120)
    ap.add_argument("--saida", default="")
    a = ap.parse_args()
    res = []
    for i, t in enumerate(a.taxas):
        r = rodada(a.motor, a.modelo, t, a.segundos, 16100 + i, a.espera_max)
        r["motor"] = a.motor
        print(json.dumps(r, ensure_ascii=False), flush=True)
        res.append(r)
    if a.saida:
        with open(a.saida, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
