#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simulador Syslog RFC 5424 sobre UDP para o agente (relatório, seção 3.6).

Variáveis controladas: taxa de eventos, tipo de ataque, proporção de tráfego
legítimo e presença de formatos de log não vistos no treino.

Uso:
  python3 syslog_simulator.py                              # misto, 1 evento a cada 2 s
  python3 syslog_simulator.py --taxa 100 --total 1000      # 100 logs/s
  python3 syslog_simulator.py --cenario forca_bruta_ssh --total 5
  python3 syslog_simulator.py --cenario adversarial --total 20
  python3 syslog_simulator.py --nao-visto --proporcao-legitimo 0.8
  python3 syslog_simulator.py --destino 192.168.15.15 --porta 5140
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import time
from datetime import datetime, timezone

from gerar_dataset import Gerador

ATAQUES = ["forca_bruta_ssh", "varredura_portas", "varredura_web", "injecao_http", "negacao_servico"]


def pacote_rfc5424(msg: str, app: str = "app") -> str:
    # <134> = facility local0 (16) x 8 + severidade informational (6)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return f"<134>1 {ts} host-alvo01 {app} - - - {msg}"


def evento(g: Gerador, cenario: str, visto: bool, prop_legit: float):
    fns = {"forca_bruta_ssh": g.ssh, "varredura_portas": g.portas, "varredura_web": g.web_scan,
           "injecao_http": g.injecao, "negacao_servico": g.dos, "benigno": g.benigno}
    if cenario == "adversarial":
        return g.adversarial()
    if cenario in fns:
        return fns[cenario](visto)
    if g.r.random() < prop_legit:
        return g.benigno(visto)
    return fns[g.r.choice(ATAQUES)](visto)


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulador de logs Syslog/UDP")
    ap.add_argument("--destino", default="127.0.0.1")
    ap.add_argument("--porta", type=int, default=5140)
    ap.add_argument("--taxa", type=float, default=0.5, help="eventos por segundo (padrão 0,5)")
    ap.add_argument("--total", type=int, default=0, help="eventos a enviar, 0 = sem parar")
    ap.add_argument("--cenario", default="misto", choices=["misto", "adversarial", "benigno"] + ATAQUES)
    ap.add_argument("--proporcao-legitimo", type=float, default=0.5)
    ap.add_argument("--nao-visto", action="store_true", help="usa formatos de log ausentes no treino")
    ap.add_argument("--semente", type=int, default=None)
    ap.add_argument("--rotulos", default="", help="grava em JSONL o rótulo esperado de cada evento enviado")
    args = ap.parse_args()

    g = Gerador(args.semente if args.semente is not None else random.randrange(10 ** 6))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    intervalo = 1.0 / args.taxa if args.taxa > 0 else 0
    rot = open(args.rotulos, "a", encoding="utf-8") if args.rotulos else None
    print(f"Simulador: {args.destino}:{args.porta}, {args.taxa:g} eventos/s, cenário {args.cenario}, "
          f"{'formatos não vistos' if args.nao_visto else 'formatos vistos'}; Ctrl+C para parar", flush=True)
    enviados, t0 = 0, time.perf_counter()
    try:
        while args.total == 0 or enviados < args.total:
            msg, rotulo = evento(g, args.cenario, not args.nao_visto, args.proporcao_legitimo)
            pacote = pacote_rfc5424(msg)
            sock.sendto(pacote.encode("utf-8"), (args.destino, args.porta))
            enviados += 1
            if rot:
                rot.write(json.dumps({"t_envio": time.time(), "log": msg, "diretiva": rotulo},
                                     ensure_ascii=False) + "\n")
            if args.taxa <= 5:
                print(f"[DISPARADO] {msg}", flush=True)
            # marcação temporal absoluta mantém a taxa média mesmo com jitter do sistema
            alvo = t0 + enviados * intervalo
            espera = alvo - time.perf_counter()
            if espera > 0:
                time.sleep(espera)
    except KeyboardInterrupt:
        pass
    dur = time.perf_counter() - t0
    print(f"\nTotal enviado: {enviados} eventos em {dur:.2f} s ({enviados / dur if dur else 0:.1f} eventos/s).")
    if rot:
        rot.close()


if __name__ == "__main__":
    main()
