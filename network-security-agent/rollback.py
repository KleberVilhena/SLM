#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reversão manual de bloqueios pelo operador (relatório, seção 3.5).

Uso:
  python3 rollback.py --listar
  sudo python3 rollback.py --ip 203.0.113.50
  sudo python3 rollback.py --todos
"""
import argparse
import time
from datetime import datetime

from guardrails import Config, Firewall


def main() -> None:
    ap = argparse.ArgumentParser(description="Lista ou remove bloqueios aplicados pelo agente")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--listar", action="store_true")
    g.add_argument("--ip")
    g.add_argument("--todos", action="store_true")
    args = ap.parse_args()

    fw = Firewall(Config.do_ambiente())
    if args.listar:
        if not fw.ativos:
            print("Nenhum bloqueio ativo.")
        for ip, info in sorted(fw.ativos.items()):
            resta = max(0, info["expira"] - time.time()) / 60
            print(f"{ip:40s} {info['tipo_evento']:18s} modo={info['modo']:9s} "
                  f"desde {datetime.fromtimestamp(info['inicio']):%d/%m %H:%M}, expira em {resta:.0f} min")
        return
    alvos = list(fw.ativos) if args.todos else [args.ip]
    for ip in alvos:
        print(fw.remover(ip))


if __name__ == "__main__":
    main()
