#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simulador de logs Syslog (RFC 5424) para testar o Agente Autônomo de Segurança.

Envia, por UDP, eventos de ataque e de tráfego legítimo para o syslog_listener.py.

Uso:
  python3 syslog_simulator.py                  # 1 evento a cada 20 s, sem parar
  python3 syslog_simulator.py --intervalo 2    # 1 evento a cada 2 s
  python3 syslog_simulator.py --total 20       # envia 20 eventos e encerra
  python3 syslog_simulator.py --destino 192.168.15.15 --porta 5140
"""
import argparse
import random
import socket
import time
from datetime import datetime, timezone

EVENTOS = [
    # (nível, mensagem) — os IPs de origem são de teste (RFC 5737 / redes privadas)
    ("ERROR", "BUFFER_OVERFLOW_ATTEMPT src_ip=10.10.10.25 payload_size=2048"),
    ("CRITICAL", "AUTH_FAILURE user=admin src_ip=203.0.113.50 reason=password_guess"),
    ("WARN", "FW-01 SYN_FLOOD_ATTEMPT src_ip=198.51.100.77 dst_port=443 count=4500"),
    ("WARN", "PORT_SCAN_DETECTED src_ip=10.0.0.5 target_ports=22,80,443"),
    ("INFO", "HTTP GET /index.html status=200 src_ip=192.0.2.10"),
    ("INFO", "HTTP GET /produtos.cfm status=200 src_ip=192.0.2.11"),
]


def montar_log(nivel: str, msg: str) -> str:
    # <134> = facility local0 (16) * 8 + severidade informational (6)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return f"<134>1 {ts} host-firewall01 app - - - {nivel} {msg}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulador de logs Syslog/UDP")
    ap.add_argument("--destino", default="127.0.0.1", help="IP do syslog_listener (padrão 127.0.0.1)")
    ap.add_argument("--porta", type=int, default=5140, help="porta UDP (padrão 5140)")
    ap.add_argument("--intervalo", type=float, default=20.0, help="segundos entre eventos (padrão 20)")
    ap.add_argument("--total", type=int, default=0, help="quantos eventos enviar (0 = sem parar)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Simulador enviando para {args.destino}:{args.porta} a cada {args.intervalo:g} s "
          f"({'sem parar' if args.total == 0 else f'{args.total} eventos'}) — Ctrl+C para parar\n",
          flush=True)
    enviados = 0
    try:
        while args.total == 0 or enviados < args.total:
            log = montar_log(*random.choice(EVENTOS))
            sock.sendto(log.encode("utf-8"), (args.destino, args.porta))
            enviados += 1
            print(f"[DISPARADO] {log}", flush=True)
            time.sleep(args.intervalo)
    except KeyboardInterrupt:
        pass
    print(f"\nTotal enviado: {enviados} eventos.")


if __name__ == "__main__":
    main()
