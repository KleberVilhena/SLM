#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agente autônomo de segurança: Syslog + SLM + Pydantic + UFW + auditoria + Telegram
==================================================================================

Ciclo fechado de cinco camadas (relatório, seção 3.1):
  1. ingestão passiva de logs via Syslog/UDP, porta 5140;
  2. inferência e tradução pelo SLM (Qwen 2.5 1.5B no Ollama, por padrão);
  3. validação determinística da diretiva com Pydantic (diretiva.py);
  4. ação no firewall via UFW, sujeita aos guardrails (guardrails.py);
  5. auditoria em JSON Lines (security_audit.json) e alerta no Telegram.

Uso:
  python3 syslog_listener.py                       # SLM no Ollama, modo sugestão
  NSA_UFW_MODE=real sudo -E python3 syslog_listener.py
  python3 syslog_listener.py --motor regras        # linha de base B2 (fail2ban)

Variáveis de ambiente (opcionais):
  NSA_PORT                porta UDP do Syslog .......................... 5140
  NSA_OLLAMA_URL          endereço do Ollama ........ http://127.0.0.1:11434
  NSA_MODEL               modelo no Ollama (vazio = detecta qwen)
  NSA_TIMEOUT             tempo máximo de inferência, em segundos ........ 60
  NSA_UFW_MODE            "sugestao" (registra a regra) ou "real" (aplica)
  NSA_LIMIAR_SEVERIDADE   severidade mínima para bloquear, de 1 a 5 ....... 3
  NSA_MAX_BLOCKS_MIN      bloqueios novos por minuto ..................... 10
  NSA_DURACAO_PADRAO_MIN  TTL quando a diretiva não define duração ....... 30
  NSA_WHITELIST           IPs ou redes que nunca são bloqueados, por vírgula
  NSA_AUDIT_FILE          arquivo de auditoria ........... security_audit.json
  NSA_AUDIT_RETENCAO_DIAS retenção da auditoria .......................... 90
  NSA_ESTADO_FILE         bloqueios ativos ............. bloqueios_ativos.json
  TELEGRAM_BOT_TOKEN      token do bot (vazio = sem alertas)
  TELEGRAM_CHAT_ID        chat que recebe os alertas
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Optional

from pydantic import ValidationError

from diretiva import DiretivaSeguranca, para_dict
from guardrails import Config, Firewall
from slm import criar_motor

AUDIT_FILE = os.getenv("NSA_AUDIT_FILE", "security_audit.json")
RETENCAO_DIAS = int(os.getenv("NSA_AUDIT_RETENCAO_DIAS", "90"))
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID", "").strip()

_print_lock = threading.Lock()
_audit_lock = threading.Lock()

# IP do atacante dentro do conteúdo do log, usado para agregar eventos repetidos
_IP_LOG = re.compile(r"(?:src_ip=|from |rhost=|SRC=|client |\"client\":\"|\"remote\":\")"
                     r"((?:\d{1,3}\.){3}\d{1,3})|^((?:\d{1,3}\.){3}\d{1,3}) ")


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def corpo_syslog(pacote: str) -> str:
    """Remove o cabeçalho RFC 5424 (<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD) e devolve a mensagem."""
    m = re.match(r"<\d{1,3}>1 \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) ?(.*)$", pacote, re.S)
    return m.group(1) if m else pacote


def ip_no_log(msg: str) -> Optional[str]:
    m = _IP_LOG.search(msg)
    return (m.group(1) or m.group(2)) if m else None


# ---------------------------------------------------------------------------
# Auditoria e Telegram
# ---------------------------------------------------------------------------
_audit_handles: dict = {}


def auditar(entrada: dict, arquivo: str = AUDIT_FILE) -> None:
    """Grava uma linha JSON; o arquivo permanece aberto e cada linha é descarregada no disco."""
    linha = json.dumps(entrada, ensure_ascii=False) + "\n"
    with _audit_lock:
        f = _audit_handles.get(arquivo)
        if f is None or f.closed:
            f = _audit_handles[arquivo] = open(arquivo, "a", encoding="utf-8")
        f.write(linha)
        f.flush()


def aplicar_retencao(arquivo: str = AUDIT_FILE, dias: int = RETENCAO_DIAS) -> int:
    """Remove da auditoria os registros mais antigos que a retenção definida."""
    if not os.path.exists(arquivo):
        return 0
    limite = datetime.now() - timedelta(days=dias)
    mantidos, removidos = [], 0
    with open(arquivo, encoding="utf-8") as f:
        for linha in f:
            try:
                ts = datetime.fromisoformat(json.loads(linha)["timestamp"])
            except Exception:
                mantidos.append(linha)
                continue
            if ts >= limite:
                mantidos.append(linha)
            else:
                removidos += 1
    if removidos:
        with _audit_lock:
            antigo = _audit_handles.pop(arquivo, None)
            if antigo:
                antigo.close()
            with open(arquivo, "w", encoding="utf-8") as f:
                f.writelines(mantidos)
    return removidos


def telegram(texto: str) -> None:
    if not (TG_TOKEN and TG_CHAT):
        return

    def _enviar() -> None:
        for tentativa in range(3):  # o bloqueio não depende do alerta; reenvia em caso de falha
            try:
                data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": texto}).encode()
                urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                                       data=data, timeout=10)
                return
            except Exception as e:
                log(f"[TELEGRAM] falha na tentativa {tentativa + 1}: {e}")
                time.sleep(5 * (tentativa + 1))

    threading.Thread(target=_enviar, daemon=True).start()


# ---------------------------------------------------------------------------
# Agente
# ---------------------------------------------------------------------------
class Agente:
    def __init__(self, motor, firewall: Firewall, arquivo_audit: str = AUDIT_FILE,
                 alertar=telegram):
        self.motor = motor
        self.fw = firewall
        self.arquivo_audit = arquivo_audit
        self.alertar = alertar

    def processar(self, pacote: str, client_ip: str, t_recebido: Optional[float] = None) -> dict:
        t_recebido = t_recebido or time.time()
        msg = corpo_syslog(pacote)
        entrada = {"timestamp": datetime.now().isoformat(), "client_ip": client_ip, "raw_log": pacote,
                   "motor": self.motor.nome, "modelo": getattr(self.motor, "modelo", "")}

        # Agregação: evento de um IP já bloqueado não precisa passar pelo SLM
        ip_previo = ip_no_log(msg)
        if self.fw.ja_bloqueado(ip_previo):
            entrada.update(agregado=True, valida=None, diretiva=None,
                           decisao_firewall=f"agregado: {ip_previo} já bloqueado")
            auditar(entrada, self.arquivo_audit)
            return entrada

        bruto, erro, latencia = None, None, None
        try:
            bruto, latencia = self.motor.decidir(msg)
            diretiva = para_dict(DiretivaSeguranca(**bruto))
        except ValidationError as e:
            diretiva, erro = None, f"diretiva inválida: {e.error_count()} erro(s) de esquema"
        except Exception as e:
            diretiva, erro = None, f"{type(e).__name__}: {e}"

        entrada.update(valida=diretiva is not None, diretiva=diretiva,
                       latencia_inferencia_ms=round(latencia, 1) if latencia is not None else None)
        if erro:
            entrada.update(erro=erro, saida_bruta=bruto, decisao_firewall="sem ação: diretiva rejeitada")
            log(f"[REJEITADA] {erro}")
        else:
            try:
                aplicado, descricao = self.fw.aplicar(diretiva, msg)
            except Exception as e:
                aplicado, descricao = False, f"ERRO no UFW: {e}"
            entrada["decisao_firewall"] = descricao
            if aplicado:
                entrada["tempo_ate_mitigacao_s"] = round(time.time() - t_recebido, 3)
            log(f"[DIRETIVA] {json.dumps(diretiva, ensure_ascii=False)}")
            log(f"[FIREWALL] {descricao}")
            if aplicado or diretiva["severidade"] >= 4:
                self.alertar(f"{diretiva['tipo_evento']} severidade {diretiva['severidade']}\n"
                             f"IP: {diretiva['ip_origem'] or 'n/d'}\n{descricao}\nLog: {msg[:300]}")
        auditar(entrada, self.arquivo_audit)
        return entrada


def expirar_periodicamente(fw: Firewall, intervalo: float = 30) -> None:
    while True:
        time.sleep(intervalo)
        for r in fw.expirar():
            log(f"[UFW] bloqueio expirado: {r}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Agente autônomo de segurança zero-touch")
    ap.add_argument("--motor", default=os.getenv("NSA_MOTOR", "ollama"), choices=["ollama", "regras", "hf"])
    ap.add_argument("--modelo", default=os.getenv("NSA_MODEL", ""))
    ap.add_argument("--adaptador", default=os.getenv("NSA_ADAPTADOR", ""), help="pasta LoRA para --motor hf")
    ap.add_argument("--few-shot", action="store_true", help="inclui exemplos no prompt, linha de base B3")
    ap.add_argument("--porta", type=int, default=int(os.getenv("NSA_PORT", "5140")))
    ap.add_argument("--workers", type=int, default=1)
    args = ap.parse_args()

    motor = criar_motor(args.motor, modelo=args.modelo, adaptador=args.adaptador,
                        few_shot=args.few_shot, timeout=float(os.getenv("NSA_TIMEOUT", "60")))
    if hasattr(motor, "aquecer"):
        motor.aquecer()
    cfg = Config.do_ambiente()
    fw = Firewall(cfg)
    agente = Agente(motor, fw)
    removidos = aplicar_retencao()

    log("=" * 72)
    log(" Agente autônomo de segurança: SLM + Pydantic + UFW, resposta zero-touch")
    log(f" Syslog UDP ........ 0.0.0.0:{args.porta}")
    log(f" Motor ............. {motor.nome} / {getattr(motor, 'modelo', '')}")
    log(f" Modo UFW .......... {cfg.modo.upper()}, limiar de severidade {cfg.limiar_severidade}, "
        f"até {cfg.max_bloqueios_min} bloqueios/min")
    log(f" Exceções .......... {', '.join(str(n) for n in fw.excecoes)}")
    log(f" Telegram .......... {'ativo' if TG_TOKEN and TG_CHAT else 'desativado'}")
    log(f" Auditoria ......... {os.path.abspath(AUDIT_FILE)}, retenção {RETENCAO_DIAS} dias"
        f"{f', {removidos} registros antigos removidos' if removidos else ''}")
    log("=" * 72)
    if cfg.modo == "real" and hasattr(os, "geteuid") and os.geteuid() != 0:
        log("[AVISO] o modo real exige root para alterar o UFW.")

    fila: "queue.Queue" = queue.Queue(maxsize=int(os.getenv("NSA_FILA_MAX", "100000")))

    def trabalhador() -> None:
        while True:
            pacote, origem, t = fila.get()
            try:
                agente.processar(pacote, origem, t)
            except Exception as e:
                log(f"[ERRO INESPERADO] {type(e).__name__}: {e}")
            finally:
                fila.task_done()

    for _ in range(max(1, args.workers)):
        threading.Thread(target=trabalhador, daemon=True).start()
    threading.Thread(target=expirar_periodicamente, args=(fw,), daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # buffer de recepção maior absorve rajadas de 1.000 logs/s sem descarte pelo kernel
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("0.0.0.0", args.porta))
    try:
        while True:
            data, addr = sock.recvfrom(8192)
            pacote = data.decode("utf-8", errors="replace").strip()
            if not pacote:
                continue
            try:
                fila.put_nowait((pacote, addr[0], time.time()))
            except queue.Full:
                log(f"[AVISO] fila cheia, log descartado de {addr[0]}")
    except KeyboardInterrupt:
        log("\nEncerrando agente.")


if __name__ == "__main__":
    main()
