# -*- coding: utf-8 -*-
"""
Guardrails e executor UFW (relatório, seção 3.5).

  - lista de exceções: loopback, IPs do próprio servidor, gateway e NSA_WHITELIST;
  - bloqueio apenas para acao "bloquear" com severidade >= limiar;
  - o IP alvo precisa aparecer no texto do log (contém alucinação e injeção);
  - limite de bloqueios novos por minuto;
  - expiração automática do bloqueio após duracao_min (TTL);
  - reversão manual pelo operador (rollback.py);
  - modo "sugestao" na fase inicial: a regra é registrada, mas não aplicada.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

ANY_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}")


def _redes_locais() -> List[ipaddress._BaseNetwork]:
    redes = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    comandos = (["hostname", "-I"], ["ip", "route", "show", "default"])
    for cmd in comandos:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except Exception:
            continue
        for tok in out.split():
            try:
                redes.append(ipaddress.ip_network(tok))
            except ValueError:
                pass
    return redes


@dataclass
class Config:
    modo: str = "sugestao"              # "sugestao" ou "real"
    limiar_severidade: int = 3          # bloqueia apenas severidade >= limiar
    max_bloqueios_min: int = 10
    duracao_padrao_min: int = 30        # usada se a diretiva pedir bloqueio com duracao 0
    duracao_max_min: int = 1440
    excecoes: List[str] = field(default_factory=list)
    arquivo_estado: str = "bloqueios_ativos.json"
    detectar_redes_locais: bool = True

    @classmethod
    def do_ambiente(cls) -> "Config":
        return cls(
            modo=os.getenv("NSA_UFW_MODE", "sugestao").strip().lower(),
            limiar_severidade=int(os.getenv("NSA_LIMIAR_SEVERIDADE", "3")),
            max_bloqueios_min=int(os.getenv("NSA_MAX_BLOCKS_MIN", "10")),
            duracao_padrao_min=int(os.getenv("NSA_DURACAO_PADRAO_MIN", "30")),
            duracao_max_min=int(os.getenv("NSA_DURACAO_MAX_MIN", "1440")),
            excecoes=[x.strip() for x in os.getenv("NSA_WHITELIST", "").split(",") if x.strip()],
            arquivo_estado=os.getenv("NSA_ESTADO_FILE", "bloqueios_ativos.json"),
        )


def executar_ufw(args: List[str]) -> str:
    out = subprocess.run(["ufw"] + args, capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout).strip())
    return out.stdout.strip()


class Firewall:
    def __init__(self, cfg: Config, executor: Callable[[List[str]], str] = executar_ufw,
                 relogio: Callable[[], float] = time.time):
        self.cfg = cfg
        self._exec = executor
        self._agora = relogio
        self._lock = threading.Lock()
        self._recentes: List[float] = []
        self.excecoes = _redes_locais() if cfg.detectar_redes_locais else []
        for item in cfg.excecoes:
            try:
                self.excecoes.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
        self.ativos: Dict[str, dict] = self._carregar()

    # ------------------------------------------------------------ estado
    def _carregar(self) -> Dict[str, dict]:
        try:
            with open(self.cfg.arquivo_estado, encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _salvar(self) -> None:
        tmp = self.cfg.arquivo_estado + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.ativos, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.cfg.arquivo_estado)

    # ------------------------------------------------------------ regras
    def em_excecao(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in rede for rede in self.excecoes)

    def ja_bloqueado(self, ip: Optional[str]) -> bool:
        return bool(ip) and ip in self.ativos and self.ativos[ip]["expira"] > self._agora()

    def _ufw(self, args: List[str]) -> str:
        if self.cfg.modo != "real":
            return "SUGESTAO: ufw " + " ".join(args)
        return self._exec(args)

    def avaliar(self, diretiva: dict, raw_log: str) -> Tuple[bool, str]:
        """Aplica os guardrails. Retorna (deve_bloquear, motivo)."""
        ip = diretiva.get("ip_origem")
        if diretiva["acao"] != "bloquear":
            return False, f"sem bloqueio: acao {diretiva['acao']}"
        if diretiva["severidade"] < self.cfg.limiar_severidade:
            return False, f"sem bloqueio: severidade {diretiva['severidade']} abaixo do limiar {self.cfg.limiar_severidade}"
        if not ip:
            return False, "sem bloqueio: IP de origem ausente"
        if ip not in ANY_IP_RE.findall(raw_log):
            return False, f"sem bloqueio: IP {ip} não aparece no log"
        if self.em_excecao(ip):
            return False, f"sem bloqueio: {ip} está na lista de exceções"
        return True, "aprovado pelos guardrails"

    def aplicar(self, diretiva: dict, raw_log: str) -> Tuple[bool, str]:
        """Retorna (regra_registrada, descricao). Em modo sugestão a regra é apenas registrada."""
        ok, motivo = self.avaliar(diretiva, raw_log)
        if not ok:
            return False, motivo
        ip = diretiva["ip_origem"]
        dur = diretiva["duracao_min"] or self.cfg.duracao_padrao_min
        dur = min(dur, self.cfg.duracao_max_min)
        with self._lock:
            agora = self._agora()
            if self.ja_bloqueado(ip):
                return False, f"já bloqueado: {ip}"
            self._recentes[:] = [t for t in self._recentes if agora - t < 60]
            if len(self._recentes) >= self.cfg.max_bloqueios_min:
                return False, f"sem bloqueio: limite de {self.cfg.max_bloqueios_min} bloqueios por minuto"
            try:
                res = self._ufw(["insert", "1", "deny", "from", ip, "to", "any"])
            except RuntimeError:
                res = self._ufw(["deny", "from", ip, "to", "any"])
            self.ativos[ip] = {"inicio": agora, "expira": agora + dur * 60, "duracao_min": dur,
                               "tipo_evento": diretiva["tipo_evento"], "modo": self.cfg.modo}
            self._recentes.append(agora)
            self._salvar()
        verbo = "BLOQUEADO" if self.cfg.modo == "real" else "SUGERIDO BLOQUEIO"
        return True, f"{verbo} {ip} por {dur} min [{res}]"

    def remover(self, ip: str) -> str:
        with self._lock:
            info = self.ativos.pop(ip, None)
            if info is None:
                return f"{ip} não está bloqueado"
            try:
                res = self._exec(["delete", "deny", "from", ip, "to", "any"]) if info.get("modo") == "real" \
                    else "regra apenas sugerida, nada a remover no UFW"
            finally:
                self._salvar()
        return f"desbloqueado {ip} [{res}]"

    def expirar(self) -> List[str]:
        # o disco é a fonte da verdade: reflete reversões feitas pelo operador em outro processo
        with self._lock:
            self.ativos = self._carregar()
        agora = self._agora()
        vencidos = [ip for ip, info in list(self.ativos.items()) if info["expira"] <= agora]
        return [self.remover(ip) for ip in vencidos]
