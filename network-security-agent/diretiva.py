# -*- coding: utf-8 -*-
"""
Esquema da diretiva JSON produzida pelo SLM (relatório, seção 3.4).

Campos: tipo_evento, severidade (1 a 5), ip_origem, servico,
acao em {bloquear, alertar, ignorar}, duracao_min e justificativa.
Qualquer diretiva malformada ou com valores fora dos permitidos é rejeitada
pelo Pydantic antes de chegar ao firewall.
"""
from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Tipos de evento e técnica correspondente no MITRE ATT&CK (relatório, seção 3.3)
TIPOS_EVENTO = {
    "forca_bruta_ssh": "T1110 Brute Force",
    "varredura_portas": "T1046 Network Service Discovery",
    "varredura_web": "T1595 Active Scanning",
    "injecao_http": "T1190 Exploit Public-Facing Application",
    "negacao_servico": "T1499 Endpoint Denial of Service",
    "benigno": "nenhuma",
}
TipoEvento = Literal[
    "forca_bruta_ssh", "varredura_portas", "varredura_web",
    "injecao_http", "negacao_servico", "benigno",
]
Acao = Literal["bloquear", "alertar", "ignorar"]

DURACAO_MAX_MIN = 1440  # um dia: limite superior aceito para um bloqueio


class DiretivaSeguranca(BaseModel):
    """Diretiva estruturada que o agente pode executar."""

    model_config = ConfigDict(extra="forbid")

    tipo_evento: TipoEvento
    severidade: int = Field(..., ge=1, le=5)
    ip_origem: Optional[str] = None
    servico: str = Field(..., min_length=1, max_length=40)
    acao: Acao
    duracao_min: int = Field(..., ge=0, le=DURACAO_MAX_MIN)
    justificativa: str = Field(..., min_length=1, max_length=300)

    @field_validator("ip_origem")
    @classmethod
    def _ip_valido(cls, v: Optional[str]) -> Optional[str]:
        if v in (None, "", "null", "none"):
            return None
        return str(ipaddress.ip_address(str(v).strip()))


def json_schema_saida() -> dict:
    """Esquema JSON enviado ao Ollama para restringir a saída do modelo."""
    return {
        "type": "object",
        "properties": {
            "tipo_evento": {"type": "string", "enum": list(TIPOS_EVENTO)},
            "severidade": {"type": "integer", "minimum": 1, "maximum": 5},
            "ip_origem": {"type": ["string", "null"]},
            "servico": {"type": "string"},
            "acao": {"type": "string", "enum": ["bloquear", "alertar", "ignorar"]},
            "duracao_min": {"type": "integer", "minimum": 0, "maximum": DURACAO_MAX_MIN},
            "justificativa": {"type": "string"},
        },
        "required": ["tipo_evento", "severidade", "ip_origem", "servico",
                     "acao", "duracao_min", "justificativa"],
    }


def para_dict(d: DiretivaSeguranca) -> dict:
    return d.model_dump()
