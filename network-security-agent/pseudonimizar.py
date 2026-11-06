#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pseudonimiza endereços IP antes da publicação de dados (relatório, seção 7.1, LGPD).

Cada IP é substituído por um endereço derivado de HMAC-SHA256 com sal secreto,
de forma consistente: o mesmo IP gera sempre o mesmo pseudônimo, preservando a
estrutura do log e a correspondência entre log e diretiva.

Uso:
  NSA_SAL=<segredo> python3 pseudonimizar.py entrada.jsonl saida.jsonl
"""
import hashlib
import hmac
import os
import re
import sys

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def pseudonimo(ip: str, sal: bytes) -> str:
    h = hmac.new(sal, ip.encode(), hashlib.sha256).digest()
    # bloco 100.64.0.0/10, reservado, para não colidir com endereços reais publicados
    return f"100.{64 + h[0] % 64}.{h[1]}.{h[2]}"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sal = os.getenv("NSA_SAL", "").encode()
    if len(sal) < 16:
        sys.exit("Defina NSA_SAL com pelo menos 16 caracteres; o sal não deve ser publicado.")
    with open(sys.argv[1], encoding="utf-8") as f, open(sys.argv[2], "w", encoding="utf-8") as g:
        for linha in f:
            g.write(IPV4.sub(lambda m: pseudonimo(m.group(0), sal), linha))


if __name__ == "__main__":
    main()
