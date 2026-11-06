#!/bin/bash
# Teste de integração com o UFW real. Requer root em uma máquina ou VM de laboratório.
# ATENÇÃO: reinicia as regras do UFW. Não execute em servidor de produção.
#   sudo bash tests/teste_ufw_real.sh [motor]      (motor padrão: regras)
set -u
cd "$(dirname "$0")/.."
MOTOR="${1:-regras}"
TMP=$(mktemp -d)
PORTA=15514
export NSA_UFW_MODE=real NSA_AUDIT_FILE=$TMP/audit.jsonl NSA_ESTADO_FILE=$TMP/estado.json
export NSA_WHITELIST=10.0.0.1,10.0.0.10 NSA_DURACAO_MAX_MIN=1 TELEGRAM_BOT_TOKEN=
falhas=0
verifica() { if eval "$2"; then echo "  [OK]    $1"; else echo "  [FALHA] $1"; falhas=$((falhas+1)); fi; }
envia() { printf '<134>1 2026-11-04T12:00:00Z alvo app - - - %s' "$1" > /dev/udp/127.0.0.1/$PORTA; }

echo "== Preparando UFW de teste"
ufw --force reset > /dev/null
ufw allow $PORTA/udp > /dev/null
ufw --force enable > /dev/null

echo "== Subindo o agente (motor $MOTOR, modo real)"
python3 syslog_listener.py --motor "$MOTOR" --porta $PORTA > $TMP/agente.log 2>&1 &
PID=$!
sleep 3

envia "sshd[77]: Failed password for root from 203.0.113.50 port 50122 ssh2 (12 attempts in 60s)"
envia '198.51.100.23 - - [04/Nov/2026:10:00:00 -0300] "GET /busca.cfm?id=1%27%20OR%201=1-- HTTP/1.1" 500 210'
envia '192.0.2.10 - - [04/Nov/2026:10:00:01 -0300] "GET /index.html HTTP/1.1" 200 3120'
envia "WARN PORT_SCAN_DETECTED src_ip=10.0.0.1 target_ports=22,80,443 distinct_ports=40"
envia "sshd[78]: Failed password for root from 203.0.113.50 port 50123 ssh2 (13 attempts in 60s)"
sleep 3

echo "== Regras após os eventos"
ufw status numbered | sed 's/^/   /'
verifica "atacante SSH bloqueado"            "ufw status | grep -q 'DENY.*203.0.113.50'"
verifica "atacante de injeção bloqueado"     "ufw status | grep -q 'DENY.*198.51.100.23'"
verifica "tráfego legítimo não bloqueado"    "! ufw status | grep -q '192.0.2.10'"
verifica "gateway em exceção não bloqueado"  "! ufw status | grep -q '10.0.0.1 '"
verifica "evento repetido agregado"          "grep -q '\"agregado\": true' $TMP/audit.jsonl"
verifica "regra de bloqueio antes do allow"  "ufw status numbered | grep -m1 -q 'DENY'"
echo "   tempos até a mitigação (s): $(grep -o '"tempo_ate_mitigacao_s": [0-9.]*' $TMP/audit.jsonl | awk '{print $2}' | xargs)"

echo "== Reversão manual pelo operador"
python3 rollback.py --ip 198.51.100.23
verifica "rollback removeu a regra"          "! ufw status | grep -q '198.51.100.23'"

echo "== Aguardando a expiração automática (TTL de 1 min)"
sleep 95
verifica "bloqueio expirado e removido"      "! ufw status | grep -q '203.0.113.50'"
grep -h "expirado" $TMP/agente.log | sed 's/^/   /'

kill $PID 2>/dev/null
ufw --force reset > /dev/null
ufw --force disable > /dev/null
echo "== UFW restaurado (inativo). Auditoria: $TMP/audit.jsonl"
echo "== Resultado: $falhas falha(s)"
exit $falhas
