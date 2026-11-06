#!/bin/bash
set -e

APP_DIR=~/network-security-agent
echo "=== [1/3] Criando estrutura do projeto em $APP_DIR ==="
mkdir -p $APP_DIR
cd $APP_DIR

echo "=== [2/3] Configurando Ambiente Virtual Python ==="
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests pydantic ollama

echo "=== [3/3] Criando script do Coletor Syslog (syslog_listener.py) ==="
cat << 'EOF' > syslog_listener.py
import socket
import json
import re
from typing import Dict, Any
from pydantic import BaseModel, Field
import requests

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = 5140  # Porta de teste não privilegiada
SLM_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "mistral-network-analyst"

class NetworkAlertSchema(BaseModel):
    severity: str = Field(..., description="Nível de severidade: LOW, MEDIUM ou HIGH")
    classification: str = Field(..., description="Classificação do evento de rede")
    action: str = Field(..., description="Ação recomendada a ser tomada")

def analyze_log_with_slm(raw_log: str) -> Dict[str, Any]:
    prompt = f"""
    Context: You are a specialized Network Security AI Agent.
    Analyze the following raw log and output ONLY valid JSON with keys "severity", "classification", and "action".

    Raw Log:
    {raw_log}
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1}
    }
    try:
        response = requests.post(SLM_API_URL, json=payload, timeout=5)
        response.raise_for_status()
        result_text = response.json().get("response", "")
        
        cleaned_text = result_text.strip()
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned_text, re.DOTALL)
        if match:
            cleaned_text = match.group(1)
        else:
            start_idx, end_idx = cleaned_text.find('{'), cleaned_text.rfind('}')
            if start_idx != -1 and end_idx != -1:
                cleaned_text = cleaned_text[start_idx:end_idx+1]

        parsed_dict = json.loads(cleaned_text)
        validated_data = NetworkAlertSchema(**parsed_dict)
        return validated_data.dict()
    except Exception as e:
        return {"severity": "HIGH", "classification": "Fallback Error", "action": "Manual Review Required"}

def start_syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_HOST, SYSLOG_PORT))
    print(f"--- Servidor Syslog ouvindo em {SYSLOG_HOST}:{SYSLOG_PORT} ---")
    while True:
        data, addr = sock.recvfrom(1024)
        raw_log = data.decode('utf-8', errors='ignore')
        print(f"\n[LOG RECEBIDO de {addr[0]}] {raw_log.strip()}")
        analysis = analyze_log_with_slm(raw_log)
        print(f"[DECISÃO SLM]: {json.dumps(analysis, indent=2)}")

if __name__ == "__main__":
    start_syslog_listener()
EOF

echo "=== Criando script do Simulador (syslog_simulator.py) ==="
cat << 'EOF' > syslog_simulator.py
import socket
import time
import random

SYSLOG_SERVER_IP = "127.0.0.1"
SYSLOG_PORT = 5140

SAMPLE_LOGS = [
    "WARN FW-01 SYN_FLOOD_ATTEMPT src_ip=192.168.1.105 dst_port=443 count=4500",
    "CRITICAL AUTH_FAILURE user=admin src_ip=203.0.113.50 reason=password_guess",
    "INFO HTTP GET /index.html status=200 src_ip=192.168.1.50",
    "WARN PORT_SCAN_DETECTED src_ip=10.0.0.5 target_ports=22,80,443"
]

def send_simulated_syslog():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"--- Simulador Syslog iniciado (Enviando para {SYSLOG_SERVER_IP}:{SYSLOG_PORT}) ---")
    try:
        while True:
            log_message = random.choice(SAMPLE_LOGS)
            syslog_packet = f"<134>1 2026-10-19T12:00:00.000Z host-firewall01 app - - - {log_message}"
            sock.sendto(syslog_packet.encode('utf-8'), (SYSLOG_SERVER_IP, SYSLOG_PORT))
            print(f"[DISPARADO] {log_message}")
            time.sleep(3)
    except KeyboardInterrupt:
        sock.close()

if __name__ == "__main__":
    send_simulated_syslog()
EOF

echo "--- Deploy concluído com sucesso em $APP_DIR! ---"
