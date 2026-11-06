#!/bin/bash
# Implanta o agente em ~/network-security-agent a partir desta pasta.
# Uso: bash 03_deploy_app.sh   (execute a partir da pasta system/)
set -e

ORIGEM="$(cd "$(dirname "$0")/network-security-agent" && pwd)"
APP_DIR=~/network-security-agent

echo "=== [1/5] Copiando o código para $APP_DIR ==="
mkdir -p "$APP_DIR"
cp "$ORIGEM"/*.py "$ORIGEM"/Modelfile "$ORIGEM"/requirements.txt "$APP_DIR"/
cp -r "$ORIGEM"/tests "$APP_DIR"/
cd "$APP_DIR"

echo "=== [2/5] Ambiente virtual Python ==="
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "=== [3/5] Testes automatizados ==="
python -m unittest discover -s tests

echo "=== [4/5] Conjunto de dados sintético (meta M1) ==="
python gerar_dataset.py --saida dados

echo "=== [5/5] Serviço systemd em modo sugestão ==="
sudo tee /etc/systemd/system/security-agent.service > /dev/null <<EOF
[Unit]
Description=Agente autonomo de seguranca (SLM + UFW)
After=network-online.target ollama.service

[Service]
WorkingDirectory=$APP_DIR
Environment=NSA_UFW_MODE=sugestao
Environment=NSA_MODEL=security-agent
# Environment=NSA_WHITELIST=10.0.0.1,10.0.0.10
# EnvironmentFile=/etc/security-agent.env   # TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/syslog_listener.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
echo
echo "--- Implantação concluída ---"
echo "Iniciar:      sudo systemctl start security-agent && journalctl -u security-agent -f"
echo "Modo real:    edite NSA_UFW_MODE=real no serviço após o piloto em modo sugestão"
echo "Simular:      venv/bin/python syslog_simulator.py --cenario misto --taxa 1 --total 20"
echo "Reverter:     sudo venv/bin/python rollback.py --listar | --ip IP | --todos"
echo "No nó alvo, encaminhe os logs com: *.* @IP_DO_AGENTE:5140;RSYSLOG_SyslogProtocol23Format"
