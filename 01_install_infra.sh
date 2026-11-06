#!/bin/bash
# Infraestrutura do nó do agente: Ubuntu 22.04 LTS (também testado em 24.04)
# Instala Python, rsyslog, UFW e o motor de inferência Ollama.
set -e

. /etc/os-release
echo "=== Sistema detectado: $PRETTY_NAME ==="
case "$VERSION_ID" in
  22.04|24.04) ;;
  *) echo "[AVISO] o projeto foi especificado para Ubuntu 22.04; continuando em $VERSION_ID" ;;
esac

echo "=== [1/4] Atualizando o sistema ==="
sudo apt update && sudo apt upgrade -y

echo "=== [2/4] Instalando Python 3, rsyslog e UFW ==="
sudo apt install -y python3 python3-pip python3-venv curl git rsyslog ufw

echo "=== [3/4] Configurando o UFW sem perder o acesso remoto ==="
# libera SSH antes de ativar, para não bloquear a própria sessão
sudo ufw allow OpenSSH
sudo ufw allow 5140/udp comment 'Syslog para o agente de seguranca'
sudo ufw --force enable
sudo ufw status verbose

echo "=== [4/4] Instalando o Ollama ==="
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable ollama
sudo systemctl start ollama

echo "--- Infraestrutura instalada com sucesso ---"
