#!/bin/bash
set -e

echo "=== [1/3] Atualizando o sistema Ubuntu 24.04 ==="
sudo apt update && sudo apt upgrade -y

echo "=== [2/3] Instalando dependências e Python 3 ==="
sudo apt install -y python3 python3-pip python3-venv curl git build-essential

echo "=== [3/3] Instalando o motor de inferência Ollama ==="
curl -fsSL https://ollama.com/install.sh | sh

echo "=== Verificando o serviço Ollama ==="
sudo systemctl enable ollama
sudo systemctl start ollama

echo "--- Infraestrutura instalada com sucesso! ---"
