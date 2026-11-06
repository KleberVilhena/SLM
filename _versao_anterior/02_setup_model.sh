#!/bin/bash
set -e

echo "=== [1/2] Criando diretório de configuração do modelo ==="
mkdir -p ~/network-slm-config
cd ~/network-slm-config

echo "=== [2/2] Criando o Modelfile para o Mistral/Llama ==="
cat << 'EOF' > Modelfile
# Usa o Mistral 7B (ou Llama 3) como base otimizada
FROM mistral

# Define o prompt de sistema especializado em segurança de rede
SYSTEM """
You are a specialized Network Security AI Agent.
Analyze raw logs and output ONLY valid JSON with keys "severity", "classification", and "action".
"""

# Configura parâmetros para respostas determinísticas
PARAMETER temperature 0.1
EOF

echo "Registrando o modelo no Ollama (mistral-network-analyst)..."
ollama create mistral-network-analyst -f ./Modelfile

echo "--- Modelo SLM configurado e registrado com sucesso! ---"
