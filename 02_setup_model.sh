#!/bin/bash
# Registra no Ollama o SLM do agente: Qwen 2.5 com 1,5 bilhão de parâmetros,
# quantizado em 4 bits (Q4_K_M), conforme o relatório.
set -e

APP_DIR=~/network-security-agent
mkdir -p "$APP_DIR"
cd "$APP_DIR"

echo "=== [1/2] Baixando o modelo base qwen2.5:1.5b (Q4_K_M, cerca de 1 GB) ==="
ollama pull qwen2.5:1.5b

echo "=== [2/2] Registrando o modelo do agente (security-agent) ==="
if [ -f qwen2.5-1.5b-security-lora-q4_k_m.gguf ]; then
  echo "Modelo ajustado com LoRA encontrado; usando o GGUF exportado."
  sed 's|^FROM .*|FROM ./qwen2.5-1.5b-security-lora-q4_k_m.gguf|' Modelfile > Modelfile.lora
  ollama create security-agent -f ./Modelfile.lora
else
  ollama create security-agent -f ./Modelfile
fi
ollama list

echo "--- Modelo registrado. Teste: ollama run security-agent 'teste' ---"
