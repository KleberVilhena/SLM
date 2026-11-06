# Agente autônomo de segurança: SLM + UFW com resposta zero-touch

Implementação do projeto descrito no relatório técnico (ABNT). A versão anterior do
código está preservada em `_versao_anterior/`.

## Correspondência com o relatório

| Relatório | Implementação |
|---|---|
| 3.1 Arquitetura de cinco camadas | `syslog_listener.py`: Syslog UDP 5140, SLM, Pydantic, UFW, auditoria e Telegram |
| 3.4 Esquema da diretiva JSON | `diretiva.py`: tipo_evento, severidade 1 a 5, ip_origem, servico, acao em bloquear/alertar/ignorar, duracao_min, justificativa |
| 3.5 Guardrails | `guardrails.py`: lista de exceções, limiar de severidade, IP presente no log, limite por minuto, TTL, modo sugestão |
| 3.5 Reversão manual | `rollback.py --listar / --ip / --todos` |
| 3.3 Dados e M1 | `gerar_dataset.py`: 5.400 pares em formatos vistos, divisão 70/15/15, 600 em formatos não vistos, 240 adversariais, 6 tipos com MITRE ATT&CK |
| 3.6 Variáveis controladas | `syslog_simulator.py --taxa 10/100/1000 --cenario ... --nao-visto --proporcao-legitimo` |
| 3.7 a 3.9 Métricas e estatística | `avaliar.py`: exatidão por campo, F1, falsos positivos, violações de exceção, latência, McNemar e Wilcoxon |
| 3.8 Linhas de base | B2 `--motor regras` (filtros estilo fail2ban); B3 `--motor ollama --few-shot`; modelo ajustado `--motor hf --adaptador` |
| OE2, M2 | `treinar_lora.py`: LoRA ou QLoRA do Qwen2.5-1.5B-Instruct |
| 7.1 LGPD | `pseudonimizar.py` (HMAC com sal) e retenção de 90 dias da auditoria |

## Instalação no nó do agente, Ubuntu 22.04

```bash
bash 01_install_infra.sh     # Python, rsyslog, UFW com SSH liberado, Ollama
bash 02_setup_model.sh       # qwen2.5:1.5b Q4_K_M registrado como security-agent
bash 03_deploy_app.sh        # código, venv, testes, dataset e serviço systemd
```

O agente inicia em modo `sugestao`, que registra as regras sem aplicá-las. Após o piloto,
defina `NSA_UFW_MODE=real`. No nó alvo, encaminhe os logs com rsyslog:
`*.* @IP_DO_AGENTE:5140;RSYSLOG_SyslogProtocol23Format`.

## Testes

```bash
cd network-security-agent
python3 -m unittest discover -s tests -v          # 24 testes unitários e ponta a ponta
sudo bash tests/teste_ufw_real.sh                 # UFW real; somente em VM de laboratório
python3 avaliar.py --motor regras --conjunto dados/teste_nao_visto.jsonl
python3 avaliar.py --motor ollama --modelo security-agent --conjunto dados/teste.jsonl --limite 150
python3 avaliar.py --comparar resultados/a.jsonl resultados/b.jsonl
```

Os resultados da campanha de testes estão em `network-security-agent/resultados/` e
resumidos em `RESULTADOS_TESTES.md`.
