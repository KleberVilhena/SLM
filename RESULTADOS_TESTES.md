# Resultados dos testes, 4 de novembro de 2026

Ambiente: notebook com Windows 11, CPU de 12 threads, 23 GB de RAM e GPU RTX 3050 de 6 GB;
Ollama 0.40.14 com qwen2.5:1.5b Q4_K_M; WSL Ubuntu 26.04 com UFW 0.36.2 para o teste de firewall real.
Os dados são sintéticos, gerados por `gerar_dataset.py` com semente 42. Os arquivos item a item estão em
`network-security-agent/resultados/`.

Importante para o REO: estes números são medições reais sobre dados sintéticos de laboratório. Eles
não substituem a avaliação com Loghub, CIC-IDS2017 e logs do laboratório prevista no relatório.

## 1. Testes automatizados

`python -m unittest discover -s tests`: 24 testes, todos aprovados. Cobrem esquema Pydantic,
guardrails, modo sugestão e modo real, limite por minuto, TTL, rollback, injeção de prompt, agregação,
retenção de 90 dias, meta M1 do dataset e um teste ponta a ponta via UDP.

## 2. UFW real, `tests/teste_ufw_real.sh`, motor regras

| Verificação | Resultado |
|---|---|
| Atacante SSH e atacante de injeção bloqueados | OK |
| Tráfego legítimo e gateway da lista de exceções não bloqueados | OK |
| Evento repetido agregado sem nova inferência | OK |
| Regra deny inserida antes das regras allow | OK |
| Tempo do recebimento do log à regra ativa | 0,38 s e 0,79 s |
| Rollback manual e expiração automática por TTL | OK |

## 3. Vazão do pipeline, `tests/teste_vazao.py`, motor regras, limite de 10 bloqueios/min

| Taxa alvo | Enviados | Perdidos | Vazão processada | Mitigação mediana |
|---|---|---|---|---|
| 10 logs/s | 100 | 0 | 9,3 logs/s | 0,003 s |
| 100 logs/s | 1.000 | 0 | 92,6 logs/s | 0,002 s |
| 1.000 logs/s | 10.000 | 0 | 908 logs/s | 0,002 s |

A primeira medição a 1.000 logs/s perdeu 26,7% dos eventos; a fila e o arquivo de auditoria foram
corrigidos e a perda caiu para zero.

Com o SLM no laço, via UDP, em modo sugestão: 15 eventos a 1 log/s, todos processados, vazão de
0,9 log/s e mitigação mediana de 0,97 s. A vazão com o SLM é limitada pela inferência, de cerca de
1,2 s por evento, e depende da agregação de eventos repetidos em picos.

## 4. Qualidade da decisão

Conjuntos: teste com formatos vistos, teste com formatos não vistos e adversarial. Para o SLM foram
usadas amostras aleatórias de 150 itens por conjunto; para a B2, os conjuntos completos.

| Motor | Conjunto | Diretivas válidas | Exatidão por campo | Diretiva completa | F1 macro | Falsos positivos | Ataques bloqueados | Violações de exceção | Latência mediana |
|---|---|---|---|---|---|---|---|---|---|
| B2 regras fail2ban | vistos | 100% | 79,6% | 55,4% | 0,891 | 0% | 82,6% | 0 | < 1 ms |
| B2 regras fail2ban | não vistos | 100% | 23,4% | 0% | 0,084 | 0% | 0% | 0 | < 1 ms |
| B2 regras fail2ban | adversarial | 100% | 95,7% | 87,1% | 1,000 | 0% | 100% | 0 | < 1 ms |
| Qwen 1.5B zero-shot | vistos | 100% | 67,3% | 11,3% | 0,521 | 16,7% | 67,8% | 0 | 1.350 ms |
| Qwen 1.5B zero-shot | não vistos | 100% | 64,4% | 15,3% | 0,559 | 12,3% | 68,8% | 0 | 1.250 ms |
| Qwen 1.5B zero-shot | adversarial | 100% | 55,6% | 0% | 0,301 | 0% | 7,1% | 0 | 1.300 ms |
| B3 Qwen 1.5B few-shot | vistos | 100% | 78,2% | 42,7% | 0,519 | 20,0% | 100% | 0 | 1.246 ms |
| B3 Qwen 1.5B few-shot | não vistos | 98,0% | 64,6% | 1,3% | 0,263 | 12,3% | 96,8% | 0 | 1.236 ms |
| B3 Qwen 1.5B few-shot | adversarial | 100% | 65,7% | 0% | 0,517 | 0% | 44,3% | 0 | 1.190 ms |

No conjunto adversarial, o modelo tentou bloquear um IP da lista de exceções em 119 de 150 casos no
zero-shot e em 107 no few-shot; a B2 tentou em 104 de 240. Os guardrails barraram todas as tentativas:
nenhuma violação ocorreu.

## 5. Situação das metas do relatório

| Meta | Situação |
|---|---|
| M1: 5.000 pares, 6 tipos, 98% válidos | Atingida: 5.400 pares em formatos vistos, 6 tipos, 100% válidos, mais 600 não vistos e 240 adversariais |
| M2: exatidão por campo de 90%, F1 de 0,90, latência de 500 ms em CPU | Não atingida pelo modelo base: exatidão de 64% a 78%, F1 macro de 0,26 a 0,56, latência de cerca de 1,3 s em GPU. O ajuste fino LoRA não foi concluído |
| M3: 100% validadas e nenhuma exceção bloqueada em 200 casos adversariais | Atingida no laboratório: 100% das diretivas passaram pelo Pydantic e houve 0 violações em 240 casos adversariais |
| M4: mitigação em até 5 s e falsos positivos de até 1% | Parcial: mitigação de 0,4 s a 0,8 s com o UFW real; falsos positivos de 12% a 20% com o modelo base, acima da meta |

## 6. Ajuste fino LoRA, OE2

`treinar_lora.py` rodou na RTX 3050 com 18,5 milhões de parâmetros treináveis, 1,18% do total. A perda caiu
de 0,0074 no passo 20 para 0,0035 no passo 40, mantendo 0,0042 no passo 60 de 237, com cerca de 12 s
por passo. O processo foi interrompido no passo 60 por falta de memória no computador e não houve
adaptador salvo. O script agora grava um checkpoint a cada 40 passos. Para retomar:

```bash
../.venv-treino/Scripts/python treinar_lora.py --saida lora/adaptador --epocas 1 --lote 4 --acumular 4 --max-len 384
python avaliar.py --motor hf --adaptador lora/adaptador --conjunto dados/teste_nao_visto.jsonl --limite 150
```

## 7. Pendências em relação ao relatório

- Concluir o treino LoRA e medir o modelo ajustado, inclusive a latência em CPU com `NSA_NUM_GPU=0`.
- Linha de base B1, operação manual, e B4, modelo de 7 bilhões de parâmetros, ainda não medidas.
- Converter dados reais de Loghub e CIC-IDS2017; hoje os dados são sintéticos.
- 30 repetições por cenário, intervalos de confiança e testes de Wilcoxon e McNemar: o código existe
  em `avaliar.py --comparar`, mas a campanha completa não foi executada.
- Teste de UFW real com o SLM no laço: o WSL não alcança o Ollama do Windows; o teste usou o motor
  de regras, e o SLM foi testado ponta a ponta em modo sugestão.
