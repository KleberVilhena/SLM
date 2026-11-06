#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ajuste fino LoRA ou QLoRA do Qwen 2.5 1.5B para tradução de logs em diretivas (OE2, meta M2).

Requisitos: pip install torch transformers peft accelerate  [bitsandbytes, para --qlora]

Uso:
  python3 treinar_lora.py --dados dados --saida lora/adaptador                 # LoRA em fp16
  python3 treinar_lora.py --qlora --epocas 2 --saida lora/adaptador-qlora      # QLoRA em 4 bits
  python3 treinar_lora.py --mesclar lora/adaptador --saida lora/mesclado       # funde para exportar GGUF

O adaptador é avaliado com: python3 avaliar.py --motor hf --adaptador lora/adaptador
Para servir no Ollama, funda o adaptador (--mesclar), converta para GGUF com o
convert_hf_to_gguf.py do llama.cpp, quantize em Q4_K_M e aponte o Modelfile para o arquivo.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import time

import torch

from slm import INSTRUCAO

BASE = "Qwen/Qwen2.5-1.5B-Instruct"


def carregar_jsonl(caminho: str):
    with open(caminho, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def exemplo_para_ids(tok, it: dict, max_len: int):
    """Tokeniza no formato de chat e mascara o prompt: a perda incide só sobre a diretiva."""
    msgs = [{"role": "system", "content": INSTRUCAO},
            {"role": "user", "content": f"LOG: <<<{it['log'][:2000]}>>>"}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    resposta = json.dumps(it["diretiva"], ensure_ascii=False) + tok.eos_token
    p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
    r_ids = tok(resposta, add_special_tokens=False)["input_ids"]
    ids = (p_ids + r_ids)[:max_len]
    rot = ([-100] * len(p_ids) + r_ids)[:max_len]
    return ids, rot


def lotes(dados, tam, pad_id, embaralhar, rng):
    idx = list(range(len(dados)))
    if embaralhar:
        rng.shuffle(idx)
    for i in range(0, len(idx), tam):
        grupo = [dados[j] for j in idx[i:i + tam]]
        L = max(len(x[0]) for x in grupo)
        ids = torch.full((len(grupo), L), pad_id)
        rot = torch.full((len(grupo), L), -100)
        att = torch.zeros((len(grupo), L), dtype=torch.long)
        for k, (a, b) in enumerate(grupo):
            ids[k, :len(a)], rot[k, :len(b)], att[k, :len(a)] = torch.tensor(a), torch.tensor(b), 1
        yield ids, rot, att


def treinar(args) -> None:
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.manual_seed(args.semente)
    rng = random.Random(args.semente)
    tok = AutoTokenizer.from_pretrained(args.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    kw = {"device_map": "auto"}
    if args.qlora:
        from transformers import BitsAndBytesConfig
        kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                       bnb_4bit_compute_dtype=torch.float16,
                                                       bnb_4bit_use_double_quant=True)
    else:
        kw["dtype"] = torch.float16 if torch.cuda.is_available() else torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.base, **kw)
    if args.qlora:
        model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    cfg = LoraConfig(r=args.rank, lora_alpha=2 * args.rank, lora_dropout=0.05, bias="none",
                     task_type="CAUSAL_LM",
                     target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, cfg)
    # adaptadores em fp32 para estabilidade numérica com o modelo base em fp16
    for p in model.parameters():
        if p.requires_grad:
            p.data = p.data.float()
    model.print_trainable_parameters()

    treino = [exemplo_para_ids(tok, it, args.max_len) for it in carregar_jsonl(os.path.join(args.dados, "treino.jsonl"))]
    valid = [exemplo_para_ids(tok, it, args.max_len) for it in carregar_jsonl(os.path.join(args.dados, "validacao.jsonl"))]
    if args.limite_treino:
        treino = treino[:args.limite_treino]
    valid = valid[:args.limite_validacao]
    passos_total = math.ceil(len(treino) / args.lote / args.acumular) * args.epocas
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=args.lr, weight_decay=0.0)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / max(1, int(0.05 * passos_total))) *
        max(0.0, 1 - s / max(1, passos_total)))
    dev = next(model.parameters()).device
    escala = torch.amp.GradScaler("cuda", enabled=torch.cuda.is_available() and not args.qlora)

    historico, passo, t0 = [], 0, time.time()
    print(f"Treino: {len(treino)} exemplos, validação: {len(valid)}, {passos_total} passos de otimização")
    for ep in range(args.epocas):
        model.train()
        for i, (ids, rot, att) in enumerate(lotes(treino, args.lote, tok.pad_token_id, True, rng), 1):
            with torch.autocast("cuda", dtype=torch.float16, enabled=torch.cuda.is_available()):
                perda = model(input_ids=ids.to(dev), attention_mask=att.to(dev), labels=rot.to(dev)).loss / args.acumular
            escala.scale(perda).backward()
            if i % args.acumular == 0:
                escala.unscale_(opt)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                escala.step(opt)
                escala.update()
                opt.zero_grad(set_to_none=True)
                sched.step()
                passo += 1
                if passo % 20 == 0:
                    print(f"  época {ep + 1} passo {passo}/{passos_total} perda {perda.item() * args.acumular:.4f} "
                          f"({time.time() - t0:.0f} s)", flush=True)
                if args.salvar_cada and passo % args.salvar_cada == 0:
                    # checkpoint intermediário: uma interrupção não perde o treino já feito
                    model.save_pretrained(os.path.join(args.saida, "checkpoint"))
                    print(f"  checkpoint salvo no passo {passo}", flush=True)
        model.eval()
        with torch.no_grad():
            perdas = []
            for ids, rot, att in lotes(valid, args.lote, tok.pad_token_id, False, rng):
                with torch.autocast("cuda", dtype=torch.float16, enabled=torch.cuda.is_available()):
                    perdas.append(model(input_ids=ids.to(dev), attention_mask=att.to(dev), labels=rot.to(dev)).loss.item())
        pv = sum(perdas) / len(perdas)
        historico.append({"epoca": ep + 1, "perda_validacao": round(pv, 5), "tempo_s": round(time.time() - t0)})
        print(f"Época {ep + 1}: perda de validação {pv:.4f}", flush=True)

    os.makedirs(args.saida, exist_ok=True)
    model.save_pretrained(args.saida)
    tok.save_pretrained(args.saida)
    with open(os.path.join(args.saida, "treino_log.json"), "w", encoding="utf-8") as f:
        json.dump({"base": args.base, "qlora": args.qlora, "rank": args.rank, "lr": args.lr,
                   "epocas": args.epocas, "exemplos_treino": len(treino), "historico": historico,
                   "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu"},
                  f, ensure_ascii=False, indent=2)
    print(f"Adaptador salvo em {args.saida}")


def mesclar(adaptador: str, saida: str, base: str) -> None:
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer
    m = AutoModelForCausalLM.from_pretrained(base, dtype=torch.float16)
    m = PeftModel.from_pretrained(m, adaptador).merge_and_unload()
    m.save_pretrained(saida)
    AutoTokenizer.from_pretrained(base).save_pretrained(saida)
    print(f"Modelo mesclado salvo em {saida}; converta com llama.cpp/convert_hf_to_gguf.py")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--dados", default="dados")
    ap.add_argument("--saida", default="lora/adaptador")
    ap.add_argument("--qlora", action="store_true")
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--epocas", type=int, default=1)
    ap.add_argument("--lote", type=int, default=8)
    ap.add_argument("--acumular", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--limite-treino", type=int, default=0)
    ap.add_argument("--limite-validacao", type=int, default=200)
    ap.add_argument("--semente", type=int, default=42)
    ap.add_argument("--salvar-cada", type=int, default=40, help="salva o adaptador a cada N passos")
    ap.add_argument("--mesclar", default="", help="pasta do adaptador a fundir no modelo base")
    a = ap.parse_args()
    if a.mesclar:
        mesclar(a.mesclar, a.saida, a.base)
    else:
        treinar(a)
