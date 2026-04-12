
# import os
# import re
# import json
# from typing import Any, Dict, List

# BASE_MODEL_DIR = r"D:\ACL-terminal-simulation\response_model\Llama-3.2-3B-Instruct"
# LORA_CHECKPOINT_DIR = r"D:\ACL-terminal-simulation\response_model\Llama-3.2-3B-Instruct-4\checkpoint-5259"

# MAX_NEW_TOKENS = int(os.getenv("RESPONSE_AGENT_MAX_NEW_TOKENS", "512"))
# TEMPERATURE = float(os.getenv("RESPONSE_AGENT_TEMPERATURE", "0.3"))
# TOP_P = float(os.getenv("RESPONSE_AGENT_TOP_P", "0.95"))

# MERGE_LORA = os.getenv("RESPONSE_AGENT_MERGE_LORA", "0").strip() == "1"

# FORCE_DEVICE = os.getenv("RESPONSE_AGENT_DEVICE", "").strip().lower()

# DUMP_PROMPT = os.getenv("RESPONSE_AGENT_DUMP_PROMPT", "0").strip() == "1"
# DUMP_PROMPT_PATH = os.getenv("RESPONSE_AGENT_DUMP_PROMPT_PATH", "response_agent_last_prompt.txt")

# _TOKENIZER = None
# _MODEL = None



# TRAIN_INSTRUCTION = (
#     "You are a Linux OS terminal. Your task is to simulate exact CLI behavior. "
#     "You must only respond with the terminal output enclosed in a single code block (```), "
#     "with no explanations or additional text. Do not generate any commands yourself. "
#     "For each user input, respond exactly as a real Linux terminal would, including errors "
#     "or empty outputs when appropriate. For invalid or non-Linux commands, return the typical shell error."
# )


# def _json_compact(obj: Any, limit: int = 20000) -> str:
#     try:
#         s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
#     except Exception:
#         s = str(obj)
#     if len(s) > limit:
#         return s[:limit] + "...<truncated>"
#     return s


# def _extract_code_block(text: str) -> str:

#     if text is None:
#         return ""

#     s = text.strip()

#     m = re.search(r"```[^\n]*\n?(.*?)```", s, flags=re.DOTALL)
#     if m:
#         inner = m.group(1)

#         if inner.startswith("\n"):
#             inner = inner[1:]
#         return inner

#     if s.startswith("```"):
#         s2 = re.sub(r"^\s*```[^\n]*\n?", "", s)
#         return s2

#     return s


# def _load_local_model() -> None:
#     global _TOKENIZER, _MODEL
#     if _TOKENIZER is not None and _MODEL is not None:
#         return

#     import torch
#     from transformers import AutoTokenizer, AutoModelForCausalLM
#     from peft import PeftModel

#     dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16

#     _TOKENIZER = AutoTokenizer.from_pretrained(BASE_MODEL_DIR, use_fast=True)
#     # Some tokenizers have no pad token by default
#     if _TOKENIZER.pad_token_id is None and _TOKENIZER.eos_token_id is not None:
#         _TOKENIZER.pad_token_id = _TOKENIZER.eos_token_id

#     if FORCE_DEVICE in {"cpu", "cuda"}:
#         base = AutoModelForCausalLM.from_pretrained(BASE_MODEL_DIR, torch_dtype=dtype)
#         base.to(FORCE_DEVICE)
#     else:
#         base = AutoModelForCausalLM.from_pretrained(BASE_MODEL_DIR, torch_dtype=dtype, device_map="auto")

#     model = PeftModel.from_pretrained(base, LORA_CHECKPOINT_DIR)

#     if MERGE_LORA:
#         model = model.merge_and_unload()

#     model.eval()
#     _MODEL = model


# def _build_messages(command: str, planning_advice: str, session_log: Any, system_log: Any) -> List[Dict[str, str]]:
#     user_prompt = (
#         f"{command}\n\n"
#         f"(Planning advice / constraints): {planning_advice}\n"
#         f"(System snapshot): {_json_compact(system_log)}\n"
#     )

#     return [
#         {"role": "system", "content": TRAIN_INSTRUCTION},
#         {"role": "user", "content": user_prompt},
#     ]


# def _format_chat(tokenizer, messages: List[Dict[str, str]]) -> str:
#     if hasattr(tokenizer, "apply_chat_template"):
#         try:
#             return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
#         except Exception:
#             pass

#     parts = []
#     for m in messages:
#         parts.append(f"[{m.get('role','user').upper()}]\n{m.get('content','')}")
#     parts.append("[ASSISTANT]\n")
#     return "\n\n".join(parts)


# def _generate_local(command: str, planning_advice: str, session_log: Any, system_log: Any) -> str:
#     _load_local_model()

#     import torch

#     messages = _build_messages(command, planning_advice, session_log, system_log)
#     prompt = _format_chat(_TOKENIZER, messages)

#     if DUMP_PROMPT:
#         try:
#             with open(DUMP_PROMPT_PATH, "w", encoding="utf-8") as f:
#                 f.write(prompt)
#         except Exception:
#             pass

#     inputs = _TOKENIZER(prompt, return_tensors="pt")

#     model_device = getattr(_MODEL, "device", None)
#     if model_device is not None:
#         inputs = {k: v.to(model_device) for k, v in inputs.items()}

#     gen_kwargs = dict(
#         max_new_tokens=MAX_NEW_TOKENS,
#         do_sample=TEMPERATURE > 0,
#         temperature=TEMPERATURE,
#         top_p=TOP_P,
#         pad_token_id=_TOKENIZER.pad_token_id,
#         eos_token_id=_TOKENIZER.eos_token_id,
#     )

#     with torch.no_grad():
#         out = _MODEL.generate(**inputs, **gen_kwargs)

#     input_len = inputs["input_ids"].shape[-1]
#     gen_ids = out[0][input_len:]
#     raw = _TOKENIZER.decode(gen_ids, skip_special_tokens=True)

#     cleaned = _extract_code_block(raw)
#     return cleaned


# def render_response(command: str, planning_advice: str, session_log: Any, system_log: Any) -> str:
#     return _generate_local(command, planning_advice, session_log, system_log)





from __future__ import annotations

import os
import re
import json
from typing import Any, Dict, List, Optional

from openai import OpenAI

# =====================
# Config
# =====================
DEFAULT_RESPONSE_MODEL = os.getenv("RESPONSE_AGENT_MODEL", "gpt-4o-mini")

MAX_NEW_TOKENS = int(os.getenv("RESPONSE_AGENT_MAX_NEW_TOKENS", "512"))
TEMPERATURE = float(os.getenv("RESPONSE_AGENT_TEMPERATURE", "0.3"))
TOP_P = float(os.getenv("RESPONSE_AGENT_TOP_P", "0.95"))

DUMP_PROMPT = os.getenv("RESPONSE_AGENT_DUMP_PROMPT", "0").strip() == "1"
DUMP_PROMPT_PATH = os.getenv("RESPONSE_AGENT_DUMP_PROMPT_PATH", "response_agent_last_prompt.txt")


# =====================
# Instruction (same spirit as your FT training)
# =====================
TRAIN_INSTRUCTION = (
    "You are a Linux OS terminal. Your task is to simulate exact CLI behavior. "
    "You must only respond with the terminal output enclosed in a single code block (```), "
    "with no explanations or additional text. Do not generate any commands yourself. "
    "For each user input, respond exactly as a real Linux terminal would, including errors "
    "or empty outputs when appropriate. For invalid or non-Linux commands, return the typical shell error."
)


def init_client(api_key: Optional[str] = None) -> OpenAI:
    key = api_key or os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE"
    return OpenAI(api_key=key)


def _json_compact(obj: Any, limit: int = 20000) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        s = str(obj)
    if len(s) > limit:
        return s[:limit] + "...<truncated>"
    return s


def _extract_code_block(text: Optional[str]) -> str:
    if text is None:
        return ""

    s = text.strip()

    m = re.search(r"```[^\n]*\n?(.*?)```", s, flags=re.DOTALL)
    if m:
        inner = m.group(1)
        if inner.startswith("\n"):
            inner = inner[1:]
        return inner

    if s.startswith("```"):
        s2 = re.sub(r"^\s*```[^\n]*\n?", "", s)
        return s2

    return s


def _build_messages(
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
) -> List[Dict[str, str]]:

    user_prompt = (
        f"{command}\n\n"
        f"(Planning advice / constraints): {planning_advice}\n"
        f"(System snapshot): {_json_compact(system_log)}\n"
    )

    return [
        {"role": "system", "content": TRAIN_INSTRUCTION},
        {"role": "user", "content": user_prompt},
    ]


def _generate_gpt(
    client: OpenAI,
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
    model: Optional[str] = None,
) -> str:
    messages = _build_messages(command, planning_advice, session_log, system_log)

    # 可选：dump prompt，方便你对齐 FT 版本做对比
    if DUMP_PROMPT:
        try:
            with open(DUMP_PROMPT_PATH, "w", encoding="utf-8") as f:
                f.write(json.dumps(messages, ensure_ascii=False, indent=2))
        except Exception:
            pass

    resp = client.chat.completions.create(
        model=model or DEFAULT_RESPONSE_MODEL,
        messages=messages,
        temperature=TEMPERATURE,
        top_p=TOP_P,
        max_tokens=MAX_NEW_TOKENS,
    )

    raw = (resp.choices[0].message.content or "").strip()
    return _extract_code_block(raw)


def render_response(
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
    client: Optional[OpenAI] = None,
    model: Optional[str] = None,
) -> str:
    """
    Returns: pure terminal output text (WITHOUT ``` fences).
    """
    c = client or init_client()
    return _generate_gpt(
        client=c,
        command=command,
        planning_advice=planning_advice,
        session_log=session_log,
        system_log=system_log,
        model=model,
    )





