
# from __future__ import annotations

# import os
# import json
# import time
# from typing import Any, Dict, List, Optional, Callable, TypedDict

# from openai import OpenAI
# from datetime import datetime, timezone

# _DEFAULT_MODEL = "gpt-4o-mini"

# def set_default_model(model: str) -> None:
#     global _DEFAULT_MODEL
#     _DEFAULT_MODEL = model

# def init_client(api_key: Optional[str] = None) -> OpenAI:
#     key = api_key or os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE"
#     return OpenAI(api_key=key)

# def call_openai_json(
#     client: OpenAI,
#     messages: List[Dict[str, str]],
#     model: Optional[str] = None,
#     max_tokens: int = 64,
# ) -> Dict[str, Any]:
#     resp = client.chat.completions.create(
#         model=model or _DEFAULT_MODEL,
#         messages=messages,
#         temperature=0,
#         max_tokens=max_tokens,
#         response_format={"type": "json_object"},
#     )
#     content = resp.choices[0].message.content
#     return json.loads(content)

# def call_openai_text(
#     client: OpenAI,
#     messages: List[Dict[str, str]],
#     model: Optional[str] = None,
#     temperature: float = 0.0,
#     max_tokens: int = 512,
# ) -> str:
#     resp = client.chat.completions.create(
#         model=model or _DEFAULT_MODEL,
#         messages=messages,
#         temperature=temperature,
#         max_tokens=max_tokens,
#     )
#     return (resp.choices[0].message.content or "").strip()


# import torch
# from transformers import AutoTokenizer, AutoModelForSequenceClassification

# _FT_MODEL_PATH = r"D:\HoneyAgents\classify_model\modernbert_par_2_jaur_1"

# ID2LABEL = {0: "read", 1: "write", 2: "rejection"}
# LABEL2ID = {v: k for k, v in ID2LABEL.items()}

# class LocalClassifier:
#     def __init__(self, model_dir: str = _FT_MODEL_PATH, device: Optional[str] = None):
#         self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
#         self.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
#         self.model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
#         self.model.to(self.device)
#         self.model.eval()

#     @torch.no_grad()
#     def predict_label(self, text: str) -> str:
#         inputs = self.tokenizer(
#             text,
#             truncation=True,
#             max_length=256,
#             padding="max_length",
#             return_tensors="pt",
#         ).to(self.device)
#         logits = self.model(**inputs).logits
#         pred_id = int(torch.argmax(logits, dim=-1).item())
#         return ID2LABEL.get(pred_id, "rejection")

# _classifier: Optional[LocalClassifier] = None

# def _get_classifier() -> LocalClassifier:
#     global _classifier
#     if _classifier is None:
#         _classifier = LocalClassifier()
#     return _classifier

# def validate_command(
#     client: OpenAI,           
#     command: str,
#     model: Optional[str] = None,
#     retries: int = 1,
#     retry_base_sleep: float = 0.0,
# ) -> str:
#     try:
#         clf = _get_classifier()
#         return clf.predict_label(command)
#     except Exception:
#         return "rejection"


# try:
#     from history_pruning import OnlinePruner
# except Exception:
#     OnlinePruner = None  

# class PlanningRuntime:

#     def __init__(self, K: int = 30):
#         self.K = K
#         self.t = 0
#         self.pruner = OnlinePruner(K=K) if OnlinePruner is not None else None

#     def get_pruned_history(self) -> List[Dict[str, Any]]:
#         if self.pruner is None:
#             return []
#         kept = sorted(self.pruner.W, key=lambda e: e.t)
#         return [{"t": e.t, "command": e.command, "response": e.response} for e in kept]

#     def step(
#         self,
#         command: str,
#         response: str,
#         pre_snapshot: Dict[str, Any],
#         post_snapshot: Dict[str, Any],
#     ) -> None:
#         self.t += 1
#         if self.pruner is None:
#             return
#         self.pruner.step(
#             t=self.t,
#             command=command,
#             response=response,
#             s_prev=pre_snapshot,
#             s_cur=post_snapshot,
#         )



# def plan_terminal_response(
#     client: OpenAI,
#     command: str,
#     current_path: str,
#     file_tree: Dict[str, Any],
#     pruned_history: Optional[List[Dict[str, Any]]] = None,
#     pre_snapshot: Optional[Dict[str, Any]] = None,
#     post_snapshot: Optional[Dict[str, Any]] = None,
#     model: Optional[str] = None,
#     temperature: float = 0.0,
#     max_tokens: int = 512,
# ) -> str:


#     now_utc = datetime.now(timezone.utc)
#     now_local = now_utc.astimezone()
#     system_time = {
#         "utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
#         "local": now_local.isoformat(),
#     }

#     system_state = {
#         "current_path": current_path,
#         "file_tree": file_tree,
#         "system_time": system_time,
#         "history_pruned": pruned_history or [],
#         "pre_snapshot": pre_snapshot or {},
#         "post_snapshot": post_snapshot or {},
#     }

#     SYSTEM_PROMPT_PLAN = (
#         "You are the Strategic Agent for a Linux terminal.\n"
#         "Task: Produce the exact terminal output and response advice.\n"
#         "You MUST be consistent with the provided snapshot and the interaction history.\n\n"
#         "Single source of truth (snapshot):\n"
#         "- If a path/name is not present in the snapshot, it does not exist.\n"
#         "- Never assume anything not explicitly present in the snapshot.\n\n"
#         "Read snapshot:\n"
#         "- snapshot is a JSON object that contains at least:\n"
#         "  * cwd: current working directory (string)\n"
#         "  * filesystem: directory tree (absolute paths / nested nodes)\n"
#         "  * (optional) processes/services/network/vulnerabilities/plan_log\n"
#         "- Resolve relative paths using snapshot.cwd.\n"
#         "- Use permissions/owner/timestamps/content fingerprints if provided.\n\n"
#         "Output requirements:\n"
#         "- Output the parsed version of the current command, along with suggested responses.\n"
#         "- Do NOT echo or repeat the input command.\n"
#         "- Preserve realistic terminal formatting (exact newlines, spacing, canonical error messages).\n"
#         "- Do not ask questions.\n\n"
#         "Strict constraints:\n"
#         "- Do NOT invent nonexistent files/dirs/permissions/users/processes/ports.\n"
#         "- Do NOT invent new state changes.\n"
#         "- When uncertain, prefer a safe canonical failure message (e.g., 'No such file or directory').\n"
#     )


#     messages = [
#         {"role": "system", "content": SYSTEM_PROMPT_PLAN},
#         {
#             "role": "user",
#             "content": json.dumps(
#                 {"command": command, "system_state": system_state},
#                 ensure_ascii=False,
#             ),
#         },
#     ]

#     return call_openai_text(
#         client=client,
#         messages=messages,
#         model=model or _DEFAULT_MODEL,
#         temperature=temperature,
#         max_tokens=max_tokens,
#     )



# class RouteResult(TypedDict, total=False):
#     classification: str
#     dispatched_to: str
#     planned_text: str
#     handler_result: Any
#     passthrough: str

# def route_command(
#     client: OpenAI,
#     command: str,
#     current_path: str,
#     file_tree: Dict[str, Any],
#     pruned_history: List[Dict[str, Any]],
#     pre_snapshot: Dict[str, Any],
#     post_snapshot: Dict[str, Any],
#     on_safe_fs: Callable[[str], Any],
#     model: Optional[str] = None,
# ) -> RouteResult:
#     label = validate_command(client, command, model=model)

#     if label == "read":
#         planned = plan_terminal_response(
#             client=client,
#             command=command,
#             current_path=current_path,
#             file_tree=file_tree,
#             pruned_history=pruned_history,
#             pre_snapshot=pre_snapshot,
#             post_snapshot=post_snapshot,
#             model=model,
#         )
#         return RouteResult(classification="read", dispatched_to="read", planned_text=planned)

#     if label == "write":
#         res = on_safe_fs(command)
#         return RouteResult(classification="write", dispatched_to="write", handler_result=res)

#     return RouteResult(classification="rejection", dispatched_to="rejection", passthrough=command)













from __future__ import annotations

import os
import json
import time
from typing import Any, Dict, List, Optional, Callable, TypedDict

from openai import OpenAI
from datetime import datetime, timezone

_DEFAULT_MODEL = "gpt-4o-mini"

def set_default_model(model: str) -> None:
    global _DEFAULT_MODEL
    _DEFAULT_MODEL = model

def init_client(api_key: Optional[str] = None) -> OpenAI:
    key = api_key or os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE"
    return OpenAI(api_key=key)

def call_openai_json(
    client: OpenAI,
    messages: List[Dict[str, str]],
    model: Optional[str] = None,
    max_tokens: int = 64,
) -> Dict[str, Any]:
    resp = client.chat.completions.create(
        model=model or _DEFAULT_MODEL,
        messages=messages,
        temperature=0,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )
    content = resp.choices[0].message.content
    return json.loads(content)

def call_openai_text(
    client: OpenAI,
    messages: List[Dict[str, str]],
    model: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> str:
    resp = client.chat.completions.create(
        model=model or _DEFAULT_MODEL,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return (resp.choices[0].message.content or "").strip()



import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_MODEL_PATH = os.path.join(_BASE_DIR, "model", "ModernBERT-base_jaur_1")
_FT_MODEL_PATH = os.getenv("CLASSIFIER_MODEL_DIR", _DEFAULT_MODEL_PATH)

ID2LABEL = {0: "safe", 1: "safe-fs", 2: "unsafe"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}

class LocalClassifier:
    def __init__(self, model_dir: str = _FT_MODEL_PATH, device: Optional[str] = None):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()

    @torch.no_grad()
    def predict_label(self, text: str) -> str:
        inputs = self.tokenizer(
            text,
            truncation=True,
            max_length=256,
            padding="max_length",
            return_tensors="pt",
        ).to(self.device)
        logits = self.model(**inputs).logits
        pred_id = int(torch.argmax(logits, dim=-1).item())
        return ID2LABEL.get(pred_id, "unsafe")

_classifier: Optional[LocalClassifier] = None

def _get_classifier() -> LocalClassifier:
    global _classifier
    if _classifier is None:
        _classifier = LocalClassifier()
    return _classifier

def validate_command(
    client: OpenAI,           # kept for API compatibility
    command: str,
    model: Optional[str] = None,
    retries: int = 1,
    retry_base_sleep: float = 0.0,
) -> str:
    """
    Return one of: safe / safe-fs / unsafe
    """
    try:
        clf = _get_classifier()
        return clf.predict_label(command)
    except Exception:
        return "unsafe"


try:
    from history_pruning import OnlinePruner
except Exception:
    OnlinePruner = None

class PlanningRuntime:
    def __init__(self, K: int = 30):
        self.K = K
        self.t = 0
        self.pruner = OnlinePruner(K=K) if OnlinePruner is not None else None

    def get_pruned_history(self) -> List[Dict[str, Any]]:
        if self.pruner is None:
            return []
        kept = sorted(self.pruner.W, key=lambda e: e.t)
        return [{"t": e.t, "command": e.command, "response": e.response} for e in kept]

    def step(
        self,
        command: str,
        response: str,
        pre_snapshot: Dict[str, Any],
        post_snapshot: Dict[str, Any],
    ) -> None:
        self.t += 1
        if self.pruner is None:
            return
        self.pruner.step(
            t=self.t,
            command=command,
            response=response,
            s_prev=pre_snapshot,
            s_cur=post_snapshot,
        )


def plan_terminal_response(
    client: OpenAI,
    command: str,
    current_path: str,
    file_tree: Dict[str, Any],
    pruned_history: Optional[List[Dict[str, Any]]] = None,
    pre_snapshot: Optional[Dict[str, Any]] = None,
    post_snapshot: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> str:
    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone()
    system_time = {
        "utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "local": now_local.isoformat(),
    }

    system_state = {
        "current_path": current_path,
        "file_tree": file_tree,
        "system_time": system_time,
        "history_pruned": pruned_history or [],
        "pre_snapshot": pre_snapshot or {},
        "post_snapshot": post_snapshot or {},
    }

    SYSTEM_PROMPT_PLAN = (
        "You are the Strategic Agent for a Linux terminal.\n"
        "Task: Produce the exact terminal output text for the given command.\n"
        "You MUST be consistent with the provided snapshot and the interaction history.\n\n"
        "Single source of truth (snapshot):\n"
        "- If a path/name is not present in the snapshot, it does not exist.\n"
        "- Never assume anything not explicitly present in the snapshot.\n\n"
        "Read snapshot:\n"
        "- snapshot is a JSON object that contains at least:\n"
        "  * cwd: current working directory (string)\n"
        "  * filesystem: directory tree (absolute paths / nested nodes)\n"
        "  * (optional) processes/services/network/vulnerabilities/plan_log\n"
        "- Resolve relative paths using snapshot.cwd.\n"
        "- Use permissions/owner/timestamps/content fingerprints if provided.\n\n"
        "Output requirements:\n"
        "- Output ONLY the terminal response text.\n"
        "- Do NOT echo or repeat the input command.\n"
        "- Preserve realistic terminal formatting (exact newlines, spacing, canonical error messages).\n"
        "- Do not ask questions.\n\n"
        "Strict constraints:\n"
        "- Do NOT invent nonexistent files/dirs/permissions/users/processes/ports.\n"
        "- Do NOT invent new state changes.\n"
        "- When uncertain, prefer a safe canonical failure message (e.g., 'No such file or directory').\n"
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_PLAN},
        {
            "role": "user",
            "content": json.dumps(
                {"command": command, "system_state": system_state},
                ensure_ascii=False,
            ),
        },
    ]

    return call_openai_text(
        client=client,
        messages=messages,
        model=model or _DEFAULT_MODEL,
        temperature=temperature,
        max_tokens=max_tokens,
    )


class RouteResult(TypedDict, total=False):
    classification: str
    dispatched_to: str
    planned_text: str
    handler_result: Any
    passthrough: str

def route_command(
    client: OpenAI,
    command: str,
    current_path: str,
    file_tree: Dict[str, Any],
    pruned_history: List[Dict[str, Any]],
    pre_snapshot: Dict[str, Any],
    post_snapshot: Dict[str, Any],
    on_safe_fs: Callable[[str], Any],
    model: Optional[str] = None,
) -> RouteResult:
    """
    - safe    -> planning LLM generates terminal text
    - safe-fs -> deterministic FS handler (snapshot mutation)
    - unsafe  -> passthrough / blocked path
    """
    label = validate_command(client, command, model=model)

    if label == "safe":
        planned = plan_terminal_response(
            client=client,
            command=command,
            current_path=current_path,
            file_tree=file_tree,
            pruned_history=pruned_history,
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
            model=model,
        )
        return RouteResult(classification="safe", dispatched_to="safe", planned_text=planned)

    if label == "safe-fs":
        res = on_safe_fs(command)
        return RouteResult(classification="safe-fs", dispatched_to="safe-fs", handler_result=res)

    return RouteResult(classification="unsafe", dispatched_to="unsafe", passthrough=command)
