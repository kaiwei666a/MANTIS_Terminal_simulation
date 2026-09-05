
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import torch
from openai import OpenAI
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from terminal_config import CLASSIFIER_MODEL_DIR

logger = logging.getLogger(__name__)

try:
    from agents.history_pruning import OnlinePruner
except Exception:
    OnlinePruner = None


def init_client(api_key: Optional[str] = None) -> OpenAI:
    key = api_key or os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE"
    return OpenAI(api_key=key)

ID2LABEL = {0: "read", 1: "write", 2: "rejection"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}


class LocalClassifier:
    def __init__(self, model_dir: str = CLASSIFIER_MODEL_DIR, device: Optional[str] = None):
        if not os.path.isdir(model_dir):
            raise FileNotFoundError(
                f"Classifier model directory does not exist: {model_dir}. "
                "Place the model in model/modernbert_par_2_jaur_1 or set CLASSIFIER_MODEL_DIR."
            )
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()
        logger.info("Local classifier loaded from %s on %s", model_dir, self.device)

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
        return ID2LABEL.get(pred_id, "rejection")


_classifier: Optional[LocalClassifier] = None


def _get_classifier() -> LocalClassifier:
    global _classifier
    if _classifier is None:
        _classifier = LocalClassifier()
    return _classifier


def validate_command(
    _client: OpenAI,
    command: str,
) -> str:
    try:
        clf = _get_classifier()
        label = clf.predict_label(command)
        if label in {"read", "write", "rejection"}:
            return label
        return "read"
    except Exception:
        logger.exception(
            "Local classifier failed (model directory: %s); falling back to read. "
            "Check CLASSIFIER_MODEL_DIR, model files, and runtime dependencies.",
            CLASSIFIER_MODEL_DIR,
        )
        return "read"


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
