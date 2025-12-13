# core/bert_model.py
from __future__ import annotations

from typing import Optional, Dict
import os
import re
import logging

logger = logging.getLogger(__name__)

# -------------------- keyword fallback (твій словник) --------------------
ATTACK_KEYWORDS = [
    r"mimikatz", r"ransomware", r"crypto[- ]?locker", r"cobalt strike",
    r"meterpreter", r"invoke-mimikatz", r"credential theft", r"\blsass\b",
    r"dump lsass", r"brute force", r"bruteforce", r"sql injection",
    r"reverse shell", r"command and control", r"\bc2\b",
]

SUSPICIOUS_KEYWORDS = [
    r"failed logon", r"failed login", r"multiple logon failures",
    r"privilege escalation", r"lateral movement", r"unusual process",
    r"suspicious process", r"suspicious command", r"remote desktop",
    r"rdp", r"admin share", r"psexec", r"\bwmic\b", r"\bwmi\b",
]

BENIGN_KEYWORDS = [
    r"windows logon", r"user logon", r"user login",
    r"service started", r"service stopped", r"group policy",
    r"software update", r"antivirus update", r"system reboot",
]

def _match_any(patterns, text_lower: str) -> bool:
    for p in patterns:
        if re.search(p, text_lower):
            return True
    return False

def _fallback_keywords(text: str) -> Optional[Dict[str, object]]:
    if not text or not text.strip():
        return None
    t = text.strip().lower()

    if _match_any(ATTACK_KEYWORDS, t):
        return {"label": "attack", "label_en": "Attack indicators (keyword)", "score": 0.95}
    if _match_any(SUSPICIOUS_KEYWORDS, t):
        return {"label": "suspicious", "label_en": "Suspicious indicators (keyword)", "score": 0.80}
    if _match_any(BENIGN_KEYWORDS, t):
        return {"label": "benign", "label_en": "Likely benign (keyword)", "score": 0.65}
    return {"label": "unknown", "label_en": "No clear indicators (keyword)", "score": 0.45}

# -------------------- real transformer (optional) --------------------
# Можеш задати свою модель через ENV:
#   BERT_MODEL_NAME=...  (наприклад distilbert-base-uncased)
MODEL_NAME = os.environ.get("BERT_MODEL_NAME", "distilbert-base-uncased")

_transformer_ready = False
_tokenizer = None
_model = None

def _lazy_init_transformer() -> None:
    global _transformer_ready, _tokenizer, _model
    if _transformer_ready:
        return
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch  # noqa

        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        _model.eval()
        _transformer_ready = True
        logger.info("Loaded transformer model: %s", MODEL_NAME)
    except Exception as exc:
        logger.warning("Transformer not available, using keyword fallback only. Reason: %s", exc)
        _transformer_ready = False
        _tokenizer = None
        _model = None

def _softmax(logits):
    import math
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    return [e / s for e in exps]

def analyze_text(text: str) -> Optional[Dict[str, object]]:
    """
    Повертає:
      { label: benign|suspicious|attack|unknown, label_en: str, score: 0..1 }
    """
    if not text or not text.strip():
        return None

    # 1) Спочатку швидкий keyword-trigger: якщо явна атака — одразу attack
    kw = _fallback_keywords(text)
    if kw and kw["label"] == "attack":
        return kw

    # 2) Пробуємо реальний Transformer
    _lazy_init_transformer()
    if _transformer_ready and _tokenizer and _model:
        try:
            import torch
            inputs = _tokenizer(
                text[:2000],  # обрізаємо, щоб не вбивати модель
                return_tensors="pt",
                truncation=True,
                max_length=256,
            )
            with torch.no_grad():
                out = _model(**inputs)
                logits = out.logits[0].tolist()

            # ⚠️ Тут важливо: базові моделі можуть бути не “security classification”.
            # Якщо модель має 2 класи -> це просто “клас0/клас1”.
            # Тому ми робимо "калібрування": беремо впевненість як max softmax.
            probs = _softmax(logits)
            conf = float(max(probs))

            # Якщо модель дуже невпевнена — повертаємось на словник.
            if conf < 0.55 and kw:
                return kw

            # Мапінг у 4 класи:
            # - якщо keyword каже suspicious/benign — використаємо його label,
            #   а score піднімемо/опустимо за conf.
            if kw and kw["label"] in {"suspicious", "benign"}:
                return {
                    "label": kw["label"],
                    "label_en": f"{kw['label_en']} + transformer_conf",
                    "score": round(max(kw["score"], min(0.95, conf)), 3),
                }

            # Інакше — unknown, але зі score від conf
            return {
                "label": "unknown",
                "label_en": "Transformer confidence (no keywords)",
                "score": round(min(0.95, max(0.35, conf)), 3),
            }
        except Exception as exc:
            logger.warning("Transformer inference failed, fallback to keywords. Reason: %s", exc)

    # 3) Fallback
    return kw
