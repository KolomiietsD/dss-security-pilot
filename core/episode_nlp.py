from __future__ import annotations

from typing import Any, Dict, List, Optional

from .bert_model import analyze_text


def _extract_event_text(ev: Dict[str, Any]) -> str:
    """
    Витягуємо «людський» текст з події:
    description / message / title / rule.description / summary ...
    """
    # Уже нормалізовані поля
    for key in ("description", "message", "short_description", "title"):
        val = ev.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    raw = ev.get("raw") or {}
    if isinstance(raw, dict):
        # Спробуємо типові поля з Wazuh / CrowdStrike
        for key in (
                "description",
                "message",
                "log",
                "full_log",
                "rule_description",
                "summary",
                "EventDescription",
        ):
            val = raw.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Wazuh rule.description
        rule = raw.get("rule") or {}
        if isinstance(rule, dict):
            desc = rule.get("description")
            if isinstance(desc, str) and desc.strip():
                return desc.strip()

    # fallback – нічого нормального не знайшли
    return ""


def _build_episode_text(ep: Dict[str, Any], max_chars: int = 800) -> str:
    """
    Склеюємо кілька описів подій в один короткий текст епізоду.
    """
    events: List[Dict[str, Any]] = ep.get("events") or []
    parts: List[str] = []

    for ev in events:
        t = _extract_event_text(ev)
        if not t:
            continue
        parts.append(t)
        joined = " ".join(parts)
        if len(joined) >= max_chars:
            return joined[:max_chars]

    return " ".join(parts)[:max_chars]


def _label_to_ukrainian(label: str) -> str:
    """
    Перекладаємо внутрішню мітку у короткий україномовний опис.
    Для твоєї BERT-моделі це не XNLI, але хай буде fallback.
    """
    if label == "benign":
        return "ймовірно нормальний / службовий епізод"
    if label == "suspicious":
        return "підозрілий інцидент інформаційної безпеки"
    if label == "attack":
        return "ймовірна атака або шкідлива активність"
    return "оцінка неоднозначна"


def enrich_episodes_with_bert(
        episodes: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Обробляє всі епізоди і додає ключі:

      (нові поля)
      - bert_sentiment_label
      - bert_sentiment_label_en
      - bert_sentiment_label_ua
      - bert_sentiment_score

      (старі поля — для сумісності з фронтендом)
      - bert_label
      - bert_score
    """

    if not episodes:
        return episodes

    enriched: List[Dict[str, Any]] = []

    for ep in episodes:
        ep_copy = dict(ep)

        # ------------------------------------------------------
        # 1. Формуємо текст епізоду
        # ------------------------------------------------------
        try:
            text = _build_episode_text(ep_copy)
            bert_res: Optional[Dict[str, Any]] = analyze_text(text) if text else None
        except Exception:
            bert_res = None

        # ------------------------------------------------------
        # 2. Якщо модель щось повернула — зберігаємо результат
        # ------------------------------------------------------
        if bert_res:

            # Наприклад:
            # {"label": "4 stars", "score": 0.87}
            label = bert_res.get("label") or "unknown"
            score = float(bert_res.get("score") or 0.0)

            # старі ключі (фронтенд епізодів очікує саме їх)
            ep_copy["bert_label"] = label
            ep_copy["bert_score"] = score

            # нові ключі
            ep_copy["bert_sentiment_label"] = label
            ep_copy["bert_sentiment_label_en"] = label
            ep_copy["bert_sentiment_label_ua"] = _label_to_ukrainian(label)
            ep_copy["bert_sentiment_score"] = round(score, 3)

        else:
            # Порожні значення, щоб фронтенд не падав
            ep_copy["bert_label"] = None
            ep_copy["bert_score"] = None

            ep_copy["bert_sentiment_label"] = None
            ep_copy["bert_sentiment_label_en"] = None
            ep_copy["bert_sentiment_label_ua"] = None
            ep_copy["bert_sentiment_score"] = None

        enriched.append(ep_copy)

    return enriched
