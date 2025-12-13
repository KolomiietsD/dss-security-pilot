# core/episode_nlp.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import json

from .bert_model import analyze_text


# ------------------------- helpers -------------------------

def _safe_json(obj: Any, max_chars: int = 700) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        try:
            s = str(obj)
        except Exception:
            return ""
    if len(s) > max_chars:
        return s[:max_chars] + "…"
    return s


def _get_nested(d: Any, path: str) -> Optional[Any]:
    """
    Простий getter по вкладених dict: "a.b.c"
    """
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _pick_first_str(*vals: Any) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


# ------------------------- text extraction -------------------------

def _extract_event_text(ev: Dict[str, Any], max_chars: int = 1200) -> str:
    """
    Витягуємо максимально інформативний текст з події.
    ВАЖЛИВО: тут додаємо не тільки "description", а й корисні поля з raw.
    """
    parts: List[str] = []

    # 1) Нормалізовані поля (якщо є)
    base = _pick_first_str(
        ev.get("description"),
        ev.get("message"),
        ev.get("short_description"),
        ev.get("title"),
    )
    if base:
        parts.append(base)

    # 2) Метадані події (нормалізовані)
    src = ev.get("source")
    sev = ev.get("severity")
    ev_type = ev.get("event_type") or ev.get("type")
    host = ev.get("hostname")
    user = ev.get("user_name")
    proc = ev.get("process_name") or ev.get("process")
    if src:
        parts.append(f"source={src}")
    if sev:
        parts.append(f"severity={sev}")
    if ev_type:
        parts.append(f"type={ev_type}")
    if host:
        parts.append(f"host={host}")
    if user:
        parts.append(f"user={user}")
    if proc:
        parts.append(f"process={proc}")

    # 3) RAW (Wazuh/CrowdStrike) — саме тут “соковиті” індикатори
    raw = ev.get("raw") or {}
    if isinstance(raw, dict):

        # 3.1) Wazuh rule / groups / mitre
        rule_desc = _pick_first_str(
            raw.get("rule_description"),
            raw.get("description"),
            raw.get("message"),
            raw.get("full_log"),
            raw.get("log"),
            raw.get("summary"),
            raw.get("EventDescription"),
        )
        rule = raw.get("rule") or {}
        if isinstance(rule, dict):
            rule_desc = _pick_first_str(rule_desc, rule.get("description"))
            rid = rule.get("id")
            lvl = rule.get("level")
            groups = rule.get("groups")
            if rid:
                parts.append(f"wazuh_rule_id={rid}")
            if lvl is not None:
                parts.append(f"wazuh_rule_level={lvl}")
            if isinstance(groups, list) and groups:
                parts.append("wazuh_groups=" + ",".join([str(x) for x in groups[:8]]))

            mitre = rule.get("mitre") or {}
            if isinstance(mitre, dict):
                tids = mitre.get("id")
                tacts = mitre.get("tactic")
                techs = mitre.get("technique")
                if isinstance(tids, list) and tids:
                    parts.append("mitre_id=" + ",".join([str(x) for x in tids[:8]]))
                if isinstance(tacts, list) and tacts:
                    parts.append("mitre_tactic=" + ",".join([str(x) for x in tacts[:8]]))
                if isinstance(techs, list) and techs:
                    parts.append("mitre_technique=" + ",".join([str(x) for x in techs[:8]]))

        if rule_desc:
            parts.append(rule_desc)

        # 3.2) Windows EventChannel (Wazuh) — eventID, channel, provider, message, userdata
        win_msg = _pick_first_str(
            _get_nested(raw, "data.win.system.message"),
            _get_nested(raw, "data.win.system.providerName"),
        )
        event_id = _get_nested(raw, "data.win.system.eventID")
        channel = _get_nested(raw, "data.win.system.channel")
        computer = _get_nested(raw, "data.win.system.computer")
        if event_id is not None:
            parts.append(f"win_event_id={event_id}")
        if channel:
            parts.append(f"win_channel={channel}")
        if computer:
            parts.append(f"win_computer={computer}")
        if win_msg and isinstance(win_msg, str) and win_msg.strip():
            parts.append(win_msg.strip())

        # 3.3) CrowdStrike (якщо є типові поля)
        cs_name = _pick_first_str(
            raw.get("tactic"),
            raw.get("technique"),
            raw.get("scenario"),
            raw.get("detect_name"),
            raw.get("name"),
        )
        if cs_name:
            parts.append(f"cs_signal={cs_name}")

        # 3.4) Витяг “підозрілих” полів якщо вони десь лежать
        # (команди, шляхи, файли, хеші, імена процесів)
        candidates = [
            "command_line",
            "cmdline",
            "process.command_line",
            "process.cmdline",
            "process.name",
            "process_path",
            "file_path",
            "filename",
            "image",
            "parent_image",
            "sha256",
            "md5",
            "registry_key",
        ]
        for key in candidates:
            v = raw.get(key)
            if v is None:
                v = _get_nested(raw, key)  # підтримка nested через "process.name"
            if isinstance(v, str) and v.strip():
                parts.append(f"{key}={v.strip()}")
            elif isinstance(v, (int, float)) and v is not None:
                parts.append(f"{key}={v}")

        # 3.5) В крайньому разі — компактний JSON raw (обрізаний)
        # Це дуже допомагає keyword-евристиці/моделі побачити "ransomware", "mimikatz", тощо,
        # які часто не в description, а всередині raw.
        parts.append("raw=" + _safe_json(raw, max_chars=700))

    text = " | ".join([p for p in parts if isinstance(p, str) and p.strip()])
    return text[:max_chars]


def _build_episode_text(ep: Dict[str, Any], max_chars: int = 1200) -> str:
    """
    Склеюємо тексти кількох подій (але тепер це тільки fallback).
    Основна оцінка йде через per-event scoring.
    """
    events: List[Dict[str, Any]] = ep.get("events") or []
    parts: List[str] = []
    for ev in events[:12]:  # не беремо сотні подій
        t = _extract_event_text(ev, max_chars=600)
        if t:
            parts.append(t)
        joined = " || ".join(parts)
        if len(joined) >= max_chars:
            return joined[:max_chars]
    return " || ".join(parts)[:max_chars]


def _label_to_ukrainian(label: str) -> str:
    if label == "benign":
        return "ймовірно нормальна / службова активність"
    if label == "suspicious":
        return "підозріла активність"
    if label == "attack":
        return "ймовірна атака / шкідлива активність"
    return "оцінка неоднозначна"


def _better_than(a: Tuple[str, float], b: Tuple[str, float]) -> bool:
    """
    Порівняння двох (label, score):
    1) attack завжди вище за suspicious/benign/unknown
    2) suspicious вище за benign/unknown
    3) далі — по score
    """
    order = {"attack": 3, "suspicious": 2, "benign": 1, "unknown": 0}
    la, sa = a
    lb, sb = b
    if order.get(la, 0) != order.get(lb, 0):
        return order.get(la, 0) > order.get(lb, 0)
    return sa > sb


# ------------------------- main -------------------------

def enrich_episodes_with_bert(episodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Додає до кожного епізоду:
      - bert_label / bert_score (сумісність з фронтендом)
      - bert_sentiment_* (нові поля)
      - bert_event_best (яка подія дала найкращий результат)
      - bert_counts (скільки яких лейблів у епізоді)
    """
    if not episodes:
        return episodes

    enriched: List[Dict[str, Any]] = []

    for ep in episodes:
        ep_copy = dict(ep)

        events: List[Dict[str, Any]] = ep_copy.get("events") or []

        best_label = "unknown"
        best_score = 0.0
        best_event: Optional[Dict[str, Any]] = None

        counts = {"attack": 0, "suspicious": 0, "benign": 0, "unknown": 0}

        # 1) Оцінюємо кожну подію окремо
        for ev in events[:80]:  # safety cap
            try:
                txt = _extract_event_text(ev, max_chars=1200)
                if not txt:
                    continue
                res = analyze_text(txt)
            except Exception:
                res = None

            if not res:
                continue

            label = (res.get("label") or "unknown").lower().strip()
            score = float(res.get("score") or 0.0)

            if label not in counts:
                label = "unknown"
            counts[label] += 1

            if _better_than((label, score), (best_label, best_score)):
                best_label, best_score = label, score
                best_event = ev

        # 2) Fallback: якщо зовсім нічого не оцінилось — пробуємо по тексту епізоду
        if best_score <= 0.0:
            try:
                ep_text = _build_episode_text(ep_copy, max_chars=1200)
                res = analyze_text(ep_text) if ep_text else None
            except Exception:
                res = None

            if res:
                best_label = (res.get("label") or "unknown").lower().strip()
                best_score = float(res.get("score") or 0.0)
                if best_label not in counts:
                    best_label = "unknown"
                counts[best_label] += 1

        # 3) Запис результатів
        if best_label:
            ep_copy["bert_label"] = best_label
            ep_copy["bert_score"] = round(float(best_score), 3)

            ep_copy["bert_sentiment_label"] = best_label
            ep_copy["bert_sentiment_label_en"] = best_label
            ep_copy["bert_sentiment_label_ua"] = _label_to_ukrainian(best_label)
            ep_copy["bert_sentiment_score"] = round(float(best_score), 3)

            # корисно для дебагу: яка подія “перемогла”
            if best_event:
                ep_copy["bert_event_best"] = {
                    "source": best_event.get("source"),
                    "severity": best_event.get("severity"),
                    "event_type": best_event.get("event_type") or best_event.get("type"),
                    "description": best_event.get("description") or best_event.get("message"),
                }
            else:
                ep_copy["bert_event_best"] = None

            ep_copy["bert_counts"] = counts
        else:
            ep_copy["bert_label"] = None
            ep_copy["bert_score"] = None

            ep_copy["bert_sentiment_label"] = None
            ep_copy["bert_sentiment_label_en"] = None
            ep_copy["bert_sentiment_label_ua"] = None
            ep_copy["bert_sentiment_score"] = None

            ep_copy["bert_event_best"] = None
            ep_copy["bert_counts"] = counts

        enriched.append(ep_copy)

    return enriched

