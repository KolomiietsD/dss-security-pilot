# core/unified_events.py
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from .wazuh_api import get_normalized_wazuh_alerts
from .crowdstrike_api import get_normalized_cs_alerts


def _parse_ts(ts: str | None) -> datetime | None:
    """
    Акуратно парсимо ISO-час. Повертаємо datetime в UTC або None.
    """
    if not ts:
        return None

    # найчастіше формат типу "2025-12-07T05:21:32.665+0200" або з "Z"
    try:
        # Замінимо Z на +00:00, якщо є
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        # Якщо немає двокрапки в таймзоні, наприклад +0200 -> +02:00
        if len(ts) > 5 and (ts[-5] in ["+", "-"]) and ts[-3] != ":":
            ts = ts[:-2] + ":" + ts[-2:]
        dt = datetime.fromisoformat(ts)
        # приводимо до UTC, якщо є tzinfo
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _severity_to_score(sev: str | None) -> int:
    """
    Грубе перетворення текстової severity у число для агрегації.
    0 = unknown/info, 1 = low, 2 = medium, 3 = high, 4 = critical
    """
    if not sev:
        return 0
    s = sev.lower()
    if s.startswith("crit"):
        return 4
    if s.startswith("high"):
        return 3
    if s.startswith("med"):
        return 2
    if s.startswith("low"):
        return 1
    # info / informational / unknown
    return 0


def _compute_episode_risk(
    max_severity: str | None,
    num_events: int,
    num_wazuh: int,
    num_crowdstrike: int,
) -> float:
    """
    Оцінка ризику епізоду в діапазоні 0..1.

    Інтуїція:
      - 60% ваги: максимальна небезпека серед подій (severity)
      - 30% ваги: кількість подій (чим більше, тим гірше, до 10 подій)
      - 10% ваги: якщо епізод містить і Wazuh, і CrowdStrike
    """
    sev_score = _severity_to_score(max_severity)  # 0..4
    sev_component = sev_score / 4.0 if sev_score > 0 else 0.0

    volume_component = min(1.0, float(num_events) / 10.0) if num_events > 0 else 0.0

    sources_component = 1.0 if (num_wazuh > 0 and num_crowdstrike > 0) else 0.0

    risk = (
        0.6 * sev_component
        + 0.3 * volume_component
        + 0.1 * sources_component
    )

    # Округляємо для краси
    return round(risk, 3)


def get_unified_events(limit_per_source: int = 200) -> List[Dict[str, Any]]:
    """
    Повертає єдиний список нормалізованих подій з Wazuh + CrowdStrike.
    Кожна подія має принаймні:
      - source: "wazuh" / "crowdstrike"
      - hostname
      - timestamp (ISO-рядок)
      - severity
      - description / message тощо
    """
    wazuh_events = get_normalized_wazuh_alerts(limit=limit_per_source)
    cs_events = get_normalized_cs_alerts(limit=limit_per_source)

    unified: List[Dict[str, Any]] = []

    for ev in wazuh_events:
        ev = dict(ev)  # захист від випадкових посилань
        ev.setdefault("source", "wazuh")
        unified.append(ev)

    for ev in cs_events:
        ev = dict(ev)
        ev.setdefault("source", "crowdstrike")
        unified.append(ev)

    return unified


def group_events_by_time_window(
    events: List[Dict[str, Any]],
    window_seconds: int = 90,
) -> List[Dict[str, Any]]:
    """
    Групує події у "епізоди" за принципом:
      - окремо по кожному hostname
      - всередині хоста події сортуються за часом
      - поки різниця між сусідніми подіями <= window_seconds, вони в одному епізоді
      - якщо більша — починається новий епізод

    Повертає список епізодів у форматі:
      {
        "hostname": str,
        "start_time": str (ISO, UTC),
        "end_time": str (ISO, UTC),
        "duration_sec": float,
        "num_events": int,
        "num_events_wazuh": int,
        "num_events_crowdstrike": int,
        "max_severity": str | None,
        "risk_score": float (0..1),
        "has_wazuh": bool,
        "has_crowdstrike": bool,
        "events": [ ...оригінальні події... ],
      }
    """
    # 1. Розкласти по hostname
    events_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        host = ev.get("hostname") or ev.get("host") or "(unknown)"
        events_by_host.setdefault(host, []).append(ev)

    all_episodes: List[Dict[str, Any]] = []
    window = timedelta(seconds=window_seconds)

    for hostname, host_events in events_by_host.items():
        # 2. Відсортувати події по часу
        enriched: List[Dict[str, Any]] = []
        for ev in host_events:
            dt = _parse_ts(ev.get("timestamp") or ev.get("time"))
            if dt is None:
                # пропускаємо події без валідного часу
                continue
            new_ev = dict(ev)
            new_ev["_dt"] = dt
            enriched.append(new_ev)

        if not enriched:
            continue

        enriched.sort(key=lambda e: e["_dt"])

        # 3. Йдемо по подіях і формуємо епізоди
        current_cluster: List[Dict[str, Any]] = [enriched[0]]

        for ev in enriched[1:]:
            prev = current_cluster[-1]
            if ev["_dt"] - prev["_dt"] <= window:
                current_cluster.append(ev)
            else:
                # закриваємо поточний епізод
                all_episodes.append(_build_episode_dict(hostname, current_cluster))
                # починаємо новий
                current_cluster = [ev]

        # останній епізод
        if current_cluster:
            all_episodes.append(_build_episode_dict(hostname, current_cluster))

    # глобально — від найстаршого до найновішого
    all_episodes.sort(key=lambda ep: ep.get("start_time") or "")
    return all_episodes


def _build_episode_dict(
    hostname: str,
    cluster: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Допоміжна функція: з кластера подій будує агрегований епізод.
    """
    if not cluster:
        return {}

    start_dt = cluster[0]["_dt"]
    end_dt = cluster[-1]["_dt"]
    duration = (end_dt - start_dt).total_seconds()

    num_events = len(cluster)
    num_wz = sum(1 for e in cluster if e.get("source") == "wazuh")
    num_cs = sum(1 for e in cluster if e.get("source") == "crowdstrike")

    # максимум по severity
    max_score = -1
    max_sev: str | None = None
    for e in cluster:
        sev = e.get("severity")
        sc = _severity_to_score(sev)
        if sc > max_score:
            max_score = sc
            max_sev = sev

    # ризик епізоду 0..1
    risk_score = _compute_episode_risk(
        max_severity=max_sev,
        num_events=num_events,
        num_wazuh=num_wz,
        num_crowdstrike=num_cs,
    )

    # прибираємо службове поле перед поверненням
    cleaned_events: List[Dict[str, Any]] = []
    for e in cluster:
        e = dict(e)
        e.pop("_dt", None)
        cleaned_events.append(e)

    return {
        "hostname": hostname,
        "start_time": start_dt.isoformat(),
        "end_time": end_dt.isoformat(),
        "duration_sec": duration,
        "num_events": num_events,
        "num_events_wazuh": num_wz,
        "num_events_crowdstrike": num_cs,
        "max_severity": max_sev,
        "risk_score": risk_score,
        "has_wazuh": num_wz > 0,
        "has_crowdstrike": num_cs > 0,
        "events": cleaned_events,
    }
