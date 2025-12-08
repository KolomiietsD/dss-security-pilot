# core/episode_ml.py
from __future__ import annotations

from typing import Any, Dict, List

from sklearn.cluster import KMeans

from .unified_events import _severity_to_score


def build_episode_features(episode: Dict[str, Any]) -> List[float]:
    """
    Будує вектор ознак для одного епізоду.

    Ознаки:
      0: duration_sec
      1: num_events
      2: num_events_wazuh
      3: num_events_crowdstrike
      4: max_severity_score (0..4)
      5: unique_users
      6: unique_processes
      7: unique_sources
    """
    duration = float(episode.get("duration_sec") or 0.0)
    num_events = float(episode.get("num_events") or 0)
    num_wz = float(episode.get("num_events_wazuh") or 0)
    num_cs = float(episode.get("num_events_crowdstrike") or 0)

    max_sev = episode.get("max_severity")
    sev_score = float(_severity_to_score(max_sev))

    events = episode.get("events") or []

    users = {
        e.get("user_name")
        for e in events
        if e.get("user_name")
    }
    procs = {
        e.get("process_name") or e.get("process")
        for e in events
        if (e.get("process_name") or e.get("process"))
    }
    sources = {
        e.get("source")
        for e in events
        if e.get("source")
    }

    unique_users = float(len(users))
    unique_processes = float(len(procs))
    unique_sources = float(len(sources))

    return [
        duration,
        num_events,
        num_wz,
        num_cs,
        sev_score,
        unique_users,
        unique_processes,
        unique_sources,
    ]


def analyze_episodes(
    episodes: List[Dict[str, Any]],
    n_clusters: int = 3,
) -> List[Dict[str, Any]]:
    """
    Проганяє епізоди через k-means і рахує risk_score / risk_level.

    Повертає список епізодів з додатковими полями:
      - cluster_id: int
      - risk_score: float [0,1]
      - risk_level: "low" | "medium" | "high"
    """
    if not episodes:
        return []

    feature_vectors: List[List[float]] = [
        build_episode_features(ep) for ep in episodes
    ]

    effective_k = min(max(1, n_clusters), len(feature_vectors))

    if effective_k == 1:
        labels = [0 for _ in feature_vectors]
    else:
        kmeans = KMeans(
            n_clusters=effective_k,
            random_state=42,
            n_init=10,
        )
        labels = kmeans.fit_predict(feature_vectors)

    analyzed: List[Dict[str, Any]] = []

    for ep, label, feats in zip(episodes, labels, feature_vectors):
        (
            duration,
            num_events,
            num_wz,
            num_cs,
            sev_score,
            uniq_users,
            uniq_procs,
            uniq_sources,
        ) = feats

        # Нормалізовані частини ризику
        sev_norm = (sev_score / 4.0) if sev_score > 0 else 0.0
        length_norm = min(num_events / 10.0, 1.0)
        cs_norm = 1.0 if num_cs > 0 else 0.0
        diversity_norm = min((uniq_users + uniq_procs) / 10.0, 1.0)

        risk_score = (
            sev_norm * 0.5
            + length_norm * 0.2
            + cs_norm * 0.2
            + diversity_norm * 0.1
        )
        if risk_score >= 0.7:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"

        enriched = dict(ep)
        enriched["cluster_id"] = int(label)
        enriched["risk_score"] = round(float(risk_score), 3)
        enriched["risk_level"] = risk_level

        analyzed.append(enriched)

    return analyzed
