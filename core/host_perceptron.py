# core/host_perceptron.py
from __future__ import annotations

import os
import pickle
import logging
import math
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "ai_perceptron.pkl"


# ============================================================================
#                         ФІЧІ З ЕПІЗОДІВ ДЛЯ КОЖНОГО ХОСТА
# ============================================================================

def extract_host_features(episodes: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Формує словник:
        { hostname_norm : { feature_name : value, ... } }

    Очікується, що епізод має хоча б:
      - hostname  (або ми спробуємо дістати з events)
      - risk_score
      - cluster_id
      - bert_sentiment_label (або bert_label)
      - events: list
    """
    host_data: Dict[str, Dict[str, Any]] = {}

    for ep in episodes or []:
        hostname = (ep.get("hostname") or "").strip().lower()

        # fallback: якщо hostname нема на рівні епізоду — пробуємо взяти з першої події
        if not hostname:
            events = ep.get("events") or []
            if isinstance(events, list) and events:
                ev0 = events[0] if isinstance(events[0], dict) else {}
                hostname = (ev0.get("hostname") or ev0.get("agent_name") or "").strip().lower()

        if not hostname:
            continue

        if hostname not in host_data:
            host_data[hostname] = {
                "episodes_count": 0,
                "risk_sum": 0.0,
                "risk_max": 0.0,
                "cluster_0": 0,
                "cluster_1": 0,
                "cluster_2": 0,
                "bert_negative": 0,
                "bert_suspicious": 0,
                "bert_attack": 0,
            }

        h = host_data[hostname]
        h["episodes_count"] += 1

        risk = float(ep.get("risk_score") or 0.0)
        h["risk_sum"] += risk
        h["risk_max"] = max(h["risk_max"], risk)

        cl = ep.get("cluster_id")
        if cl in (0, 1, 2):
            h[f"cluster_{cl}"] += 1

        # BERT класи (підтримуємо кілька назв поля)
        bert = (ep.get("bert_sentiment_label") or ep.get("bert_label") or "").lower()
        if "attack" in bert:
            h["bert_attack"] += 1
        elif "suspicious" in bert:
            h["bert_suspicious"] += 1
        elif "negative" in bert:
            h["bert_negative"] += 1

    return host_data


# ============================================================================
#                             WEAK LABELS (самомітки)
# ============================================================================

def generate_weak_labels(features: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """
    Створює слабкі мітки:
        0 = low
        1 = medium
        2 = high
        3 = critical
    """
    labels: Dict[str, int] = {}

    for hostname, f in (features or {}).items():
        # якщо все нуль — мітка low
        score = (
            0.45 * min(float(f.get("risk_max", 0.0)), 1.0)
            + 0.25 * min(float(f.get("episodes_count", 0.0)) / 10.0, 1.0)
            + 0.20 * min((float(f.get("bert_attack", 0.0)) * 0.6 + float(f.get("bert_suspicious", 0.0)) * 0.3), 1.0)
            + 0.10 * min((float(f.get("cluster_1", 0.0)) + float(f.get("cluster_2", 0.0))) / 5.0, 1.0)
        )

        if score >= 0.75:
            labels[hostname] = 3
        elif score >= 0.45:
            labels[hostname] = 2
        elif score >= 0.20:
            labels[hostname] = 1
        else:
            labels[hostname] = 0

    return labels


# ============================================================================
#                                "MLP" (простий 2-шаровий)
# ============================================================================

def _sigmoid(x: float) -> float:
    # захист від overflow
    if x > 50:
        return 1.0
    if x < -50:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


def _tanh(x: float) -> float:
    # tanh стійкий, але залишимо як є
    return math.tanh(x)


def train_perceptron(features: Dict[str, Dict[str, Any]], labels: Dict[str, int]) -> Dict[str, Any]:
    """
    Реально зробимо мінімальний MLP:
      input -> hidden (tanh) -> output (sigmoid)
    Повертає модель dict, яку можна pickle'нути.
    """
    feature_names = [
        "episodes_count",
        "risk_sum",
        "risk_max",
        "cluster_0",
        "cluster_1",
        "cluster_2",
        "bert_negative",
        "bert_suspicious",
        "bert_attack",
    ]

    # hyperparams
    hidden_size = 6
    lr = 0.01
    epochs = 120

    # ініціалізація ваг
    # W1: hidden_size x input_size
    input_size = len(feature_names)
    W1 = [[0.01] * input_size for _ in range(hidden_size)]
    b1 = [0.0] * hidden_size

    # W2: 1 x hidden_size
    W2 = [0.01] * hidden_size
    b2 = 0.0

    # dataset
    Xs = []
    ys = []
    for host, feats in (features or {}).items():
        if host not in labels:
            continue
        X = [float(feats.get(n, 0.0)) for n in feature_names]
        y = float(labels[host]) / 3.0  # 0..1
        Xs.append(X)
        ys.append(y)

    if not Xs:
        logger.warning("train_perceptron: no training items")
        return {
            "type": "mlp",
            "feature_names": feature_names,
            "hidden_size": hidden_size,
            "W1": W1,
            "b1": b1,
            "W2": W2,
            "b2": b2,
        }

    # проста нормалізація (щоб не вбивати градієнти)
    # масштаб: risk_* вже 0..1, а решта може бути великим -> притиснемо log1p
    def _prep(X: List[float]) -> List[float]:
        out = []
        for name, v in zip(feature_names, X):
            if name in ("risk_sum", "risk_max"):
                out.append(max(0.0, min(v, 1.0)))
            else:
                out.append(math.log1p(max(0.0, v)))
        return out

    Xs = [_prep(x) for x in Xs]

    # train (MSE на виході sigmoid)
    for _ in range(epochs):
        for X, y in zip(Xs, ys):
            # forward hidden
            h = []
            for j in range(hidden_size):
                z1 = sum(W1[j][i] * X[i] for i in range(input_size)) + b1[j]
                h.append(_tanh(z1))

            # forward output
            z2 = sum(W2[j] * h[j] for j in range(hidden_size)) + b2
            pred = _sigmoid(z2)

            # loss grad (MSE): dL/dpred = 2*(pred-y)
            dL_dpred = 2.0 * (pred - y)

            # dpred/dz2 = pred*(1-pred)
            dpred_dz2 = pred * (1.0 - pred)
            dL_dz2 = dL_dpred * dpred_dz2

            # grads W2, b2
            for j in range(hidden_size):
                W2[j] -= lr * (dL_dz2 * h[j])
            b2 -= lr * dL_dz2

            # backprop to hidden
            for j in range(hidden_size):
                # dz2/dhj = W2[j]
                dL_dhj = dL_dz2 * W2[j]
                # dhj/dz1 = 1 - tanh^2(z1) -> але z1 не зберігали, тому через h
                dh_dz1 = 1.0 - (h[j] * h[j])
                dL_dz1 = dL_dhj * dh_dz1

                # grads W1[j][i], b1[j]
                for i in range(input_size):
                    W1[j][i] -= lr * (dL_dz1 * X[i])
                b1[j] -= lr * dL_dz1

    return {
        "type": "mlp",
        "feature_names": feature_names,
        "hidden_size": hidden_size,
        "W1": W1,
        "b1": b1,
        "W2": W2,
        "b2": b2,
    }


# ============================================================================
#                         ЗБЕРЕЖЕННЯ / ЗАВАНТАЖЕННЯ МОДЕЛІ
# ============================================================================

def save_model(model: Dict[str, Any]) -> None:
    try:
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        logger.info("Perceptron/MLP model saved to %s", MODEL_PATH)
    except Exception as exc:
        logger.error("Cannot save model: %s", exc)


def load_model() -> Optional[Dict[str, Any]]:
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except Exception as exc:
        logger.error("Cannot load model: %s", exc)
        return None


# ============================================================================
#                           ПРОГНОЗ ПРІОРИТЕТУ ДЛЯ ХОСТІВ
# ============================================================================

def predict_host_priority(model: Dict[str, Any], features: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Повертає:
      { hostname_norm : { priority_score: float, priority_level: str } }
    """
    if not model:
        return {}

    feature_names = model.get("feature_names") or []
    if not feature_names:
        return {}

    # така сама підготовка як на train
    def _prep(feats: Dict[str, Any]) -> List[float]:
        X = [float(feats.get(n, 0.0)) for n in feature_names]
        out = []
        for name, v in zip(feature_names, X):
            if name in ("risk_sum", "risk_max"):
                out.append(max(0.0, min(v, 1.0)))
            else:
                out.append(math.log1p(max(0.0, v)))
        return out

    result: Dict[str, Dict[str, Any]] = {}

    if model.get("type") == "mlp":
        W1 = model["W1"]
        b1 = model["b1"]
        W2 = model["W2"]
        b2 = model["b2"]
        hidden_size = int(model.get("hidden_size") or len(b1))

        for host, feats in (features or {}).items():
            X = _prep(feats)

            # hidden
            h = []
            for j in range(hidden_size):
                z1 = sum(W1[j][i] * X[i] for i in range(len(feature_names))) + b1[j]
                h.append(_tanh(z1))

            # out
            z2 = sum(W2[j] * h[j] for j in range(hidden_size)) + b2
            score = _sigmoid(z2)

            if score >= 0.8:
                level = "critical"
            elif score >= 0.5:
                level = "high"
            elif score >= 0.25:
                level = "medium"
            else:
                level = "low"

            result[host] = {
                "priority_score": round(float(score), 3),
                "priority_level": level,
            }

        return result

    # fallback (старий лінійний)
    weights = model.get("weights") or [0.0] * len(feature_names)
    bias = float(model.get("bias") or 0.0)

    for host, feats in (features or {}).items():
        X = _prep(feats)
        z = sum(float(w) * x for w, x in zip(weights, X)) + bias
        score = _sigmoid(z)

        if score >= 0.8:
            level = "critical"
        elif score >= 0.5:
            level = "high"
        elif score >= 0.25:
            level = "medium"
        else:
            level = "low"

        result[host] = {
            "priority_score": round(float(score), 3),
            "priority_level": level,
        }

    return result


