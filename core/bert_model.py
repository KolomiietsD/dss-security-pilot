# core/bert_model.py
"""
Легкий "BERT-замінник" без HuggingFace, щоб не падати через важкі моделі.

Ми зберігаємо той самий інтерфейс:
    analyze_text(text) -> dict або None

Повертаємо структуру:
{
    "label": "benign" | "suspicious" | "attack" | "unknown",
    "label_en": "...",
    "score": float  # 0..1
}
"""

from __future__ import annotations

from typing import Optional, Dict
import re


# Прості списки ключових слів для евристики
ATTACK_KEYWORDS = [
    r"mimikatz",
    r"ransomware",
    r"crypto[- ]?locker",
    r"cobalt strike",
    r"meterpreter",
    r"powershell",
    r"invoke-mimikatz",
    r"credential theft",
    r"lsass",
    r"dump lsass",
    r"brute force",
    r"bruteforce",
    r"sql injection",
    r"sql-injection",
    r"reverse shell",
    r"reverse-shell",
    r"command and control",
    r"c2 channel",
]

SUSPICIOUS_KEYWORDS = [
    r"failed logon",
    r"failed login",
    r"multiple logon failures",
    r"multiple login failures",
    r"privilege escalation",
    r"privilege-escalation",
    r"lateral movement",
    r"unusual process",
    r"suspicious process",
    r"suspicious command",
    r"remote desktop",
    r"rdp connection",
    r"rdp brute force",
    r"admin share",
    r"psexec",
    r"wmic",
    r"wmi",
]

BENIGN_KEYWORDS = [
    r"windows logon",
    r"windows login",
    r"user logon",
    r"user login",
    r"service started",
    r"service stopped",
    r"scheduled task created",
    r"group policy",
    r"software update",
    r"antivirus update",
    r"system reboot",
]


def _match_any(patterns, text_lower: str) -> bool:
    for p in patterns:
        if re.search(p, text_lower):
            return True
    return False


def analyze_text(text: str) -> Optional[Dict[str, object]]:
    """
    Легка евристична "оцінка" тексту події / епізоду.

    Повертає:
        {
            "label": "benign" | "suspicious" | "attack" | "unknown",
            "label_en": <людський опис англійською>,
            "score": float в [0,1] (наскільки впевнені)
        }
    або None, якщо текст порожній.
    """
    if not text or not text.strip():
        return None

    t = text.strip().lower()

    # 1) Явні ознаки атаки
    if _match_any(ATTACK_KEYWORDS, t):
        return {
            "label": "attack",
            "label_en": "Clear signs of attack / malware activity",
            "score": 0.9,
        }

    # 2) Підозріла активність
    if _match_any(SUSPICIOUS_KEYWORDS, t):
        return {
            "label": "suspicious",
            "label_en": "Suspicious security-related activity",
            "score": 0.7,
        }

    # 3) Схоже на нешкідливу системну активність
    if _match_any(BENIGN_KEYWORDS, t):
        return {
            "label": "benign",
            "label_en": "Likely benign system activity",
            "score": 0.6,
        }

    # 4) За замовчуванням
    return {
        "label": "unknown",
        "label_en": "No clear security semantics detected",
        "score": 0.5,
    }