# core/views.py
from django.shortcuts import render
from django.http import JsonResponse

from .episode_ml import analyze_episodes
from .episode_nlp import enrich_episodes_with_bert  # BERT над епізодами
from .bert_model import analyze_text
from .crowdstrike_api import get_recent_devices, get_recent_detects
from .wazuh_api import (
    get_agents,
    WazuhAPIError,
    get_recent_alerts,
    get_recent_siem_events,
)
from .assets_unified import get_unified_assets  # поки лишаємо, може знадобитися деінде
from .unified_events import get_unified_events, group_events_by_time_window

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _parse_iso_dt(value):
    """
    Допоміжна функція: перетворює ISO-дату з Wazuh у datetime або None.
    Очікує формат типу '2025-12-04T13:42:14Z'.
    """
    if not value:
        return None
    try:
        if isinstance(value, str) and value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


# ======================= ХЕЛПЕРИ ДЛЯ УНІФІКАЦІЇ АКТИВІВ =======================

def _norm_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    return hostname.strip().lower()


def _norm_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return ip.strip()


def _hostname_from_wazuh_agent(agent: Dict[str, Any]) -> Optional[str]:
    # Wazuh: частіше за все name / hostname
    return agent.get("hostname") or agent.get("name")


def _ip_from_wazuh_agent(agent: Dict[str, Any]) -> Optional[str]:
    ip = agent.get("ip") or agent.get("ip_address")
    if ip:
        return str(ip)
    ips = agent.get("ips") or agent.get("ip_list")
    if isinstance(ips, list) and ips:
        return str(ips[0])
    return None


def _hostname_from_cs_device(dev: Dict[str, Any]) -> Optional[str]:
    return dev.get("hostname") or dev.get("device_hostname")


def _ip_from_cs_device(dev: Dict[str, Any]) -> Optional[str]:
    ip = (
        dev.get("local_ip")
        or dev.get("local_ip_address")
        or dev.get("ip")
        or dev.get("ip_address")
    )
    if ip:
        return str(ip)
    ips = dev.get("local_ip_list") or dev.get("ip_list")
    if isinstance(ips, list) and ips:
        return str(ips[0])
    return None


def _hostname_from_wazuh_log(ev: Dict[str, Any]) -> Optional[str]:
    return (
        ev.get("hostname")
        or ev.get("agent_name")
        or (ev.get("agent") or {}).get("name")
        or (ev.get("agent") or {}).get("hostname")
    )


def _ip_from_wazuh_log(ev: Dict[str, Any]) -> Optional[str]:
    return (
        ev.get("srcip")
        or ev.get("src_ip")
        or ev.get("dstip")
        or ev.get("dst_ip")
    )


def bert_demo(request):
    result = None
    text = ""
    error = None

    if request.method == "POST":
        text = request.POST.get("text", "")
        try:
            result = analyze_text(text)
        except Exception as e:
            error = f"Помилка при роботі з BERT: {e}"

    context = {
        "text": text,
        "result": result,
        "error": error,
    }
    # шаблон лежить у templates/core/bert_demo.html
    return render(request, "core/bert_demo.html", context)


def _hostname_from_cs_log(d: Dict[str, Any]) -> Optional[str]:
    return (
        d.get("hostname")
        or d.get("device_hostname")
        or (d.get("device") or {}).get("hostname")
    )


def _ip_from_cs_log(d: Dict[str, Any]) -> Optional[str]:
    return (
        d.get("local_ip")
        or d.get("ip")
        or (d.get("device") or {}).get("local_ip")
    )


def _build_unified_assets_from_sources(
    wazuh_agents: List[Dict[str, Any]],
    cs_devices: List[Dict[str, Any]],
) -> Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]]:
    """
    Будує словник { (hostname_norm, ip_norm) -> asset_dict } на основі Wazuh-агентів
    та девайсів CrowdStrike. Якщо збігаються hostname+ip — це один актив.
    """
    assets: Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]] = {}

    # Спочатку Wazuh
    for agent in wazuh_agents or []:
        raw_hostname = _hostname_from_wazuh_agent(agent)
        raw_ip = _ip_from_wazuh_agent(agent)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)
        key = (hn, ip)

        if key not in assets:
            assets[key] = {
                "key": {
                    "hostname_norm": hn,
                    "ip_norm": ip,
                },
                "hostname": raw_hostname,
                "ip": raw_ip,
                "platform": None,
                "vendor": None,
                "online_status": agent.get("status") or None,
                "risk_score": agent.get("risk_score"),
                "sources": {
                    "wazuh": True,
                    "crowdstrike": False,
                },
                "wazuh_agents": [],
                "crowdstrike_devices": [],
                "logs": [],
            }

        asset = assets[key]
        asset["sources"]["wazuh"] = True
        asset["wazuh_agents"].append(agent)

        # заповнимо hostname/IP, якщо не були
        if not asset["hostname"] and raw_hostname:
            asset["hostname"] = raw_hostname
        if not asset["ip"] and raw_ip:
            asset["ip"] = raw_ip

        # платформа (OS name, якщо є)
        if not asset["platform"]:
            os_info = agent.get("os") or {}
            os_name = os_info.get("name")
            if os_name:
                asset["platform"] = os_name

    # Потім CrowdStrike
    for dev in cs_devices or []:
        raw_hostname = _hostname_from_cs_device(dev)
        raw_ip = _ip_from_cs_device(dev)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)
        key = (hn, ip)

        if key not in assets:
            assets[key] = {
                "key": {
                    "hostname_norm": hn,
                    "ip_norm": ip,
                },
                "hostname": raw_hostname,
                "ip": raw_ip,
                "platform": None,
                "vendor": None,
                "online_status": None,
                "risk_score": None,
                "sources": {
                    "wazuh": False,
                    "crowdstrike": True,
                },
                "wazuh_agents": [],
                "crowdstrike_devices": [],
                "logs": [],
            }

        asset = assets[key]
        asset["sources"]["crowdstrike"] = True
        asset["crowdstrike_devices"].append(dev)

        if not asset["hostname"] and raw_hostname:
            asset["hostname"] = raw_hostname
        if not asset["ip"] and raw_ip:
            asset["ip"] = raw_ip

        # платформа / вендор / статус / ризик з CS (якщо є такі поля)
        if not asset["platform"]:
            asset["platform"] = (
                dev.get("platform_name")
                or dev.get("platform")
                or dev.get("os_version")
                or None
            )

        if not asset["vendor"]:
            asset["vendor"] = dev.get("vendor") or dev.get("platform_name") or None

        if asset["online_status"] is None:
            asset["online_status"] = dev.get("online_status") or dev.get("status")

        if asset["risk_score"] is None and dev.get("risk_score") is not None:
            asset["risk_score"] = dev.get("risk_score")

    return assets


def _attach_wazuh_logs(
    assets: Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]],
    wazuh_logs: List[Dict[str, Any]],
    create_missing_assets: bool = False,
) -> None:
    """
    Прив'язує Wazuh-логи лише до ВЖЕ ІСНУЮЧИХ активів.
    create_missing_assets за замовчуванням False, щоб не плодити дублі.
    """
    for ev in wazuh_logs or []:
        raw_hostname = _hostname_from_wazuh_log(ev)
        raw_ip = _ip_from_wazuh_log(ev)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)
        key = (hn, ip)

        asset = assets.get(key)
        if asset is None:
            # не створюємо новий актив, просто пропускаємо
            continue

        asset["sources"]["wazuh"] = True

        log_entry = {
            "source": "wazuh",
            "hostname": raw_hostname,
            "ip": raw_ip,
            "raw": ev,
        }
        asset["logs"].append(log_entry)


def _attach_cs_logs(
    assets: Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]],
    cs_logs: List[Dict[str, Any]],
    create_missing_assets: bool = False,
) -> None:
    """
    Прив'язує CS-логи лише до ВЖЕ ІСНУЮЧИХ активів.

    ВАЖЛИВО:
    1) Спочатку пробуємо знайти актив по (hostname_norm, ip_norm).
    2) Якщо не знайдено, але є hostname_norm — пробуємо знайти актив
       тільки по hostname_norm (ігноруючи IP).
    """
    for d in cs_logs or []:
        raw_hostname = _hostname_from_cs_log(d)
        raw_ip = _ip_from_cs_log(d)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)
        key = (hn, ip)

        asset = assets.get(key)

        # fallback: шукаємо по одному лише hostname_norm
        if asset is None and hn is not None:
            for a in assets.values():
                try:
                    a_hn = (a.get("key") or {}).get("hostname_norm")
                except Exception:
                    a_hn = None
                if a_hn == hn:
                    asset = a
                    break

        if asset is None:
            # не створюємо новий актив, просто пропускаємо
            continue

        asset["sources"]["crowdstrike"] = True

        log_entry = {
            "source": "crowdstrike",
            "hostname": raw_hostname,
            "ip": raw_ip,
            "raw": d,
        }
        asset["logs"].append(log_entry)


def _build_unified_assets_with_logs() -> List[Dict[str, Any]]:
    """
    Високорівнева функція:
    - тягне Wazuh-агентів + логи
    - тягне CrowdStrike-девайси + детекти
    - зводить усе до списку уніфікованих активів з логами
    """
    wazuh_agents: List[Dict[str, Any]] = []
    wazuh_alerts: List[Dict[str, Any]] = []
    wazuh_events: List[Dict[str, Any]] = []
    cs_devices: List[Dict[str, Any]] = []
    cs_detects: List[Dict[str, Any]] = []

    # Wazuh частина – не валимо все, якщо вона падає
    try:
        wazuh_agents = get_agents(limit=500) or []
    except (WazuhAPIError, RuntimeError, Exception) as exc:
        logger.warning("Не вдалося отримати агентів Wazuh: %s", exc)

    try:
        wazuh_alerts = get_recent_alerts(limit=200) or []
    except (WazuhAPIError, RuntimeError, Exception) as exc:
        logger.warning("Не вдалося отримати alerts Wazuh: %s", exc)

    try:
        wazuh_events = get_recent_siem_events(limit=200) or []   # noqa: F811
    except (WazuhAPIError, RuntimeError, Exception) as exc:
        logger.warning("Не вдалося отримати SIEM events Wazuh: %s", exc)

    # CrowdStrike частина
    try:
        cs_devices = get_recent_devices(limit=500) or []
    except Exception as exc:
        logger.warning("Не вдалося отримати хости CrowdStrike: %s", exc)

    try:
        cs_detects = get_recent_detects(limit=200) or []
    except Exception as exc:
        logger.warning("Не вдалося отримати детекти CrowdStrike: %s", exc)

    assets = _build_unified_assets_from_sources(wazuh_agents, cs_devices)

    # ⛔️ ВАЖЛИВО: не створюємо нові активи з логів, тільки прив'язуємо до існуючих
    all_wazuh_logs = (wazuh_alerts or []) + (wazuh_events or [])
    _attach_wazuh_logs(assets, all_wazuh_logs, create_missing_assets=False)

    _attach_cs_logs(assets, cs_detects, create_missing_assets=False)

    return list(assets.values())


# ======================= VIEW'ШКИ =======================

def home(request):
    """
    Головна сторінка про наші активи.
    """
    return render(request, "core/home.html")


def perceptron_view(request):
    return render(request, "core/perceptron.html")


def about(request):
    """
    Сторінка 'Про систему'.
    """
    return render(request, "core/about.html")


def crowdstrike_view(request):
    """
    Сторінка з дашбордом CrowdStrike (хости + детекції).
    """
    return render(request, "core/crowdstrike.html")


def wazuh_view(request):
    """
    Дашборд Wazuh: інфографіка + таблиця агентів + останні детекти / SIEM-івенти.
    """
    agents: List[Dict[str, Any]] = []
    error_message: Optional[str] = None
    wazuh_connected = False

    wazuh_alerts: List[Dict[str, Any]] = []
    wazuh_events: List[Dict[str, Any]] = []

    # Лічильники для графіків
    status_counts = {
        "active": 0,
        "disconnected": 0,
        "never_connected": 0,
        "unknown": 0,
    }
    os_counts: Dict[str, int] = {}
    last_seen_buckets = {
        "lt_24h": 0,
        "d1_7": 0,
        "gt_7": 0,
        "unknown": 0,
    }

    try:
        # 1. Агенти
        agents = get_agents(limit=500)
        wazuh_connected = True

        now = datetime.now(timezone.utc)

        for a in agents:
            # --- Статус ---
            status = (a.get("status") or "").lower()
            if status not in status_counts:
                status = "unknown"
            status_counts[status] += 1

            # --- ОС ---
            os_info = a.get("os") or {}
            os_name = os_info.get("name") or "Unknown"
            os_counts[os_name] = os_counts.get(os_name, 0) + 1

            # --- Останній keepalive ---
            last_keepalive = _parse_iso_dt(a.get("last_keepalive"))
            if not last_keepalive:
                last_seen_buckets["unknown"] += 1
            else:
                delta = now - last_keepalive
                days = delta.total_seconds() / 86400.0
                if days <= 1:
                    last_seen_buckets["lt_24h"] += 1
                elif days <= 7:
                    last_seen_buckets["d1_7"] += 1
                else:
                    last_seen_buckets["gt_7"] += 1

        # 2. Останні детекти / івенти з Indexer (якщо він налаштований)
        try:
            wazuh_alerts = get_recent_alerts(limit=50) or []
            wazuh_events = get_recent_siem_events(limit=50) or []
        except (WazuhAPIError, RuntimeError) as exc:
            # не валимо сторінку, просто лог
            logger.warning("Не вдалося отримати alerts/events з Wazuh Indexer: %s", exc)

    except (WazuhAPIError, RuntimeError) as exc:
        error_message = str(exc)

    # Дані для графіків
    charts = {
        "status": {
            "labels": ["Active", "Disconnected", "Never connected", "Unknown"],
            "data": [
                status_counts["active"],
                status_counts["disconnected"],
                status_counts["never_connected"],
                status_counts["unknown"],
            ],
        },
        "platforms": {
            "labels": list(os_counts.keys()),
            "data": list(os_counts.values()),
        },
        "last_seen": {
            "labels": ["≤ 24 год", "1–7 днів", "> 7 днів", "Невідомо"],
            "data": [
                last_seen_buckets["lt_24h"],
                last_seen_buckets["d1_7"],
                last_seen_buckets["gt_7"],
                last_seen_buckets["unknown"],
            ],
        },
    }

    context = {
        "page_title": "Wazuh інтеграція",
        "wazuh_connected": wazuh_connected,
        "wazuh_agents": agents,
        "wazuh_error": error_message,
        "wazuh_charts_json": json.dumps(charts),
        "wazuh_alerts": wazuh_alerts,
        "wazuh_events": wazuh_events,
    }
    return render(request, "core/wazuh.html", context)


def crowdstrike_data(request):
    """
    JSON з хостами CrowdStrike для /crowdstrike/data/
    """
    try:
        devices = get_recent_devices(limit=100) or []
        return JsonResponse(
            {
                "success": True,
                "devices": devices,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as e:
        logger.exception("Помилка при отриманні хостів CrowdStrike")
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


def assets_data(request):
    """
    Уніфікований список активів (Wazuh + CrowdStrike) для головної сторінки.
    """
    try:
        unified_assets = _build_unified_assets_with_logs()
        return JsonResponse(
            {
                "success": True,
                "assets": unified_assets,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as e:
        logger.exception("Помилка при отриманні уніфікованих активів")
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


def crowdstrike_detects_data(request):
    """
    JSON з детекціями (alerts) для /crowdstrike/detects/
    """
    try:
        detects = get_recent_detects(limit=200) or []
        return JsonResponse(
            {
                "success": True,
                "detects": detects,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as e:
        logger.exception("Помилка при отриманні детекцій CrowdStrike")
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


def asset_detections_data(request):
    """
    Детекти (alerts) для конкретного активу за hostname.
    Викликається фронтендом як:
      /assets/detections/?hostname=HOSTNAME
    """
    hostname = request.GET.get("hostname")
    if not hostname:
        return JsonResponse(
            {
                "success": False,
                "error": "Потрібен параметр hostname",
            },
            status=400,
            json_dumps_params={"ensure_ascii": False},
        )

    try:
        all_detects = get_recent_detects(limit=200) or []

        filtered: List[Dict[str, Any]] = []
        for d in all_detects:
            det_hostname = (
                d.get("hostname")
                or d.get("device_hostname")
                or (d.get("device") or {}).get("hostname")
            )
            if det_hostname == hostname:
                filtered.append(d)

        return JsonResponse(
            {
                "success": True,
                "detections": filtered,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as e:
        logger.exception(
            "Помилка при отриманні детекцій для активу з hostname=%s", hostname
        )
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


def wazuh_hosts_data(request):
    """
    JSON з хостами/агентами Wazuh для /wazuh/hosts/
    """
    try:
        agents = get_agents(limit=500) or []
        return JsonResponse(
            {
                "success": True,
                "hosts": agents,
                "agents": agents,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except (WazuhAPIError, RuntimeError) as e:
        logger.exception("Помилка при отриманні хостів/агентів Wazuh")
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


def wazuh_events_data(request):
    """
    JSON з подіями Wazuh для /wazuh/events/ (alerts + siem events разом)
    """
    try:
        alerts = get_recent_alerts(limit=200) or []
        siem_events = get_recent_siem_events(limit=200) or []
        events = alerts + siem_events

        return JsonResponse(
            {
                "success": True,
                "events": events,
                "alerts": alerts,
                "siem_events": siem_events,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except (WazuhAPIError, RuntimeError) as e:
        logger.exception("Помилка при отриманні подій Wazuh")
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


# ======================= ЕПІЗОДИ + ML/NLP =======================

def episodes_data(request):
    """
    Повертає список епізодів (кластерів подій) з:
      - cluster_id (k-means / ML)
      - risk_score, risk_level (евристики + ML)
      - bert_label, bert_score, bert_sentiment (оцінка BERT текстів подій)
    Ендпоінт: /events/episodes/
    """
    # Параметри з запиту (опціонально, щоб було гнучко)
    try:
        window_seconds = int(request.GET.get("window_seconds", 90))
    except ValueError:
        window_seconds = 90

    try:
        limit_per_source = int(request.GET.get("limit_per_source", 200))
    except ValueError:
        limit_per_source = 200

    try:
        # 1) тягнемо уніфіковані події
        events = get_unified_events(limit_per_source=limit_per_source)

        # 2) групуємо у часові епізоди
        episodes = group_events_by_time_window(
            events,
            window_seconds=window_seconds,
        )

        # 3) рахуємо ML-ризик / кластери
        analyzed = analyze_episodes(episodes, n_clusters=3)

        # 4) додаємо BERT-оцінку (по текстах подій епізоду)
        enriched = enrich_episodes_with_bert(analyzed)

        return JsonResponse(
            {"success": True, "episodes": enriched},
            json_dumps_params={"ensure_ascii": False},
        )

    except Exception as exc:
        logger.exception("Помилка при ML/NLP-аналізі епізодів")
        return JsonResponse(
            {"success": False, "error": str(exc)},
            status=500,
            json_dumps_params={"ensure_ascii": False},
        )


def episodes_analyze_data(request):
    """
    Сумісний ендпоінт, зараз просто делегує в episodes_data.
    Якщо десь у коді/шаблонах ще є посилання на /episodes/analyze/,
    воно отримає ті самі дані.
    """
    return episodes_data(request)
