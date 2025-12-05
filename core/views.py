# core/views.py
from django.shortcuts import render
from django.http import JsonResponse

from .crowdstrike_api import get_recent_devices, get_recent_detects
from .wazuh_api import get_agents, WazuhAPIError, get_recent_alerts, get_recent_siem_events

from .assets_unified import get_unified_assets

from datetime import datetime, timezone
import json
import logging

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
    agents: list[dict] = []
    error_message: str | None = None
    wazuh_connected = False

    wazuh_alerts: list[dict] = []
    wazuh_events: list[dict] = []

    # Лічильники для графіків
    status_counts = {
        "active": 0,
        "disconnected": 0,
        "never_connected": 0,
        "unknown": 0,
    }
    os_counts: dict[str, int] = {}
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

    # Дані для графіків (аналогічно CrowdStrike-дашборду)
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
        # last_seen зараз у шаблоні не використовується, але залишимо про запас
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

    Формат відповіді:
    {
        "success": true/false,
        "devices": [...],
        "error": "..."  # тільки при success=false
    }
    """
    try:
        devices = get_recent_devices(limit=100)
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
            status=200,  # щоб фронт зміг прочитати JSON і показати помилку
            json_dumps_params={"ensure_ascii": False},
        )


def assets_data(request):
    """
    Уніфікований список активів для головної сторінки.

    Формат відповіді:
    {
        "success": true/false,
        "assets": [...],
        "error": "..."  # тільки при success=false
    }
    """
    try:
        assets = get_unified_assets()
        return JsonResponse(
            {
                "success": True,
                "assets": assets,
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

    Формат відповіді:
    {
        "success": true/false,
        "detects": [...],
        "error": "..."  # тільки при success=false
    }
    """
    try:
        detects = get_recent_detects(limit=200)
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
            status=200,  # щоб НЕ було HTTP 500, а помилка пішла у фронтенд
            json_dumps_params={"ensure_ascii": False},
        )


def asset_detections_data(request):
    """
    Детекти (alerts) для конкретного активу за hostname.

    Викликається фронтендом як:
      /assets/detections/?hostname=HOSTNAME

    Формат відповіді:
    {
        "success": true/false,
        "detections": [...],
        "error": "..."  # тільки при success=false
    }

    Тут ми поки що просто беремо останні детекти з get_recent_detects()
    і фільтруємо їх по hostname у Python.
    Якщо потім захочеш – винесемо це в окрему функцію в crowdstrike_api
    з прямим фільтром у запиті до API.
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
        # Беремо останні детекти
        all_detects = get_recent_detects(limit=200)

        filtered = []
        for d in all_detects or []:
            # намагаємось дістати hostname з різних можливих полів
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
            status=200,  # щоб фронт прочитав JSON і показав помилку в модалці
            json_dumps_params={"ensure_ascii": False},
        )


def wazuh_hosts_data(request):
    """
    JSON з хостами/агентами Wazuh для /wazuh/hosts/

    Формат відповіді:
    {
        "success": true/false,
        "hosts": [...],
        "agents": [...],  # дублюємо для зручності
        "error": "..."    # тільки при success=false
    }
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
    JSON з подіями Wazuh для /wazuh/events/

    Зараз просто повертаємо суму alerts + siem events.

    Формат відповіді:
    {
        "success": true/false,
        "events": [...],        # об'єднаний список
        "alerts": [...],        # сирі alerts
        "siem_events": [...],   # сирі siem-івенти
        "error": "..."          # тільки при success=false
    }
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
