# core/views.py
from django.shortcuts import render
from django.http import JsonResponse

from .crowdstrike_api import get_recent_devices, get_recent_detects
from .assets_unified import get_unified_assets

import logging

logger = logging.getLogger(__name__)


def home(request):
    """
    Головна сторінка про наші активи.
    """
    return render(request, "core/home.html")


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
