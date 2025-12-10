# core/views_episodes.py
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from .unified_events import (
    get_unified_events,
    group_events_by_time_window,
)
from .episode_ml import analyze_episodes


def _get_int_param(request, name, default, min_value=None, max_value=None):
    """
    Акуратний парсер цілочисельних GET-параметрів.
    Якщо значення некоректне – повертаємо default.
    """
    value = request.GET.get(name)
    if value is None:
        return default

    try:
        value = int(value)
    except (TypeError, ValueError):
        return default

    if min_value is not None and value < min_value:
        value = min_value
    if max_value is not None and value > max_value:
        value = max_value

    return value


@require_GET
def episodes_view(request):
    """
    HTML-сторінка з епізодами (таблиця + деталі).

    Може приймати ?host=<hostname> для попереднього фільтру по хосту.
    Весь контент всередині підтягується AJAX-запитом на episodes_data.
    """
    host_filter = (request.GET.get("host") or "").strip()

    context = {
        "default_window_seconds": 60,
        "default_limit_per_source": 50,
        "initial_host_filter": host_filter,
    }
    return render(request, "core/episodes.html", context)


@require_GET
def episodes_data(request):
    """
    JSON з епізодами для /events/episodes/

    Параметри (GET):
        - window: тривалість вікна для групування подій в епізоди, сек.
                  за замовчуванням 60, обмежуємо 30–600.
        - limit: ліміт подій на кожне джерело (Wazuh / CrowdStrike),
                 за замовчуванням 50, обмежуємо 20–500.
        - host: (необов'язково) фільтр по hostname
    """
    window_seconds = _get_int_param(
        request,
        name="window",
        default=60,
        min_value=30,
        max_value=600,
    )
    limit_per_source = _get_int_param(
        request,
        name="limit",
        default=50,
        min_value=20,
        max_value=500,
    )

    host_filter = (request.GET.get("host") or "").strip()
    host_filter_lower = host_filter.lower() if host_filter else ""

    try:
        # 1) Тягнемо нормалізовані події з обох джерел
        events = get_unified_events(limit_per_source=limit_per_source)

        # 2) Групуємо їх у епізоди
        episodes = group_events_by_time_window(
            events,
            window_seconds=window_seconds,
        )

        # 3) Проганяємо через ML-аналітику (k-means + risk_score / risk_level)
        episodes = analyze_episodes(episodes, n_clusters=3)

        # 4) Фільтр по hostname (якщо заданий)
        if host_filter_lower:
            filtered = []
            for ep in episodes:
                hn = (ep.get("hostname") or "").lower()
                if hn == host_filter_lower:
                    filtered.append(ep)
            episodes = filtered

        return JsonResponse(
            {
                "success": True,
                "episodes": episodes,
                "meta": {
                    "window_seconds": window_seconds,
                    "limit_per_source": limit_per_source,
                    "episodes_count": len(episodes) if isinstance(episodes, list) else None,
                    "host": host_filter or None,
                },
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as e:
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
            },
            status=200,
            json_dumps_params={"ensure_ascii": False},
        )


