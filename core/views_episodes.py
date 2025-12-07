# core/views_episodes.py
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .unified_events import get_unified_events, group_events_by_time_window


@require_GET
def episodes_data(request):
    """
    Повертає згруповані епізоди подій (Wazuh + CrowdStrike).

    GET-параметри (опційно):
      - limit_per_source: скільки подій брати з кожного джерела (default: 200)
      - window_seconds: розмір часового вікна для епізоду (default: 90)
    """
    try:
        limit_per_source = int(request.GET.get("limit_per_source", "200"))
        window_seconds = int(request.GET.get("window_seconds", "90"))
    except ValueError:
        return JsonResponse(
            {"success": False, "error": "Некоректні параметри запиту"},
            status=400,
        )

    try:
        events = get_unified_events(limit_per_source=limit_per_source)
        episodes = group_events_by_time_window(
            events=events,
            window_seconds=window_seconds,
        )

        return JsonResponse(
            {
                "success": True,
                "episodes": episodes,
                "limit_per_source": limit_per_source,
                "window_seconds": window_seconds,
            },
            json_dumps_params={"ensure_ascii": False},
        )
    except Exception as exc:
        return JsonResponse(
            {"success": False, "error": str(exc)},
            status=500,
        )
