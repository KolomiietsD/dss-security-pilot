# core/views_episodes.py
from django.http import JsonResponse
from django.shortcuts import render

from .unified_events import (
    get_unified_events,
    group_events_by_time_window,
)


def episodes_view(request):
    """
    HTML-сторінка з епізодами (таблиця + деталі).
    Весь контент всередині підтягується AJAX-запитом на /events/episodes/.
    """
    return render(request, "core/episodes.html")


def episodes_data(request):
    """
    JSON з епізодами для /events/episodes/
    """
    try:
        events = get_unified_events(limit_per_source=200)
        episodes = group_events_by_time_window(events, window_seconds=90)

        # Тут уже пораховані risk_score, has_wazuh, has_crowdstrike і т.д.
        return JsonResponse(
            {
                "success": True,
                "episodes": episodes,
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
