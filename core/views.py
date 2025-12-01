from django.shortcuts import render
from django.http import JsonResponse
from .crowdstrike_api import get_recent_devices

def home(request):
    return render(request, 'core/home.html')

def about(request):
    return render(request, "core/about.html")

# Сторінка CrowdStrike: віддаємо HTML максимально швидко
def crowdstrike_view(request):
    return render(request, "core/crowdstrike.html")

# Окремий endpoint для даних (його викликає JS)
def crowdstrike_data(request):
    try:
        devices = get_recent_devices(limit=100)

        # якщо devices вже список звичайних dict'ів — цього достатньо
        return JsonResponse({
            "success": True,
            "devices": devices,
        })
    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e),
        }, status=500)
