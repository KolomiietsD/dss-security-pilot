# core/views.py
from django.shortcuts import render
from django.http import JsonResponse

from .crowdstrike_api import get_recent_devices
from .assets_unified import get_unified_assets

def home(request):
    # тепер головна – про наші активи
    return render(request, 'core/home.html')

def about(request):
    return render(request, "core/about.html")

def crowdstrike_view(request):
    # сторінка, яка показує тільки crowdstrike-хости (як ти вже зробив)
    return render(request, "core/crowdstrike.html")

def crowdstrike_data(request):
    # JSON з сирими crowdstrike-девайсами (як ми робили раніше)
    try:
        devices = get_recent_devices(limit=100)
        return JsonResponse({"success": True, "devices": devices})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

def assets_data(request):
    """Уніфікований список активів для головної сторінки."""
    try:
        assets = get_unified_assets()
        return JsonResponse({"success": True, "assets": assets})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

