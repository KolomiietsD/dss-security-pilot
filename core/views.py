from django.shortcuts import render
from .crowdstrike_api import get_recent_devices

# Create your views here.
def home(request):
    return render(request, 'core/home.html')
def about(request):
    return render(request, "core/about.html")

def crowdstrike_view(request):
    error = None
    devices = []

    try:
        devices = get_recent_devices(limit=100)
    except Exception as e:
        error = str(e)

    context = {
        "devices": devices,
        "error": error,
    }
    return render(request, "core/crowdstrike.html", context)