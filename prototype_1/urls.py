"""URL configuration for prototype_1 project.

The `urlpatterns` list routes URLs to views.
"""

from django.contrib import admin
from django.urls import path

from core.views import (
    home,
    about,
    crowdstrike_view,
    crowdstrike_data,
    assets_data,
    crowdstrike_detects_data,
    asset_detections_data,
)

urlpatterns = [
    path("admin/", admin.site.urls),

    # Головна сторінка
    path("", home, name="home"),

    # Сторінка "Про систему"
    path("about/", about, name="about"),

    # Дашборд CrowdStrike (HTML)
    path("crowdstrike/", crowdstrike_view, name="crowdstrike"),

    # JSON з хостами CrowdStrike
    path("crowdstrike/data/", crowdstrike_data, name="crowdstrike_data"),

    # JSON з уніфікованими активами
    path("assets/data/", assets_data, name="assets_data"),

    # JSON з детекціями (alerts) CrowdStrike
    path(
        "crowdstrike/detects/",
        crowdstrike_detects_data,
        name="crowdstrike_detects",
    ),

    path("assets/detections/",asset_detections_data, name="asset_detections"),
]
