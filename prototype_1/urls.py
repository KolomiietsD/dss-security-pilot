# urls.py
from django.contrib import admin
from django.urls import path

from core.views import (
    home,
    perceptron_view,
    about,
    crowdstrike_view,
    crowdstrike_data,
    assets_data,
    crowdstrike_detects_data,
    asset_detections_data,
    wazuh_view,
    wazuh_hosts_data,
    wazuh_events_data,
    bert_demo,
    episodes_data,          # 👈 беремо episodes_data з core.views
    episodes_analyze_data,  # 👈 новий ендпоінт з ML + BERT
)
from core.views_episodes import episodes_view  # тільки HTML-сторінка


urlpatterns = [
    path("admin/", admin.site.urls),

    # Головна сторінка
    path("", home, name="home"),

    # Персептрон
    path("perceptron/", perceptron_view, name="perceptron"),

    # Сторінка "Про систему"
    path("about/", about, name="about"),

    # Wazuh
    path("wazuh/", wazuh_view, name="wazuh"),
    path("wazuh/hosts/", wazuh_hosts_data, name="wazuh_hosts_data"),
    path("wazuh/events/", wazuh_events_data, name="wazuh_events_data"),

    # CrowdStrike дашборд
    path("crowdstrike/", crowdstrike_view, name="crowdstrike"),
    path("crowdstrike/data/", crowdstrike_data, name="crowdstrike_data"),

    # Глобальний список детектів CrowdStrike
    path(
        "crowdstrike/detects/",
        crowdstrike_detects_data,
        name="crowdstrike_detects_data",
    ),

    # Уніфіковані активи
    path("assets/data/", assets_data, name="assets_data"),
    # Детекти по конкретному активу (зазвичай /assets/detections/?hostname=...)
    path("assets/detections/", asset_detections_data, name="asset_detections"),

    # BERT демо
    path("bert/", bert_demo, name="bert_demo"),

    # Епізоди (HTML + JSON + ML)
    path("episodes/", episodes_view, name="episodes"),                # сторінка
    path("events/episodes/", episodes_data, name="episodes_data"),    # "сирі" епізоди
    path(
        "events/episodes/analyze/",
        episodes_analyze_data,
        name="episodes_analyze_data",
    ),  # ML + BERT аналіз
]
