from falconpy import Hosts, Alerts
from datetime import datetime, timezone
import os


def _get_cs_credentials():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise RuntimeError(
            "Не знайдено FALCON_CLIENT_ID / FALCON_CLIENT_SECRET у змінних середовища"
        )

    return client_id, client_secret


def get_recent_devices(limit: int = 100):
    client_id, client_secret = _get_cs_credentials()

    falcon = Hosts(
        client_id=client_id,
        client_secret=client_secret,
    )

    response = falcon.query_devices_by_filter_combined(
        limit=limit,
        sort="last_seen.desc",  # найсвіжіші хости першими
    )

    try:
        status_code = response["status_code"]
        body = response["body"]
    except Exception:
        raise RuntimeError(f"Несподіваний формат відповіді CrowdStrike: {type(response)}")

    if status_code != 200:
        errors = body.get("errors") or []
        if isinstance(errors, list):
            msg = ", ".join(e.get("message", "") for e in errors)
        else:
            msg = str(errors)
        raise RuntimeError(f"API error {status_code}: {msg}")

    resources = body.get("resources") or []

    devices = []
    now_utc = datetime.now(timezone.utc)

    for r in resources:
        local_ip = r.get("local_ip")
        if isinstance(local_ip, list):
            local_ip = ", ".join(local_ip)

        last_seen_raw = r.get("last_seen")
        online_status = "unknown"

        if last_seen_raw:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                delta = now_utc - last_seen_dt
                online_status = "online" if delta.total_seconds() <= 3600 else "offline"
            except Exception:
                online_status = "unknown"

        devices.append(
            {
                "hostname": r.get("hostname"),
                "platform_name": r.get("platform_name"),
                "local_ip": local_ip,
                "last_seen": last_seen_raw,
                "online_status": online_status,
            }
        )

    return devices


def get_recent_detects(limit: int = 200):
    """
    Повертає список останніх детекцій (alerts) у форматі, який очікує фронтенд.
    Працює через Alerts API (Detects API вимкнули).
    """
    client_id, client_secret = _get_cs_credentials()

    falcon = Alerts(
        client_id=client_id,
        client_secret=client_secret,
    )

    # 1. Отримуємо composite_ids через query_alerts_v2
    query_resp = falcon.query_alerts_v2(
        limit=limit,
        sort="created_timestamp.desc",
    )

    try:
        status_code = query_resp["status_code"]
        body = query_resp["body"]
    except Exception:
        raise RuntimeError(f"Несподіваний формат відповіді Alerts API: {repr(query_resp)}")

    if status_code != 200:
        errors = body.get("errors") or []
        if isinstance(errors, list):
            msg = ", ".join(e.get("message", "") for e in errors)
        else:
            msg = str(errors)
        raise RuntimeError(f"Alerts API error {status_code}: {msg}")

    alert_ids = body.get("resources") or []
    if not alert_ids:
        return []

    alert_ids = alert_ids[:limit]

    # 2. Тягнемо деталі: тут ВАЖЛИВО: composite_ids, а не ids
    details_resp = falcon.get_alerts_v2(body={"composite_ids": alert_ids})

    try:
        det_status = details_resp["status_code"]
        det_body = details_resp["body"]
    except Exception:
        raise RuntimeError(
            f"Несподіваний формат відповіді get_alerts_v2: {repr(details_resp)}"
        )

    if det_status != 200:
        errors = det_body.get("errors") or []
        if isinstance(errors, list):
            msg = ", ".join(e.get("message", "") for e in errors)
        else:
            msg = str(errors)
        raise RuntimeError(f"Alert details API error {det_status}: {msg}")

    resources = det_body.get("resources") or []
    detects: list[dict] = []

    for alert in resources:
        device = alert.get("device") or {}
        hostname = device.get("hostname") or ""

        # ----- Нормалізація severity -----
        sev_raw = alert.get("severity") or alert.get("max_severity")
        sev_name = (
                alert.get("severity_name")
                or alert.get("severity_displayname")
                or alert.get("severity_label")
        )

        if isinstance(sev_name, str):
            sev_str = sev_name.lower()
        elif isinstance(sev_raw, (int, float)):
            if sev_raw >= 80:
                sev_str = "critical"
            elif sev_raw >= 60:
                sev_str = "high"
            elif sev_raw >= 40:
                sev_str = "medium"
            elif sev_raw >= 20:
                sev_str = "low"
            else:
                sev_str = "info"
        else:
            sev_str = ""

        # ⛔️ відкидаємо informational
        if sev_str in ("info", "informational", ""):
            continue

        detects.append(
            {
                "event_id": alert.get("composite_id"),
                "device_id": device.get("aid") or device.get("device_id"),
                "hostname": hostname,
                "timestamp": alert.get("created_timestamp"),
                "severity": sev_str,
                "type": (
                        alert.get("scenario")
                        or alert.get("name")
                        or alert.get("display_name")
                        or "Alert"
                ),
                "status": alert.get("status"),
                "description": (
                        alert.get("description")
                        or alert.get("title")
                        or alert.get("summary")
                        or ""
                ),
            }
        )

    return detects