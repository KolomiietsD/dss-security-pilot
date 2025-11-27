# core/crowdstrike_api.py
import os
from datetime import datetime, timezone

from falconpy import Hosts


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
                # last_seen типу "2025-11-27T09:12:34.123Z"
                last_seen_dt = datetime.fromisoformat(
                    last_seen_raw.replace("Z", "+00:00")
                )
                delta = now_utc - last_seen_dt
                # якщо хост бачили за останню годину – вважаємо, що він онлайн
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
                # якщо оригінальний status все ж хочеш зберегти:
                # "cs_status": r.get("status"),
            }
        )

    return devices
