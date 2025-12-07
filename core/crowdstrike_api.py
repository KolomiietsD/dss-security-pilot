# core/crowdstrike_api.py
from falconpy import Hosts, Alerts
from datetime import datetime, timezone
import os

from .log_normalizer import normalize_cs_alert  # 👈 додаємо нормалізатор CS-логів

# Два допустимі теги для ІСППР
CS_ALLOWED_TAGS = ["isppr", "FalconGroupingTags/isppr"]


def _get_cs_credentials():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise RuntimeError(
            "Не знайдено FALCON_CLIENT_ID / FALCON_CLIENT_SECRET у змінних середовища"
        )

    return client_id, client_secret


def _build_tag_filter(field: str) -> str:
    """
    Побудова FQL-фільтра по кількох тегах:
      tags:['isppr','FalconGroupingTags/isppr']
    """
    if not CS_ALLOWED_TAGS:
        return ""

    if len(CS_ALLOWED_TAGS) == 1:
        return f"{field}:'{CS_ALLOWED_TAGS[0]}'"

    values = ",".join(f"'{t}'" for t in CS_ALLOWED_TAGS)
    return f"{field}:[{values}]"


def _build_id_filter(field: str, ids):
    """
    Побудова FQL-фільтра по списку device_id:
      device.device_id:'AID'
      device.device_id:['AID1','AID2',...]
    """
    ids = [i for i in ids if i]
    if not ids:
        return ""

    if len(ids) == 1:
        return f"{field}:'{ids[0]}'"

    values = ",".join(f"'{i}'" for i in ids)
    return f"{field}:[{values}]"


def _get_allowed_device_ids(limit: int = 5000):
    """
    Повертає список device_id тільки для хостів з тегами
    isppr / FalconGroupingTags/isppr.
    """
    client_id, client_secret = _get_cs_credentials()

    falcon_hosts = Hosts(
        client_id=client_id,
        client_secret=client_secret,
    )

    tag_filter = _build_tag_filter("tags")

    resp = falcon_hosts.query_devices_by_filter_combined(
        limit=limit,
        sort="last_seen.desc",
        filter=tag_filter,
    )

    try:
        status_code = resp["status_code"]
        body = resp["body"]
    except Exception:
        raise RuntimeError(
            f"Несподіваний формат відповіді CrowdStrike (Hosts): {type(resp)}"
        )

    if status_code != 200:
        errors = body.get("errors") or []
        if isinstance(errors, list):
            msg = ", ".join(e.get("message", "") for e in errors)
        else:
            msg = str(errors)
        raise RuntimeError(f"Hosts API error {status_code}: {msg}")

    resources = body.get("resources") or []

    device_ids = []
    for r in resources:
        aid = r.get("device_id") or r.get("aid")
        if aid:
            device_ids.append(aid)

    return device_ids


# ---------------------------- ХОСТИ ---------------------------- #

def get_recent_devices(limit: int = 100):
    """
    Повертає хости тільки з тегами isppr / FalconGroupingTags/isppr.
    """
    client_id, client_secret = _get_cs_credentials()

    falcon = Hosts(
        client_id=client_id,
        client_secret=client_secret,
    )

    tag_filter = _build_tag_filter("tags")

    response = falcon.query_devices_by_filter_combined(
        limit=limit,
        sort="last_seen.desc",  # найсвіжіші хости першими
        filter=tag_filter,
    )

    try:
        status_code = response["status_code"]
        body = response["body"]
    except Exception:
        raise RuntimeError(
            f"Несподіваний формат відповіді CrowdStrike: {type(response)}"
        )

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
                last_seen_dt = datetime.fromisoformat(
                    last_seen_raw.replace("Z", "+00:00")
                )
                delta = now_utc - last_seen_dt
                # якщо бачили за останню годину – вважаємо, що online
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


# ---------------------------- ДЕТЕКТИ (старий формат для фронту) ---------------------------- #

def get_recent_detects(limit: int = 200):
    """
    Повертає список останніх детекцій (alerts) тільки для хостів,
    які мають теги isppr / FalconGroupingTags/isppr.

    Ця функція повертає "напів-нормалізований" формат під поточний фронтенд.
    Для уніфікованої обробки логів краще використовувати get_normalized_cs_alerts().
    """
    client_id, client_secret = _get_cs_credentials()

    # 0. Отримуємо device_id тільки дозволених хостів
    allowed_ids = _get_allowed_device_ids()
    if not allowed_ids:
        return []

    device_filter = _build_id_filter("device.device_id", allowed_ids)

    falcon = Alerts(
        client_id=client_id,
        client_secret=client_secret,
    )

    # 1. Отримуємо composite_ids через query_alerts_v2
    query_resp = falcon.query_alerts_v2(
        limit=limit,
        sort="created_timestamp.desc",
        filter=device_filter,
    )

    try:
        status_code = query_resp["status_code"]
        body = query_resp["body"]
    except Exception:
        raise RuntimeError(
            f"Несподіваний формат відповіді Alerts API: {repr(query_resp)}"
        )

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

    # 2. Деталі по composite_ids
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
    detects = []

    now_utc = datetime.now(timezone.utc)

    for alert in resources:
        device = alert.get("device") or {}
        hostname = device.get("hostname") or ""

        # ---------- Severity нормалізація ----------
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

        # ---------- Продукт / платформа ----------
        product = (
            alert.get("product_name")
            or alert.get("product")
            or alert.get("source")
        )

        platform = (
            device.get("platform_name")
            or device.get("os_version")
            or device.get("platform")
        )

        scenario_text = (
            alert.get("scenario")
            or alert.get("name")
            or alert.get("display_name")
            or "Alert"
        )
        scenario_lower = scenario_text.lower()

        is_lateral_movement = "lateral" in scenario_lower
        is_ransomware_like = "ransom" in scenario_lower

        # ---------- Вік детекції в годинах ----------
        created_ts = alert.get("created_timestamp")
        age_hours = None
        if created_ts:
            try:
                created_dt = datetime.fromisoformat(
                    created_ts.replace("Z", "+00:00")
                )
                delta = now_utc - created_dt
                age_hours = round(delta.total_seconds() / 3600, 2)
            except Exception:
                age_hours = None

        # ---------- MITRE, процес, користувач, мережа ----------
        behaviors = alert.get("behaviors") or []
        primary_behavior = behaviors[0] if behaviors else {}

        tactic = (
            primary_behavior.get("tactic_display_name")
            or primary_behavior.get("tactic")
        )
        technique_id = primary_behavior.get("technique_id")
        technique = (
            primary_behavior.get("technique_display_name")
            or primary_behavior.get("technique")
        )

        user_name = (
            alert.get("user_name")
            or alert.get("user")
            or primary_behavior.get("user_name")
        )

        process_name = (
            primary_behavior.get("filename")
            or primary_behavior.get("image_file_name")
            or primary_behavior.get("process")
        )

        remote_ip = None
        remote_port = None
        net_details = alert.get("network_details") or alert.get("network") or []
        if isinstance(net_details, dict):
            net_details = [net_details]

        if net_details:
            chosen = None
            for nd in net_details:
                if nd.get("direction") == "egress":
                    chosen = nd
                    break
            if not chosen:
                chosen = net_details[0]

            remote_ip = (
                chosen.get("remote_ip")
                or chosen.get("remote_address")
                or chosen.get("remote")
            )
            remote_port = (
                chosen.get("remote_port")
                or chosen.get("port")
            )

        detects.append(
            {
                # ID-шники
                "event_id": alert.get("composite_id"),
                "detection_id": alert.get("composite_id"),
                "device_id": device.get("aid") or device.get("device_id"),

                # базове
                "hostname": hostname,
                "timestamp": created_ts,

                "severity": sev_str,
                "severity_score": sev_raw,

                "type": scenario_text,
                "product": product,
                "platform": platform,

                # MITRE / контекст атаки
                "tactic": tactic,
                "technique_id": technique_id,
                "technique": technique,

                # користувач / процес
                "user_name": user_name,
                "process_name": process_name,

                # мережевий контекст
                "remote_ip": remote_ip,
                "remote_port": remote_port,

                # прапорці для UI / моделі
                "is_lateral_movement": is_lateral_movement,
                "is_ransomware_like": is_ransomware_like,
                "age_hours": age_hours,

                # статус та опис
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


# ---------------------------- НОРМАЛІЗОВАНІ ДЕТЕКТИ ДЛЯ ІСППР ---------------------------- #

def get_normalized_cs_alerts(limit: int = 200) -> list[dict]:
    """
    Повертає уніфіковані (нормалізовані) алерти CrowdStrike тільки для хостів
    з тегами isppr / FalconGroupingTags/isppr.

    На відміну від get_recent_detects, повертає raw-алерти, пропущені через
    core.log_normalizer.normalize_cs_alert, щоб формат був спільний з Wazuh.
    """
    client_id, client_secret = _get_cs_credentials()

    # 0. device_id тільки дозволених хостів
    allowed_ids = _get_allowed_device_ids()
    if not allowed_ids:
        return []

    device_filter = _build_id_filter("device.device_id", allowed_ids)

    falcon = Alerts(
        client_id=client_id,
        client_secret=client_secret,
    )

    # 1. Отримуємо composite_ids
    query_resp = falcon.query_alerts_v2(
        limit=limit,
        sort="created_timestamp.desc",
        filter=device_filter,
    )

    try:
        status_code = query_resp["status_code"]
        body = query_resp["body"]
    except Exception:
        raise RuntimeError(
            f"Несподіваний формат відповіді Alerts API: {repr(query_resp)}"
        )

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

    # 2. Деталі по composite_ids
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

    raw_alerts = det_body.get("resources") or []

    # тут сама уніфікація
    normalized = [normalize_cs_alert(a) for a in raw_alerts]
    return normalized

