# core/log_normalizer.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional


def _map_wazuh_level_to_severity(level: Optional[int]) -> Optional[str]:
    """
    Мапінг рівня Wazuh rule.level -> текстовий severity.
    Аналогічний тому, що ти вже використовуєш у фронті.
    """
    if level is None:
        return None
    try:
        lvl = int(level)
    except (ValueError, TypeError):
        return None

    if lvl <= 3:
        return "low"
    if lvl <= 7:
        return "medium"
    if lvl <= 11:
        return "high"
    return "critical"


def _map_cs_severity(severity: Optional[int], severity_name: Optional[str]) -> Optional[str]:
    """
    Приводимо CrowdStrike severity до "low/medium/high/critical/info".
    """
    if isinstance(severity_name, str) and severity_name:
        return severity_name.lower()

    if severity is None:
        return None

    try:
        sev = int(severity)
    except (ValueError, TypeError):
        return None

    if sev >= 80:
        return "critical"
    if sev >= 60:
        return "high"
    if sev >= 40:
        return "medium"
    if sev >= 20:
        return "low"
    return "info"


def _safe_get(d: Dict[str, Any], *keys, default=None):
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def normalize_wazuh_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Нормалізація одного сирого alert-а з індекса wazuh-alerts-* у
    уніфікований формат події.
    """
    agent = alert.get("agent") or {}
    data_win = _safe_get(alert, "data", "win", default={}) or {}
    eventdata = data_win.get("eventdata") or {}
    system = data_win.get("system") or {}
    rule = alert.get("rule") or {}

    # Час
    ts = alert.get("timestamp") or alert.get("@timestamp")
    ingest_ts = alert.get("@timestamp") if ts != alert.get("@timestamp") else None

    # Хост / агент
    hostname = system.get("computer") or agent.get("name")
    ip_local = agent.get("ip")

    # Користувач
    user_name = eventdata.get("targetUserName") or eventdata.get("subjectUserName")
    user_domain = (
        eventdata.get("targetDomainName") or
        eventdata.get("subjectDomainName")
    )
    user_sid = (
        eventdata.get("targetUserSid") or
        eventdata.get("subjectUserSid")
    )

    # Процес
    process_name = eventdata.get("processName")
    process_id = eventdata.get("processId")
    # шлях процесу зазвичай є тільки у system.message як текст – на перший етап можна не парсити
    process_path = None
    process_cmdline = None

    # Severity
    level = rule.get("level")
    try:
        level_int = int(level) if level is not None else None
    except (ValueError, TypeError):
        level_int = None

    severity = _map_wazuh_level_to_severity(level_int)

    # MITRE
    mitre = rule.get("mitre") or {}
    tactics = mitre.get("tactic") or []
    techniques = mitre.get("technique") or []
    ids = mitre.get("id") or []

    tactic = tactics[0] if tactics else None
    tactic_id = ids[0] if ids else None
    technique = techniques[0] if techniques else None
    # у Wazuh technique_id зазвичай в "id", а technique в "technique"
    technique_id = tactic_id  # або None; можна уточнити пізніше

    # Мережа (в інших типах подій може бути; у нашому прикладі немає)
    src_ip = alert.get("srcip") or alert.get("src_ip")
    dst_ip = alert.get("dstip") or alert.get("dst_ip")
    src_port = alert.get("srcport") or alert.get("src_port")
    dst_port = alert.get("dstport") or alert.get("dst_port")
    protocol = alert.get("protocol")

    description = rule.get("description")
    full_message = system.get("message")

    normalized = {
        "source": "wazuh",

        "timestamp": ts,
        "ingest_timestamp": ingest_ts,

        "hostname": hostname,
        "agent_id": agent.get("id"),
        "device_id": None,
        "ip_local": ip_local,
        "ip_external": None,

        "severity": severity,
        "severity_numeric": level_int,
        "status": None,

        "event_category": "authentication" if system.get("eventID") in ("4624", "4634") else None,
        "event_action": rule.get("description"),
        "event_provider": system.get("providerName"),

        "rule_id": rule.get("id"),
        "rule_name": rule.get("description"),

        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique": technique,
        "technique_id": technique_id,

        "user_name": user_name,
        "user_domain": user_domain,
        "user_sid": user_sid,

        "process_name": process_name,
        "process_path": process_path,
        "process_command_line": process_cmdline,
        "process_id": process_id,
        "parent_process_name": None,
        "parent_process_path": None,
        "parent_process_id": None,

        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "network_protocol": protocol,
        "network_direction": None,

        "description": full_message or description,
        "short_description": description,
        "product": "Wazuh",

        "raw": alert,
    }

    return normalized


def normalize_cs_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Нормалізація одного сирого alert-а з CrowdStrike Alerts API
    (як у твоєму прикладі) в той же уніфікований формат.
    """
    device = alert.get("device") or {}

    # Час
    ts = alert.get("created_timestamp") or alert.get("timestamp") or alert.get("context_timestamp")
    ingest_ts = alert.get("updated_timestamp")

    # Хост / device
    hostname = device.get("hostname")
    ip_local = device.get("local_ip")
    ip_external = device.get("external_ip")

    # Користувач
    user_name = alert.get("user_name")
    user_domain = alert.get("logon_domain") or device.get("hostinfo", {}).get("domain")
    user_sid = alert.get("user_id")

    # Процес / parent
    process_name = alert.get("filename")
    process_path = alert.get("filepath")
    process_cmdline = alert.get("cmdline")
    process_id = alert.get("process_id") or alert.get("local_process_id")

    parent = alert.get("parent_details") or {}
    parent_process_name = parent.get("filename")
    parent_process_path = parent.get("filepath")
    parent_process_id = parent.get("process_id") or parent.get("local_process_id")

    # Severity
    severity_numeric = alert.get("severity")
    severity = _map_cs_severity(severity_numeric, alert.get("severity_name"))

    # MITRE - беремо з верхнього рівня, якщо є; якщо ні – з mitre_attack[0]
    tactic = alert.get("tactic")
    tactic_id = alert.get("tactic_id")
    technique = alert.get("technique")
    technique_id = alert.get("technique_id")

    if not tactic or not technique:
        mitre_list = alert.get("mitre_attack") or []
        if mitre_list:
            m0 = mitre_list[0]
            tactic = tactic or m0.get("tactic")
            tactic_id = tactic_id or m0.get("tactic_id")
            technique = technique or m0.get("technique")
            technique_id = technique_id or m0.get("technique_id")

    # Мережа: беремо перший outbound network_access
    net_list = alert.get("network_accesses") or []
    src_ip = src_port = dst_ip = dst_port = proto = direction = None
    if isinstance(net_list, list) and net_list:
        chosen = None
        for n in net_list:
            if n.get("connection_direction") == "Outbound":
                chosen = n
                break
        if not chosen:
            chosen = net_list[0]
        if chosen:
            src_ip = chosen.get("local_address")
            src_port = chosen.get("local_port")
            dst_ip = chosen.get("remote_address")
            dst_port = chosen.get("remote_port")
            proto = chosen.get("protocol")
            direction = chosen.get("connection_direction")

    description = alert.get("description")
    short_desc = alert.get("display_name") or alert.get("name")

    normalized = {
        "source": "crowdstrike",

        "timestamp": ts,
        "ingest_timestamp": ingest_ts,

        "hostname": hostname,
        "agent_id": alert.get("agent_id"),
        "device_id": device.get("device_id"),
        "ip_local": ip_local,
        "ip_external": ip_external,

        "severity": severity,
        "severity_numeric": severity_numeric,
        "status": alert.get("status"),

        "event_category": alert.get("scenario"),       # наприклад "credential_theft", "suspicious_activity"
        "event_action": alert.get("display_name") or alert.get("name"),
        "event_provider": "CrowdStrike",

        "rule_id": alert.get("pattern_id"),
        "rule_name": short_desc,

        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique": technique,
        "technique_id": technique_id,

        "user_name": user_name,
        "user_domain": user_domain,
        "user_sid": user_sid,

        "process_name": process_name,
        "process_path": process_path,
        "process_command_line": process_cmdline,
        "process_id": process_id,
        "parent_process_name": parent_process_name,
        "parent_process_path": parent_process_path,
        "parent_process_id": parent_process_id,

        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "network_protocol": proto,
        "network_direction": direction,

        "description": description,
        "short_description": short_desc,
        "product": alert.get("product") or "CrowdStrike",

        "raw": alert,
    }

    return normalized
