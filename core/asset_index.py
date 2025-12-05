# core/asset_index.py
"""
Уніфікація активів та логів з різних джерел (Wazuh, CrowdStrike, інші).

Ідея:
- Є агенти Wazuh (get_agents()).
- Є девайси CrowdStrike (get_recent_devices()).
- Є логи:
    - Wazuh alerts / SIEM events (get_recent_alerts(), get_recent_siem_events()).
    - CrowdStrike detects (get_recent_detects()).
- Ми зводимо все до єдиного списку "активів", де кожен актив визначається ключем
  (hostname_norm, ip_norm). Якщо hostname+ip співпадають між Wazuh і CS –
  це один і той самий актив з двома джерелами.
- До кожного активу прив’язуємо логи з усіх джерел.

Цей модуль НЕ прив’язаний до Django напряму – це "чиста" логіка,
яку можна викликати з будь-якого view / воркера.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------- Допоміжні функції нормалізації ----------

def _norm_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    return hostname.strip().lower()


def _norm_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return ip.strip()


def _extract_ip_from_wazuh_agent(agent: Dict[str, Any]) -> Optional[str]:
    """
    Повертає IP з агента Wazuh.
    Wazuh часто має щось типу:
      agent["ip"] або agent["ip_address"] або список у agent["ips"].
    """
    ip = agent.get("ip") or agent.get("ip_address")
    if ip:
        return str(ip)

    # якщо раптом там список
    ips = agent.get("ips") or agent.get("ip_list")
    if isinstance(ips, list) and ips:
        return str(ips[0])

    return None


def _extract_ip_from_cs_device(dev: Dict[str, Any]) -> Optional[str]:
    """
    Повертає IP з девайса CrowdStrike.
    У Falcon API часто IPшники в "local_ip", "local_ip_address", або у списку.
    Точна структура залежить від твого коду get_recent_devices.
    """
    ip = (
        dev.get("local_ip")
        or dev.get("local_ip_address")
        or dev.get("ip")
        or dev.get("ip_address")
    )
    if ip:
        return str(ip)

    ips = dev.get("local_ip_list") or dev.get("ip_list")
    if isinstance(ips, list) and ips:
        return str(ips[0])

    return None


def _hostname_from_wazuh_agent(agent: Dict[str, Any]) -> Optional[str]:
    """
    hostname для Wazuh-агента.
    Зазвичай це agent["name"] або agent["hostname"].
    """
    return agent.get("hostname") or agent.get("name")


def _hostname_from_cs_device(dev: Dict[str, Any]) -> Optional[str]:
    """
    hostname для CrowdStrike-девайса.
    Найчастіше: dev["hostname"] або dev["device_hostname"].
    """
    return dev.get("hostname") or dev.get("device_hostname")


def _hostname_from_wazuh_log(ev: Dict[str, Any]) -> Optional[str]:
    """
    hostname з Wazuh-логу.
    Часто: ev["hostname"], ev["agent"]["name"], ev["agent"]["hostname"].
    """
    return (
        ev.get("hostname")
        or ev.get("agent_name")
        or (ev.get("agent") or {}).get("name")
        or (ev.get("agent") or {}).get("hostname")
    )


def _ip_from_wazuh_log(ev: Dict[str, Any]) -> Optional[str]:
    """
    IP з Wazuh-логу. Це може бути srcip, dstip, або щось інше.
    Для прив'язки до активу бажано брати "основний" хост –
    у Wazuh це не завжди тривіально, тому тут базовий варіант.
    """
    # Якщо подія "про сам хост", там може бути т.зв. "agent ip" у іншому полі,
    # але для старту беремо srcip/dstip.
    return ev.get("srcip") or ev.get("src_ip") or ev.get("dstip") or ev.get("dst_ip")


def _hostname_from_cs_log(d: Dict[str, Any]) -> Optional[str]:
    """
    hostname з CrowdStrike-детекта.
    """
    return (
        d.get("hostname")
        or d.get("device_hostname")
        or (d.get("device") or {}).get("hostname")
    )


def _ip_from_cs_log(d: Dict[str, Any]) -> Optional[str]:
    """
    IP з CrowdStrike-детекта.
    """
    return (
        d.get("local_ip")
        or d.get("ip")
        or (d.get("device") or {}).get("local_ip")
    )


# ---------- Модель уніфікованого активу ----------

@dataclass
class UnifiedAsset:
    """
    Уніфікований актив (Wazuh + CrowdStrike + інші).
    """
    key: Tuple[Optional[str], Optional[str]]  # (hostname_norm, ip_norm)

    # "канонічні" поля для відображення
    hostname: Optional[str] = None
    ip: Optional[str] = None

    # джерела
    has_wazuh: bool = False
    has_crowdstrike: bool = False

    # "сирі" об'єкти джерел (за бажанням, щоб не губити)
    wazuh_agents: List[Dict[str, Any]] = field(default_factory=list)
    crowdstrike_devices: List[Dict[str, Any]] = field(default_factory=list)

    # логи з усіх джерел
    logs: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Перетворення в dict для JSON / фронтенду.
        """
        return {
            "key": {
                "hostname_norm": self.key[0],
                "ip_norm": self.key[1],
            },
            "hostname": self.hostname,
            "ip": self.ip,
            "sources": {
                "wazuh": self.has_wazuh,
                "crowdstrike": self.has_crowdstrike,
            },
            # Можна сюди ще прокинути агреговані поля (OS, status, risk тощо).
            "wazuh_agents": self.wazuh_agents,
            "crowdstrike_devices": self.crowdstrike_devices,
            "logs": self.logs,
        }


# ---------- Побудова списку активів ----------

def build_assets_from_sources(
    wazuh_agents: List[Dict[str, Any]],
    cs_devices: List[Dict[str, Any]],
) -> Dict[Tuple[Optional[str], Optional[str]], UnifiedAsset]:
    """
    Створює словник { (hostname_norm, ip_norm) -> UnifiedAsset }
    на основі списків агентів Wazuh та девайсів CrowdStrike.

    Якщо hostname+ip збігаються між Wazuh і CS – це один актив.
    Якщо hostname однаковий, але ip різний – це два ключі (так безпечніше).
    """

    assets: Dict[Tuple[Optional[str], Optional[str]], UnifiedAsset] = {}

    # Спочатку Wazuh
    for agent in wazuh_agents or []:
        raw_hostname = _hostname_from_wazuh_agent(agent)
        raw_ip = _extract_ip_from_wazuh_agent(agent)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)

        key = (hn, ip)

        if key not in assets:
            assets[key] = UnifiedAsset(key=key, hostname=raw_hostname, ip=raw_ip)

        asset = assets[key]
        asset.has_wazuh = True
        asset.wazuh_agents.append(agent)

        # Якщо hostname/ip на активі були пусті, а тут з'явились – оновимо
        if not asset.hostname and raw_hostname:
            asset.hostname = raw_hostname
        if not asset.ip and raw_ip:
            asset.ip = raw_ip

    # Потім CrowdStrike
    for dev in cs_devices or []:
        raw_hostname = _hostname_from_cs_device(dev)
        raw_ip = _extract_ip_from_cs_device(dev)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)

        key = (hn, ip)

        if key not in assets:
            assets[key] = UnifiedAsset(key=key, hostname=raw_hostname, ip=raw_ip)

        asset = assets[key]
        asset.has_crowdstrike = True
        asset.crowdstrike_devices.append(dev)

        if not asset.hostname and raw_hostname:
            asset.hostname = raw_hostname
        if not asset.ip and raw_ip:
            asset.ip = raw_ip

    return assets


# ---------- Прив'язка логів до активів ----------

def attach_wazuh_logs(
    assets: Dict[Tuple[Optional[str], Optional[str]], UnifiedAsset],
    wazuh_logs: List[Dict[str, Any]],
    create_missing_assets: bool = True,
) -> None:
    """
    Прив'язує Wazuh-логи до існуючих активів.
    Якщо create_missing_assets=True і для лога немає активу з таким hostname+ip –
    створюємо "новий" актив тільки по логу.
    """
    for ev in wazuh_logs or []:
        raw_hostname = _hostname_from_wazuh_log(ev)
        raw_ip = _ip_from_wazuh_log(ev)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)

        key = (hn, ip)

        asset = assets.get(key)
        if asset is None and create_missing_assets:
            asset = UnifiedAsset(key=key, hostname=raw_hostname, ip=raw_ip)
            asset.has_wazuh = True  # бо лог прийшов з Wazuh
            assets[key] = asset

        if asset is None:
            continue  # лог "висить у повітрі", але не створюємо актив

        log_entry = {
            "source": "wazuh",
            "hostname": raw_hostname,
            "ip": raw_ip,
            "raw": ev,
        }
        asset.logs.append(log_entry)


def attach_cs_logs(
    assets: Dict[Tuple[Optional[str], Optional[str]], UnifiedAsset],
    cs_logs: List[Dict[str, Any]],
    create_missing_assets: bool = True,
) -> None:
    """
    Прив'язує CrowdStrike-логи до існуючих активів.
    Аналог attach_wazuh_logs, але для CS.
    """
    for d in cs_logs or []:
        raw_hostname = _hostname_from_cs_log(d)
        raw_ip = _ip_from_cs_log(d)

        hn = _norm_hostname(raw_hostname)
        ip = _norm_ip(raw_ip)

        key = (hn, ip)

        asset = assets.get(key)
        if asset is None and create_missing_assets:
            asset = UnifiedAsset(key=key, hostname=raw_hostname, ip=raw_ip)
            asset.has_crowdstrike = True
            assets[key] = asset

        if asset is None:
            continue

        log_entry = {
            "source": "crowdstrike",
            "hostname": raw_hostname,
            "ip": raw_ip,
            "raw": d,
        }
        asset.logs.append(log_entry)


# ---------- Високо-рівнева функція "все разом" ----------

def build_unified_assets_with_logs(
    wazuh_agents: List[Dict[str, Any]],
    cs_devices: List[Dict[str, Any]],
    wazuh_alerts: List[Dict[str, Any]],
    wazuh_siem_events: List[Dict[str, Any]],
    cs_detects: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Високорівнева функція, яка:
    - будує уніфіковані активи з Wazuh + CS;
    - прив'язує до них усі логи;
    - повертає список dict'ів, готових до віддачі на фронтенд.

    ЦЕ – якраз те, що можна буде потім передавати в BERT-пайплайн:
    по кожному активу є всі логи.
    """
    assets = build_assets_from_sources(wazuh_agents, cs_devices)

    # всі wazuh-логи разом
    all_wazuh_logs = (wazuh_alerts or []) + (wazuh_siem_events or [])
    attach_wazuh_logs(assets, all_wazuh_logs, create_missing_assets=True)

    # всі crowdstrike-детекти
    attach_cs_logs(assets, cs_detects, create_missing_assets=True)

    # повертаємо як список dict
    return [asset.to_dict() for asset in assets.values()]
