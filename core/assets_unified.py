# core/assets_unified.py

from .crowdstrike_api import get_recent_devices

def load_assets_from_crowdstrike(limit=100):
    """Тягнемо хости з CrowdStrike і конвертуємо їх в уніфікований формат asset'а."""
    devices = get_recent_devices(limit=limit)
    assets = []

    for d in devices:
        asset = {
            "asset_id": f"cs:{d.get('device_id')}",       # або інший унікальний ID з CrowdStrike
            "hostname": d.get("hostname"),
            "ip": d.get("local_ip"),
            "platform": d.get("platform_name"),
            "vendor": "CrowdStrike",
            "source": "crowdstrike",
            "online_status": d.get("online_status"),      # online/offline/unknown
            "risk_score": None,                           # placeholder під майбутню модель
        }
        assets.append(asset)

    return assets


def get_unified_assets():
    """Єдина точка збору активів з усіх вендорів.

    Зараз – тільки CrowdStrike, потім сюди додаємо Nexpose, SIEM тощо.
    """
    assets = []

    # CrowdStrike
    try:
        cs_assets = load_assets_from_crowdstrike(limit=100)
        assets.extend(cs_assets)
    except Exception:
        # можна залогувати, щоб не роняти всю сторінку
        pass

    # TODO: Nexpose, інші вендори
    # try:
    #     nx_assets = load_assets_from_nexpose(...)
    #     assets.extend(nx_assets)
    # except Exception:
    #     pass

    return assets
