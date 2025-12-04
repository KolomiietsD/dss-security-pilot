# core/wazuh_api.py
import os
import requests


class WazuhAPIError(Exception):
    """Помилка при роботі з Wazuh API."""
    pass


def _get_wazuh_config():
    """
    Читає конфіг з змінних середовища.
    Аналогічно до _get_cs_credentials() для Falcon.
    """
    base_url = os.getenv("WAZUH_API_URL")
    user = os.getenv("WAZUH_API_USER")
    password = os.getenv("WAZUH_API_PASSWORD")
    verify_ssl_raw = os.getenv("WAZUH_API_VERIFY_SSL", "false")

    if not user or not password:
        raise RuntimeError(
            "Не знайдено WAZUH_API_USER / WAZUH_API_PASSWORD у змінних середовища"
        )

    # Проста обробка true/false
    verify_ssl = verify_ssl_raw.strip().lower() in ("1", "true", "yes")

    # прибираємо можливий слеш в кінці
    base_url = base_url.rstrip("/")

    return base_url, user, password, verify_ssl


def _get_token() -> str:
    """
    Отримує JWT-токен Wazuh API через basic auth (user/password).
    """
    base_url, user, password, verify_ssl = _get_wazuh_config()

    url = f"{base_url}/security/user/authenticate?raw=true"

    try:
        resp = requests.post(
            url,
            auth=(user, password),
            timeout=10,
            verify=verify_ssl,
        )
    except requests.RequestException as exc:
        raise WazuhAPIError(f"Помилка з'єднання з Wazuh API: {exc}") from exc

    if not resp.ok:
        raise WazuhAPIError(
            f"Не вдалося отримати токен Wazuh API "
            f"({resp.status_code}): {resp.text[:500]}"
        )

    token = resp.text.strip().strip('"')
    if not token:
        raise WazuhAPIError("Порожній токен Wazuh API у відповіді")

    return token


def _request(method: str, path: str, params: dict | None = None) -> dict:
    """
    Базовий запит до Wazuh API з авторизацією по Bearer-токену.
    """
    base_url, _, _, verify_ssl = _get_wazuh_config()
    token = _get_token()

    url = f"{base_url}{path}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            timeout=10,
            verify=verify_ssl,
        )
    except requests.RequestException as exc:
        raise WazuhAPIError(f"Помилка з'єднання з Wazuh API: {exc}") from exc

    if not resp.ok:
        raise WazuhAPIError(
            f"Wazuh API {resp.status_code}: {resp.text[:500]}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise WazuhAPIError("Не вдалося розпарсити JSON-відповідь Wazuh API") from exc

    return data


# ----------------- ПУБЛІЧНІ ФУНКЦІЇ ----------------- #

def get_agents(limit: int = 100, status: str | None = None) -> list[dict]:
    """
    Отримати список агентів Wazuh.

    :param limit: скільки агентів повернути максимум
    :param status: опціональний фільтр ('active', 'disconnected', ...)
    """
    params: dict[str, str | int] = {
        "limit": limit,
        "sort": "+id",
    }
    if status:
        params["status"] = status

    data = _request("GET", "/agents", params=params)
    items = data.get("data", {}).get("affected_items", [])
    return items


def get_agent(agent_id: str) -> dict:
    """
    Отримати детальну інформацію про конкретного агента.
    """
    data = _request("GET", f"/agents/{agent_id}")
    items = data.get("data", {}).get("affected_items", [])
    if not items:
        raise WazuhAPIError(f"Агент з id={agent_id} не знайдений")
    return items[0]


def get_agent_stats(agent_id: str) -> dict:
    """
    Отримати статистику по агенту.
    """
    data = _request("GET", f"/agents/{agent_id}/stats")
    return data.get("data", {})
