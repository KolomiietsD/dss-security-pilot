# core/wazuh_api.py
import os
import requests


class WazuhAPIError(Exception):
    """Помилка при роботі з Wazuh API / Wazuh Indexer."""
    pass


def _get_wazuh_config():
    """
    Читає конфіг Wazuh API зі змінних середовища.
    Приклад:
      WAZUH_API_URL=https://wazuh-manager:55000
      WAZUH_API_USER=foo
      WAZUH_API_PASSWORD=bar
      WAZUH_API_VERIFY_SSL=false
    """
    base_url = os.getenv("WAZUH_API_URL")
    user = os.getenv("WAZUH_API_USER")
    password = os.getenv("WAZUH_API_PASSWORD")
    verify_ssl_raw = os.getenv("WAZUH_API_VERIFY_SSL", "false")

    if not base_url or not user or not password:
        raise RuntimeError(
            "Не знайдено WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD у змінних середовища"
        )

    # Проста обробка true/false
    verify_ssl = verify_ssl_raw.strip().lower() in ("1", "true", "yes")

    # прибираємо можливий слеш в кінці
    base_url = base_url.rstrip("/")

    return base_url, user, password, verify_ssl


def _get_indexer_config():
    """
    Конфіг для Wazuh Indexer (OpenSearch/Elasticsearch).

    Очікуємо змінні середовища, наприклад:
      WAZUH_INDEXER_URL=https://wazuh-indexer:9200
      WAZUH_INDEXER_USER=admin
      WAZUH_INDEXER_PASSWORD=your_password
      WAZUH_INDEXER_VERIFY_SSL=false
    """
    base_url = os.getenv("WAZUH_INDEXER_URL")
    user = os.getenv("WAZUH_INDEXER_USER")
    password = os.getenv("WAZUH_INDEXER_PASSWORD")
    verify_ssl_raw = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false")

    if not base_url or not user or not password:
        raise RuntimeError(
            "Не знайдено WAZUH_INDEXER_URL / WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD "
            "у змінних середовища (потрібно для читання alerts/events)."
        )

    verify_ssl = verify_ssl_raw.strip().lower() in ("1", "true", "yes")
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


# ----------------- ПУБЛІЧНІ ФУНКЦІЇ ДЛЯ MANAGER API ----------------- #

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


# ----------------- ПУБЛІЧНІ ФУНКЦІЇ ДЛЯ INDEXER (ALERTS / EVENTS) ----------------- #

def get_recent_alerts(limit: int = 50) -> list[dict]:
    """
    Останні детекти з Wazuh Indexer (індекс wazuh-alerts-*).
    ЦЕ НЕ WAZUH API НА 55000, а запит у OpenSearch/Elasticsearch.
    """
    base_url, user, password, verify_ssl = _get_indexer_config()
    url = f"{base_url}/wazuh-alerts-*/_search"

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }

    try:
        resp = requests.post(
            url,
            auth=(user, password),
            json=body,
            timeout=10,
            verify=verify_ssl,
        )
    except requests.RequestException as exc:
        raise WazuhAPIError(f"Помилка з'єднання з Wazuh Indexer (alerts): {exc}") from exc

    if not resp.ok:
        raise WazuhAPIError(
            f"Wazuh Indexer (alerts) {resp.status_code}: {resp.text[:500]}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise WazuhAPIError("Не вдалося розпарсити JSON-відповідь Wazuh Indexer (alerts)") from exc

    hits = data.get("hits", {}).get("hits", [])

    results: list[dict] = []
    for h in hits:
        src = h.get("_source", {}) or {}
        # нормалізуємо timestamp
        ts = src.get("@timestamp") or src.get("timestamp")
        if ts and "timestamp" not in src:
            src["timestamp"] = ts
        results.append(src)
    return results


def get_recent_siem_events(limit: int = 50) -> list[dict]:
    """
    Останні "сиcлог" / SIEM-івенти з Wazuh Indexer (індекс wazuh-archives-*).
    """
    base_url, user, password, verify_ssl = _get_indexer_config()
    url = f"{base_url}/wazuh-archives-*/_search"

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }

    try:
        resp = requests.post(
            url,
            auth=(user, password),
            json=body,
            timeout=10,
            verify=verify_ssl,
        )
    except requests.RequestException as exc:
        raise WazuhAPIError(f"Помилка з'єднання з Wazuh Indexer (events): {exc}") from exc

    if not resp.ok:
        raise WazuhAPIError(
            f"Wazuh Indexer (events) {resp.status_code}: {resp.text[:500]}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise WazuhAPIError("Не вдалося розпарсити JSON-відповідь Wazuh Indexer (events)") from exc

    hits = data.get("hits", {}).get("hits", [])

    results: list[dict] = []
    for h in hits:
        src = h.get("_source", {}) or {}
        ts = src.get("@timestamp") or src.get("timestamp")
        if ts and "timestamp" not in src:
            src["timestamp"] = ts
        results.append(src)
    return results
