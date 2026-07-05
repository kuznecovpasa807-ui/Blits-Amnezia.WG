import ipaddress
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request

from app.config import SERVER_PUBLIC_IP, logger
from app.database import get_db_connection
from app.vpn_manager import get_vpn_setting

CASCADE_COMMENT_PREFIX = "blitz-cascade-"
DEFAULT_CASCADE_V2_PORT = "54912"
DEFAULT_CASCADE_LEGACY_PORT = "54913"


def get_cascade_setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row:
            return row["value"]
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, default))
        conn.commit()
        return default
    finally:
        conn.close()


def set_cascade_setting(key: str, value: str):
    conn = get_db_connection()
    try:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
    finally:
        conn.close()


def get_cascade_settings() -> dict:
    v2_port = get_vpn_setting("port", "43912")
    legacy_port = get_vpn_setting("legacy_port", "43913")
    enabled = get_cascade_setting("cascade_enabled", "0")
    v2_local_port = get_cascade_setting("cascade_v2_local_port", DEFAULT_CASCADE_V2_PORT)
    legacy_local_port = get_cascade_setting("cascade_legacy_local_port", DEFAULT_CASCADE_LEGACY_PORT)
    if enabled != "1" and v2_local_port == v2_port:
        v2_local_port = DEFAULT_CASCADE_V2_PORT
    if enabled != "1" and legacy_local_port == legacy_port:
        legacy_local_port = DEFAULT_CASCADE_LEGACY_PORT
    return {
        "enabled": enabled,
        "target_ip": get_cascade_setting("cascade_target_ip", ""),
        "v2_local_port": v2_local_port,
        "v2_target_port": get_cascade_setting("cascade_v2_target_port", v2_port),
        "legacy_enabled": get_cascade_setting("cascade_legacy_enabled", "1"),
        "legacy_local_port": legacy_local_port,
        "legacy_target_port": get_cascade_setting("cascade_legacy_target_port", legacy_port),
        "target_panel_url": get_cascade_setting("cascade_target_panel_url", ""),
        "target_api_token": get_cascade_setting("cascade_target_api_token", ""),
        "main_v2_port": v2_port,
        "main_legacy_port": legacy_port,
    }


def validate_port(value: str, label: str) -> str:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{label}: нужен порт числом")
    if port < 1 or port > 65535:
        raise ValueError(f"{label}: порт должен быть от 1 до 65535")
    return str(port)


def validate_target_ip(value: str) -> str:
    target_ip = str(value).strip()
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError("IP целевого сервера указан неверно")
    return target_ip


def _run(command: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=check)


def _ensure_linux_root():
    if os.name == "nt":
        raise RuntimeError("Каскад можно применять только на Linux-сервере")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("Для управления iptables нужны права root")


def _default_interface() -> str:
    result = _run(["ip", "route", "get", "8.8.8.8"])
    parts = result.stdout.split()
    if "dev" not in parts:
        raise RuntimeError("Не удалось определить внешний сетевой интерфейс")
    return parts[parts.index("dev") + 1]


def _save_rules():
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], check=False)


def clear_cascade_rules():
    _ensure_linux_root()
    result = _run(["iptables-save"])
    filtered = "\n".join(
        line for line in result.stdout.splitlines()
        if CASCADE_COMMENT_PREFIX not in line
    ) + "\n"
    subprocess.run(["iptables-restore"], input=filtered, text=True, capture_output=True, check=True)
    _save_rules()


def _add_rule(command: list[str]):
    _run(command)


def _apply_one(label: str, local_port: str, target_ip: str, target_port: str, iface: str):
    comment = f"{CASCADE_COMMENT_PREFIX}{label}"
    _add_rule(["iptables", "-A", "INPUT", "-p", "udp", "--dport", local_port, "-m", "comment", "--comment", comment, "-j", "ACCEPT"])
    _add_rule(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", local_port, "-m", "comment", "--comment", comment, "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"])
    _add_rule(["iptables", "-A", "FORWARD", "-p", "udp", "-d", target_ip, "--dport", target_port, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-m", "comment", "--comment", comment, "-j", "ACCEPT"])
    _add_rule(["iptables", "-A", "FORWARD", "-p", "udp", "-s", target_ip, "--sport", target_port, "-m", "state", "--state", "ESTABLISHED,RELATED", "-m", "comment", "--comment", comment, "-j", "ACCEPT"])


def apply_cascade(settings: dict):
    _ensure_linux_root()
    target_ip = validate_target_ip(settings["target_ip"])
    v2_local = validate_port(settings["v2_local_port"], "Входящий порт Amnezia 2.0")
    v2_target = validate_port(settings["v2_target_port"], "Порт Amnezia 2.0 на целевом сервере")
    legacy_local = validate_port(settings["legacy_local_port"], "Входящий порт Legacy")
    legacy_target = validate_port(settings["legacy_target_port"], "Порт Legacy на целевом сервере")
    main_v2_port = get_vpn_setting("port", "43912")
    main_legacy_port = get_vpn_setting("legacy_port", "43913")
    main_ports = {main_v2_port: "основной Amnezia 2.0", main_legacy_port: "основной Legacy"}
    for port, label in ((v2_local, "входящий порт каскада Amnezia 2.0"), (legacy_local, "входящий порт каскада Legacy")):
        if port in main_ports:
            raise ValueError(f"{label} не должен совпадать с портом {main_ports[port]} ({port}), чтобы каскад не мешал обычному VPN")

    clear_cascade_rules()
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    iface = _default_interface()
    _apply_one("amnezia-v2", v2_local, target_ip, v2_target, iface)
    if settings.get("legacy_enabled") == "1":
        _apply_one("amnezia-legacy", legacy_local, target_ip, legacy_target, iface)
    _add_rule(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", f"{CASCADE_COMMENT_PREFIX}masquerade", "-j", "MASQUERADE"])
    _save_rules()


def active_cascade_rules() -> list[str]:
    if os.name == "nt":
        return []
    try:
        result = _run(["iptables-save"], check=False)
    except Exception:
        return []
    return [line for line in result.stdout.splitlines() if CASCADE_COMMENT_PREFIX in line]


def _config_value(config_text: str, key: str, default: str = "") -> str:
    match = re.search(rf"(?im)^\s*{re.escape(key)}\s*=\s*([^\r\n#]*)", config_text or "")
    return match.group(1).strip() if match else default


def rewrite_config_endpoint(config_text: str, host: str, port: str) -> str:
    endpoint = f"Endpoint = {host}:{port}"
    if re.search(r"(?im)^\s*Endpoint\s*=", config_text or ""):
        return re.sub(r"(?im)^\s*Endpoint\s*=.*$", endpoint, config_text)
    return (config_text.rstrip() + "\n" + endpoint + "\n").strip() + "\n"


def _request_json(url: str, method: str = "GET", token: str = "", payload: dict | None = None) -> dict:
    data = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"Целевая панель вернула ошибку {exc.code}: {detail}") from exc


def _request_text(url: str, token: str = "") -> str:
    request = urllib.request.Request(url, method="GET")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"Не удалось получить конфиг с целевой панели ({exc.code}): {detail}") from exc


def _base_url(settings: dict) -> str:
    base_url = (settings.get("target_panel_url") or "").strip().rstrip("/")
    if not base_url:
        raise ValueError("В настройках каскада укажите URL целевой Blitz Panel")
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("URL целевой панели должен начинаться с http:// или https://")
    return base_url


def create_remote_cascade_client(name: str, days: int, traffic_limit_gb: float) -> dict:
    settings = get_cascade_settings()
    if settings.get("enabled") != "1":
        raise ValueError("Сначала включите правила каскада")
    token = (settings.get("target_api_token") or "").strip()
    if not token:
        raise ValueError("В настройках каскада укажите API-токен целевой панели")

    base_url = _base_url(settings)
    remote = _request_json(
        f"{base_url}/api/v1/clients",
        method="POST",
        token=token,
        payload={"name": name, "days": days, "traffic_limit_gb": traffic_limit_gb},
    )
    remote_id = remote["client_id"]
    v2 = _request_text(f"{base_url}/clients/{remote_id}/download?version=2.0", token)
    legacy = _request_text(f"{base_url}/clients/{remote_id}/download?version=1.0", token)
    v2_split = _request_text(f"{base_url}/clients/{remote_id}/download?version=2.0&split=true", token)
    legacy_split = _request_text(f"{base_url}/clients/{remote_id}/download?version=1.0&split=true", token)

    public_ip = get_vpn_setting("public_ip", SERVER_PUBLIC_IP)
    return {
        "remote": remote,
        "remote_client_id": remote_id,
        "remote_ip_address": remote.get("ip_address") or _config_value(v2, "Address"),
        "config_text_v2": rewrite_config_endpoint(v2, public_ip, settings["v2_local_port"]),
        "config_text_legacy": rewrite_config_endpoint(legacy, public_ip, settings["legacy_local_port"]),
        "config_text_split_v2": rewrite_config_endpoint(v2_split, public_ip, settings["v2_local_port"]),
        "config_text_split_legacy": rewrite_config_endpoint(legacy_split, public_ip, settings["legacy_local_port"]),
    }


def remote_client_action(remote_client_id: str, action: str, days: int | None = None):
    settings = get_cascade_settings()
    token = (settings.get("target_api_token") or "").strip()
    if not token:
        raise ValueError("Не указан API-токен целевой панели")
    base_url = _base_url(settings)
    if action == "delete":
        _request_json(f"{base_url}/api/v1/clients/{remote_client_id}", method="DELETE", token=token)
    elif action == "extend":
        _request_json(f"{base_url}/api/v1/clients/{remote_client_id}/extend", method="POST", token=token, payload={"days": days or 30})
    elif action in {"disable", "enable"}:
        _request_json(f"{base_url}/api/v1/clients/{remote_client_id}/{action}", method="POST", token=token)
