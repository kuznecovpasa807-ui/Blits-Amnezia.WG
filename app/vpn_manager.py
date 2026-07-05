import os
import subprocess
import secrets
import base64
import tempfile
import datetime
import functools
import ipaddress
import re
import shutil
import socket
import time
from pathlib import Path
from app.config import (
    AWG_INTERFACE, AWG_CONFIG_FILE, AWG_PORT, AWG_SUBNET, AWG_SERVER_IP,
    CLIENTS_DIR, QR_DIR, SERVER_PUBLIC_IP, AWG_CONFIG_DIR, logger
)
from app.database import get_db_connection

LEGACY_INTERFACE = "awg_legacy"
LEGACY_CONFIG_FILE = AWG_CONFIG_DIR / f"{LEGACY_INTERFACE}.conf"
LEGACY_SERVER_IP = "10.66.67.1"
LEGACY_PORT_DEFAULT = "43913"
_last_cpu_sample = None
_last_interface_sample = None
_last_peer_transfer_sample = None

def legacy_ip_from_client_ip(client_ip: str) -> str:
    parts = client_ip.split(".")
    if len(parts) == 4:
        return f"10.66.67.{parts[3]}"
    return client_ip

def get_vpn_setting(key: str, default: str) -> str:
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        if row:
            return row['value']
        
        # Если значения нет в БД, запишем дефолтное
        conn = get_db_connection()
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, default))
        conn.commit()
        conn.close()
        return default
    except Exception as e:
        logger.error(f"Ошибка получения настройки {key}: {e}")
        return default

def set_vpn_setting(key: str, value: str):
    conn = get_db_connection()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def record_sync_status(interface: str, ok: bool, message: str = ""):
    prefix = f"sync_{interface}"
    now = datetime.datetime.utcnow().isoformat()
    set_vpn_setting(f"{prefix}_ok", "1" if ok else "0")
    set_vpn_setting(f"{prefix}_at", now)
    set_vpn_setting(f"{prefix}_message", (message or "OK")[:1000])

def get_sync_statuses() -> dict:
    result = {}
    for interface in (AWG_INTERFACE, LEGACY_INTERFACE):
        prefix = f"sync_{interface}"
        result[interface] = {
            "ok": get_vpn_setting(f"{prefix}_ok", "0") == "1",
            "at": get_vpn_setting(f"{prefix}_at", ""),
            "message": get_vpn_setting(f"{prefix}_message", "sync has not run yet"),
        }
    return result

def _rand_range(start: int, end: int) -> int:
    return start + secrets.randbelow(max(end - start + 1, 1))

def generate_awg_stealth_profile(include_v2_params: bool = True) -> dict:
    used_s = set()
    s_values = []
    while len(s_values) < (4 if include_v2_params else 2):
        value = _rand_range(5, 120)
        if value not in used_s:
            used_s.add(value)
            s_values.append(str(value))

    h_ranges = []
    base = _rand_range(650000000, 820000000)
    for index in range(4):
        start = base + index * 320000000 + _rand_range(1000000, 45000000)
        end = min(start + _rand_range(110000000, 230000000), 2147483000)
        h_ranges.append(f"{start}-{end}")

    profile = {
        "jc": str(_rand_range(3, 6)),
        "jmin": str(_rand_range(10, 80)),
        "jmax": str(_rand_range(90, 180)),
        "s1": s_values[0],
        "s2": s_values[1],
        "h1": h_ranges[0],
        "h2": h_ranges[1],
        "h3": h_ranges[2],
        "h4": h_ranges[3],
    }
    if include_v2_params:
        profile["s3"] = s_values[2]
        profile["s4"] = s_values[3]
    return profile

def _parse_config_peer_keys(path: Path) -> set[str]:
    keys = set()
    try:
        for line in path.read_text(errors="ignore").splitlines():
            if line.strip().startswith("PublicKey"):
                _, value = line.split("=", 1)
                keys.add(value.strip())
    except Exception:
        pass
    return keys

def get_reconcile_report() -> dict:
    conn = get_db_connection()
    try:
        active_rows = conn.execute(
            "SELECT id, name, public_key FROM clients WHERE disabled_at IS NULL AND deleted_at IS NULL"
        ).fetchall()
    finally:
        conn.close()

    db_keys = {row["public_key"]: {"id": row["id"], "name": row["name"]} for row in active_rows}
    reports = {}
    targets = {
        AWG_INTERFACE: AWG_CONFIG_FILE,
        LEGACY_INTERFACE: LEGACY_CONFIG_FILE,
    }
    for interface, config_path in targets.items():
        live_keys = set(_parse_awg_dump(interface).keys())
        file_keys = _parse_config_peer_keys(config_path)
        db_key_set = set(db_keys.keys())
        reports[interface] = {
            "db_count": len(db_key_set),
            "file_count": len(file_keys),
            "live_count": len(live_keys),
            "db_missing_in_file": sorted(db_key_set - file_keys),
            "db_missing_live": sorted(db_key_set - live_keys),
            "live_not_in_db": sorted(live_keys - db_key_set),
            "file_not_in_db": sorted(file_keys - db_key_set),
        }
    return reports

def generate_keypair() -> tuple[str, str]:
    """
    Генерирует пару приватного и публичного ключей AmneziaWG.
    Сначала пытается использовать системные утилиты awg/wg, затем делает fallback на Python secrets.
    """
    try:
        # Попытка через awg
        priv_proc = subprocess.run(["awg", "genkey"], capture_output=True, text=True, check=True)
        priv_key = priv_proc.stdout.strip()
        
        pub_proc = subprocess.run(["awg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
        pub_key = pub_proc.stdout.strip()
        return priv_key, pub_key
    except Exception:
        try:
            # Попытка через wg
            priv_proc = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
            priv_key = priv_proc.stdout.strip()
            
            pub_proc = subprocess.run(["wg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
            pub_key = pub_proc.stdout.strip()
            return priv_key, pub_key
        except Exception:
            # Фолбек на генерацию псевдослучайных ключей для локальных тестов
            logger.warning("Утилиты awg/wg не найдены в системе. Используем заглушки ключей (локальный режим).")
            priv_bytes = secrets.token_bytes(32)
            priv_key = base64.b64encode(priv_bytes).decode('utf-8')
            pub_bytes = secrets.token_bytes(32)
            pub_key = base64.b64encode(pub_bytes).decode('utf-8')
            return priv_key, pub_key

def generate_preshared_key() -> str:
    try:
        psk_proc = subprocess.run(["awg", "genpsk"], capture_output=True, text=True, check=True)
        return psk_proc.stdout.strip()
    except Exception:
        try:
            psk_proc = subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True)
            return psk_proc.stdout.strip()
        except Exception:
            return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")

def get_next_free_ip() -> str:
    """
    Выделяет следующий свободный IP-адрес из подсети 10.66.66.0/24 (кроме .1)
    Проверяем ВСЕ записи (включая удалённых клиентов), так как UNIQUE constraint
    в БД всё равно не позволит вставить дублирующийся IP.
    """
    conn = get_db_connection()
    rows = conn.execute("SELECT ip_address FROM clients").fetchall()
    conn.close()
    
    allocated_ips = {row['ip_address'] for row in rows}
    
    # Ищем свободный октет в диапазоне 2-254
    for i in range(2, 255):
        ip = f"10.66.66.{i}"
        if ip not in allocated_ips:
            return ip
            
    raise Exception("Свободные IP-адреса в подсети 10.66.66.0/24 исчерпаны!")

def get_server_private_key() -> str:
    """
    Считывает приватный ключ сервера.
    Если файл конфига уже есть, берет его из него.
    В противном случае пытается прочесть /etc/amnezia/amneziawg/server.key
    Если ключа нет вообще — генерирует временный для локальных тестов.
    """
    try:
        if AWG_CONFIG_FILE.exists():
            with open(AWG_CONFIG_FILE, "r") as f:
                for line in f:
                    if line.strip().startswith("PrivateKey"):
                        return line.split("=", 1)[1].strip()
                        
        server_key_path = Path("/etc/amnezia/amneziawg/server.key")
        if server_key_path.exists():
            return server_key_path.read_text().strip()
    except Exception as e:
        logger.error(f"Не удалось считать приватный ключ сервера: {e}")
        
    # Заглушка для локальных тестов
    return "SERVER_PRIVATE_KEY_PLACEHOLDER_LOCAL_DEVELOPMENT="

def get_server_public_key() -> str:
    """
    Вычисляет публичный ключ сервера из приватного ключа.
    """
    priv_key = get_server_private_key()
    try:
        pub_proc = subprocess.run(["awg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
        return pub_proc.stdout.strip()
    except Exception:
        try:
            pub_proc = subprocess.run(["wg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
            return pub_proc.stdout.strip()
        except Exception:
            return "SERVER_PUBLIC_KEY_PLACEHOLDER_LOCAL_DEVELOPMENT="

def get_legacy_server_private_key() -> str:
    try:
        if LEGACY_CONFIG_FILE.exists():
            with open(LEGACY_CONFIG_FILE, "r") as f:
                for line in f:
                    if line.strip().startswith("PrivateKey"):
                        return line.split("=", 1)[1].strip()
        key_path = AWG_CONFIG_DIR / "server_legacy.key"
        if key_path.exists():
            return key_path.read_text().strip()
        priv, _ = generate_keypair()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(priv)
        os.chmod(key_path, 0o600)
        return priv
    except Exception as e:
        logger.error(f"Не удалось получить legacy private key: {e}")
        return "SERVER_PRIVATE_KEY_PLACEHOLDER_LOCAL_DEVELOPMENT="

def get_legacy_server_public_key() -> str:
    priv_key = get_legacy_server_private_key()
    try:
        pub_proc = subprocess.run(["awg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
        return pub_proc.stdout.strip()
    except Exception:
        try:
            pub_proc = subprocess.run(["wg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
            return pub_proc.stdout.strip()
        except Exception:
            return "SERVER_PUBLIC_KEY_PLACEHOLDER_LOCAL_DEVELOPMENT="

def check_awg_interface_status() -> str:
    """
    Проверяет статус интерфейса awg0 в системе.
    Возвращает "active" (запущен), "inactive" (выключен) или "not_installed" (утилита отсутствует).
    """
    if not os.path.exists("/sys/class/net/" + AWG_INTERFACE):
        # Дополнительная проверка через systemctl
        try:
            res = subprocess.run(["systemctl", "is-active", f"awg-quick@{AWG_INTERFACE}"], capture_output=True, text=True)
            if res.stdout.strip() == "active":
                return "active"
        except Exception:
            pass
        return "inactive"
    return "active"

def _parse_awg_dump(interface: str) -> dict:
    peers = {}
    try:
        proc = subprocess.run(
            ["awg", "show", interface, "dump"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except Exception:
        return peers

    for line in proc.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        public_key = parts[0]
        try:
            latest_handshake = int(parts[4])
        except ValueError:
            latest_handshake = 0
        try:
            transfer_rx = int(parts[5])
            transfer_tx = int(parts[6])
        except ValueError:
            transfer_rx = 0
            transfer_tx = 0
        peers[public_key] = {
            "interface": interface,
            "latest_handshake": latest_handshake,
            "transfer_rx": transfer_rx,
            "transfer_tx": transfer_tx,
        }
    return peers

def get_client_connection_statuses() -> dict:
    now = int(time.time())
    statuses = {}
    for interface in (AWG_INTERFACE, LEGACY_INTERFACE):
        for public_key, data in _parse_awg_dump(interface).items():
            latest = data["latest_handshake"]
            online = latest > 0 and now - latest <= 180
            current = statuses.get(public_key)
            if not current or latest > current["latest_handshake"]:
                statuses[public_key] = {
                    **data,
                    "online": online,
                    "seconds_ago": (now - latest) if latest else None,
                }
            elif online:
                current["online"] = True
    return statuses

def get_clients_traffic_usage() -> dict:
    usage = {}
    for interface in (AWG_INTERFACE, LEGACY_INTERFACE):
        for public_key, data in _parse_awg_dump(interface).items():
            item = usage.setdefault(public_key, {"rx": 0, "tx": 0, "total": 0})
            item["rx"] += int(data.get("transfer_rx", 0))
            item["tx"] += int(data.get("transfer_tx", 0))
            item["total"] = item["rx"] + item["tx"]
    return usage

def refresh_client_traffic_usage(enforce_limits: bool = True):
    usage = get_clients_traffic_usage()
    if not usage:
        return

    now = datetime.datetime.utcnow().isoformat()
    changed_limits = False
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, public_key, traffic_limit_gb, disabled_at FROM clients WHERE deleted_at IS NULL"
        ).fetchall()
        for row in rows:
            total = int(usage.get(row["public_key"], {}).get("total", 0))
            if total <= 0:
                continue
            conn.execute(
                "UPDATE clients SET traffic_used_bytes = MAX(COALESCE(traffic_used_bytes, 0), ?) WHERE id = ?",
                (total, row["id"]),
            )

            limit_gb = float(row["traffic_limit_gb"] or 0)
            if enforce_limits and limit_gb > 0 and not row["disabled_at"]:
                limit_bytes = int(limit_gb * 1024 * 1024 * 1024)
                if total >= limit_bytes:
                    conn.execute("UPDATE clients SET disabled_at = ? WHERE id = ?", (now, row["id"]))
                    changed_limits = True
                    try:
                        from app.audit import log_event
                        log_event(
                            "traffic_limit",
                            f"Клиент {row['name']} отключен: лимит трафика исчерпан.",
                            client_id=row["id"],
                            client_name=row["name"],
                            notify=True,
                        )
                    except Exception:
                        pass
        conn.commit()
    finally:
        conn.close()

    if changed_limits:
        rebuild_and_sync_vpn_config()


def enforce_expired_clients() -> int:
    now = datetime.datetime.utcnow().isoformat()
    conn = get_db_connection()
    disabled = []
    try:
        rows = conn.execute(
            """
            SELECT id, name FROM clients
            WHERE deleted_at IS NULL
              AND disabled_at IS NULL
              AND expires_at < ?
            """,
            (now,),
        ).fetchall()
        for row in rows:
            conn.execute("UPDATE clients SET disabled_at = ? WHERE id = ?", (now, row["id"]))
            disabled.append(dict(row))
        conn.commit()
    finally:
        conn.close()

    for client in disabled:
        try:
            from app.audit import log_event
            log_event(
                "expired",
                f"Клиент {client['name']} автоматически отключен: срок действия истек.",
                client_id=client["id"],
                client_name=client["name"],
                notify=True,
            )
        except Exception:
            pass

    if disabled:
        rebuild_and_sync_vpn_config()
    return len(disabled)

def _format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(max(value, 0))
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} TB"

def format_bytes(value: int) -> str:
    return _format_bytes(value)

def _format_duration(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, _ = divmod(rest, 60)
    parts = []
    if days:
        parts.append(f"{days} дн")
    if hours:
        parts.append(f"{hours} ч")
    if minutes or not parts:
        parts.append(f"{minutes} мин")
    return " ".join(parts[:2])

def _read_proc_stat_cpu() -> tuple[int, int] | None:
    try:
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()[1:]
        values = [int(x) for x in parts]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        return idle, total
    except Exception:
        return None

def _get_cpu_percent() -> float:
    global _last_cpu_sample
    first = _read_proc_stat_cpu()
    if not first:
        return 0.0

    now = time.monotonic()
    if _last_cpu_sample is None:
        _last_cpu_sample = (now, first)
        try:
            load_1 = os.getloadavg()[0]
            return max(0.0, min(100.0, load_1 / max(os.cpu_count() or 1, 1) * 100.0))
        except Exception:
            return 0.0

    prev_time, previous = _last_cpu_sample
    _last_cpu_sample = (now, first)
    if now - prev_time <= 0:
        return 0.0
    idle_delta = first[0] - previous[0]
    total_delta = first[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (1.0 - idle_delta / total_delta)))

def _get_meminfo() -> dict:
    data = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                data[key] = int(value.strip().split()[0]) * 1024
    except Exception:
        pass
    return data

def _count_socket_lines(args: list[str]) -> int:
    try:
        proc = subprocess.run(["ss", *args], capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return 0
        return max(0, len([line for line in proc.stdout.splitlines() if line.strip()]) - 1)
    except Exception:
        return 0

def _get_interface_counter(interface: str, counter: str) -> int:
    try:
        return int(Path(f"/sys/class/net/{interface}/statistics/{counter}").read_text().strip())
    except Exception:
        return 0

def _get_vpn_interface_counters() -> dict:
    return {
        "rx": _get_interface_counter(AWG_INTERFACE, "rx_bytes") + _get_interface_counter(LEGACY_INTERFACE, "rx_bytes"),
        "tx": _get_interface_counter(AWG_INTERFACE, "tx_bytes") + _get_interface_counter(LEGACY_INTERFACE, "tx_bytes"),
    }

def _get_vpn_interface_rates(counters: dict) -> dict:
    global _last_interface_sample
    now = time.monotonic()
    if _last_interface_sample is None:
        _last_interface_sample = (now, counters)
        return {"rx_bps": 0, "tx_bps": 0}

    prev_time, previous = _last_interface_sample
    _last_interface_sample = (now, counters)
    elapsed = max(now - prev_time, 0.001)
    return {
        "rx_bps": max(int((counters["rx"] - previous["rx"]) / elapsed), 0),
        "tx_bps": max(int((counters["tx"] - previous["tx"]) / elapsed), 0),
    }

def _get_peer_transfer_rates(rx_total: int, tx_total: int) -> dict:
    global _last_peer_transfer_sample
    now = time.monotonic()
    current = {"rx": rx_total, "tx": tx_total}
    if _last_peer_transfer_sample is None:
        _last_peer_transfer_sample = (now, current)
        return {"rx_bps": 0, "tx_bps": 0}

    prev_time, previous = _last_peer_transfer_sample
    _last_peer_transfer_sample = (now, current)
    elapsed = max(now - prev_time, 0.001)
    return {
        "rx_bps": max(int((current["rx"] - previous["rx"]) / elapsed), 0),
        "tx_bps": max(int((current["tx"] - previous["tx"]) / elapsed), 0),
    }

def get_dashboard_stats() -> dict:
    cpu_percent = _get_cpu_percent()
    cpu_count = os.cpu_count() or 1
    meminfo = _get_meminfo()

    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get("MemAvailable", 0)
    mem_used = max(mem_total - mem_available, 0)
    mem_percent = (mem_used / mem_total * 100) if mem_total else 0.0

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)
    swap_percent = (swap_used / swap_total * 100) if swap_total else 0.0

    disk = shutil.disk_usage("/")
    disk_percent = disk.used / disk.total * 100 if disk.total else 0.0

    uptime_seconds = 0
    try:
        uptime_seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass

    peers = {}
    total_rx = 0
    total_tx = 0
    for interface in (AWG_INTERFACE, LEGACY_INTERFACE):
        dump = _parse_awg_dump(interface)
        peers.update(dump)
        for peer in dump.values():
            total_rx += peer.get("transfer_rx", 0)
            total_tx += peer.get("transfer_tx", 0)

    statuses = get_client_connection_statuses()
    online_count = sum(1 for item in statuses.values() if item.get("online"))

    top_clients = []
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT name, public_key, traffic_used_bytes FROM clients WHERE deleted_at IS NULL"
        ).fetchall()
        conn.close()
        for row in rows:
            peer = peers.get(row["public_key"], {})
            rx = int(peer.get("transfer_rx", 0))
            tx = int(peer.get("transfer_tx", 0))
            live_total = rx + tx
            saved_total = int(row["traffic_used_bytes"] or 0)
            total = max(live_total, saved_total)
            status = statuses.get(row["public_key"], {})
            top_clients.append({
                "name": row["name"],
                "online": bool(status.get("online")),
                "rx": _format_bytes(rx),
                "tx": _format_bytes(tx),
                "total": _format_bytes(total),
                "total_bytes": total,
            })
        top_clients.sort(key=lambda item: item["total_bytes"], reverse=True)
        top_clients = top_clients[:5]
    except Exception as e:
        logger.warning(f"Не удалось собрать топ клиентов по трафику: {e}")

    interface_counters = _get_vpn_interface_counters()
    interface_rates = _get_vpn_interface_rates(interface_counters)
    peer_rates = _get_peer_transfer_rates(total_rx, total_tx)
    sent_speed = max(interface_rates["tx_bps"], peer_rates["tx_bps"])
    received_speed = max(interface_rates["rx_bps"], peer_rates["rx_bps"])

    try:
        load_1, load_5, load_15 = os.getloadavg()
    except Exception:
        load_1 = load_5 = load_15 = 0.0

    split_routes = get_split_tunnel_routes()
    telegram_routes = [route for route in split_routes if route.startswith(("91.108", "149.154", "95.161"))]
    v2_active = check_awg_interface_status() == "active"
    legacy_active = os.path.exists(f"/sys/class/net/{LEGACY_INTERFACE}")

    return {
        "cpu": {
            "percent": round(cpu_percent, 2),
            "cores": cpu_count,
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
        },
        "memory": {
            "percent": round(mem_percent, 2),
            "used": _format_bytes(mem_used),
            "total": _format_bytes(mem_total),
        },
        "swap": {
            "percent": round(swap_percent, 2),
            "used": _format_bytes(swap_used),
            "total": _format_bytes(swap_total),
        },
        "disk": {
            "percent": round(disk_percent, 2),
            "used": _format_bytes(disk.used),
            "total": _format_bytes(disk.total),
        },
        "uptime": _format_duration(uptime_seconds),
        "traffic": {
            "sent": _format_bytes(total_tx),
            "received": _format_bytes(total_rx),
            "interface_sent": _format_bytes(interface_counters["tx"]),
            "interface_received": _format_bytes(interface_counters["rx"]),
            "interface_sent_speed": f"{_format_bytes(sent_speed)}/s",
            "interface_received_speed": f"{_format_bytes(received_speed)}/s",
        },
        "connections": {
            "tcp": _count_socket_lines(["-tan"]),
            "udp": _count_socket_lines(["-uan"]),
            "vpn_udp": int(v2_active) + int(legacy_active),
            "peers": len(statuses),
            "online": online_count,
        },
        "interfaces": {
            "v2_status": "работает" if v2_active else "выключен",
            "legacy_status": "работает" if legacy_active else "выключен",
            "v2_port": get_vpn_setting("port", str(AWG_PORT)),
            "legacy_port": get_vpn_setting("legacy_port", LEGACY_PORT_DEFAULT),
            "sync": get_sync_statuses(),
        },
        "split": {
            "routes": len(split_routes),
            "telegram_routes": len(telegram_routes),
            "telegram_status": "через VPN" if telegram_routes else "не найден",
        },
        "top_clients": top_clients,
    }

def rebuild_and_sync_vpn_config():
    """
    Собирает актуальный конфигурационный файл сервера awg0.conf,
    включая всех активных пиров, и выполняет syncconf на лету.
    """
    # 1. Загружаем активных клиентов из базы
    conn = get_db_connection()
    clients = conn.execute(
        "SELECT * FROM clients WHERE disabled_at IS NULL AND deleted_at IS NULL"
    ).fetchall()
    conn.close()
    
    server_private_key = get_server_private_key()
    
    # Считываем динамические настройки из БД
    port = int(get_vpn_setting("port", str(AWG_PORT)))
    jc = get_vpn_setting("jc", "4")
    jmin = get_vpn_setting("jmin", "10")
    jmax = get_vpn_setting("jmax", "50")
    s1 = get_vpn_setting("s1", "61")
    s2 = get_vpn_setting("s2", "34")
    s3 = get_vpn_setting("s3", "21")
    s4 = get_vpn_setting("s4", "2")
    h1 = get_vpn_setting("h1", "906396796-1598714541")
    h2 = get_vpn_setting("h2", "2056848576-2126223526")
    h3 = get_vpn_setting("h3", "2141047196-2144456894")
    h4 = get_vpn_setting("h4", "2146243463-2147170402")
    i1 = get_vpn_setting("i1", "")
    i2 = get_vpn_setting("i2", "")
    i3 = get_vpn_setting("i3", "")
    i4 = get_vpn_setting("i4", "")
    i5 = get_vpn_setting("i5", "")
    
    # 2. Формируем секцию Interface
    config_lines = [
        "[Interface]",
        f"Address = {AWG_SERVER_IP}/24",
        f"ListenPort = {port}",
        f"PrivateKey = {server_private_key}",
        "",
        "# Параметры обфускации AmneziaWG (Junk Packet)",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"S3 = {s3}",
        f"S4 = {s4}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        ""
    ]
    for value, key in ((i1, "I1"), (i2, "I2"), (i3, "I3"), (i4, "I4"), (i5, "I5")):
        if value:
            config_lines.insert(-1, f"{key} = {value}")
    
    # Автоопределение основного сетевого интерфейса для iptables
    default_net_interface = "eth0"
    try:
        route_proc = subprocess.run("ip route show default", shell=True, capture_output=True, text=True)
        if route_proc.returncode == 0 and "dev" in route_proc.stdout:
            parts = route_proc.stdout.split()
            dev_idx = parts.index("dev")
            default_net_interface = parts[dev_idx + 1]
    except Exception:
        pass
        
    config_lines.append(
        f"PostUp = iptables -t nat -A POSTROUTING -o {default_net_interface} -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o {default_net_interface} -j MASQUERADE; iptables -A FORWARD -i {AWG_INTERFACE} -j ACCEPT; iptables -A FORWARD -o {AWG_INTERFACE} -j ACCEPT; ip6tables -A FORWARD -i {AWG_INTERFACE} -j ACCEPT; ip6tables -A FORWARD -o {AWG_INTERFACE} -j ACCEPT"
    )
    config_lines.append(
        f"PostDown = iptables -t nat -D POSTROUTING -o {default_net_interface} -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o {default_net_interface} -j MASQUERADE; iptables -D FORWARD -i {AWG_INTERFACE} -j ACCEPT; iptables -D FORWARD -o {AWG_INTERFACE} -j ACCEPT; ip6tables -D FORWARD -i {AWG_INTERFACE} -j ACCEPT; ip6tables -D FORWARD -o {AWG_INTERFACE} -j ACCEPT"
    )
    config_lines.append("")
    
    # 3. Добавляем пиров
    for client in clients:
        clean_name = re.sub(r'[\r\n]', ' ', client['name'] or '')
        config_lines.append(f"# ClientName: {clean_name}")
        config_lines.append(f"# ClientID: {client['id']}")
        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {client['public_key']}")
        if client['preshared_key']:
            config_lines.append(f"PresharedKey = {client['preshared_key']}")
        config_lines.append(f"AllowedIPs = {client['ip_address']}/32")
        config_lines.append("")
        
    new_config_content = "\n".join(config_lines)
    
    # Проверяем, есть ли права на запись в системную папку
    # В локальном режиме запишем в локальную папку данных во избежание сбоев
    is_linux = os.name != "nt"
    target_config_file = AWG_CONFIG_FILE if (is_linux and AWG_CONFIG_DIR.exists()) else (Path(tempfile.gettempdir()) / f"{AWG_INTERFACE}.conf")
    
    # Создаем директорию если ее нет
    target_config_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Записываем конфиг
    try:
        with open(target_config_file, "w") as f:
            f.write(new_config_content)
        # Ограничиваем права
        os.chmod(target_config_file, 0o600)
        logger.info(f"Файл конфигурации сервера успешно обновлен: {target_config_file}")
    except Exception as e:
        logger.error(f"Не удалось записать конфигурационный файл {target_config_file}: {e}")
        record_sync_status(AWG_INTERFACE, False, f"config write failed: {e}")
        
    # Если мы на реальном Linux-сервере с AmneziaWG, синхронизируем интерфейс
    if is_linux:
        try:
            # Получаем очищенный конфиг (без PostUp/PostDown/Address)
            strip_proc = subprocess.run(
                ["awg-quick", "strip", str(target_config_file)],
                capture_output=True, text=True, check=True
            )
            stripped_content = strip_proc.stdout
            
            # Применяем на лету
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as tmp:
                tmp.write(stripped_content)
                tmp_path = tmp.name
                
            try:
                subprocess.run(["awg", "syncconf", AWG_INTERFACE, tmp_path], check=True)
                record_sync_status(AWG_INTERFACE, True, "syncconf applied")
                logger.info(f"Конфигурация AmneziaWG интерфейса {AWG_INTERFACE} успешно синхронизирована live!")
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
        except Exception as e:
            logger.warning(f"Не удалось применить syncconf ({e}). Пробуем мягкий перезапуск через systemctl...")
            try:
                subprocess.run(["systemctl", "restart", f"awg-quick@{AWG_INTERFACE}"], check=True)
                record_sync_status(AWG_INTERFACE, True, "systemctl restart applied")
                logger.info(f"Сервис awg-quick@{AWG_INTERFACE} перезапущен.")
            except Exception as se:
                logger.error(f"Ошибка перезапуска сервиса awg-quick@{AWG_INTERFACE}: {se}")
                if not os.path.exists(f"/sys/class/net/{AWG_INTERFACE}"):
                    try:
                        subprocess.run(["awg-quick", "up", str(target_config_file)], check=True)
                        record_sync_status(AWG_INTERFACE, True, "awg-quick up applied")
                        logger.info(f"Интерфейс {AWG_INTERFACE} поднят через awg-quick up.")
                    except Exception as up_exc:
                        logger.error(f"Не удалось поднять интерфейс {AWG_INTERFACE} через awg-quick up: {up_exc}")
                        record_sync_status(AWG_INTERFACE, False, f"sync failed: {up_exc}")
                else:
                    record_sync_status(AWG_INTERFACE, False, f"sync failed: {se}")

# Оптимизированный список диапазонов IP-адресов зарубежных и заблокированных сервисов
# (Instagram, Facebook, Twitter, Google, YouTube, ChatGPT/OpenAI, Claude, Cloudflare, Fastly и др.)
def rebuild_and_sync_legacy_vpn_config():
    conn = get_db_connection()
    clients = conn.execute("SELECT * FROM clients WHERE disabled_at IS NULL AND deleted_at IS NULL").fetchall()
    conn.close()

    port = int(get_vpn_setting("legacy_port", LEGACY_PORT_DEFAULT))
    jc = get_vpn_setting("legacy_jc", get_vpn_setting("jc", "4"))
    jmin = get_vpn_setting("legacy_jmin", get_vpn_setting("jmin", "10"))
    jmax = get_vpn_setting("legacy_jmax", get_vpn_setting("jmax", "50"))
    s1 = get_vpn_setting("legacy_s1", get_vpn_setting("s1", "61"))
    s2 = get_vpn_setting("legacy_s2", get_vpn_setting("s2", "34"))
    h1 = get_vpn_setting("legacy_h1", get_vpn_setting("h1", "906396796-1598714541"))
    h2 = get_vpn_setting("legacy_h2", get_vpn_setting("h2", "2056848576-2126223526"))
    h3 = get_vpn_setting("legacy_h3", get_vpn_setting("h3", "2141047196-2144456894"))
    h4 = get_vpn_setting("legacy_h4", get_vpn_setting("h4", "2146243463-2147170402"))

    default_net_interface = "eth0"
    try:
        route_proc = subprocess.run("ip route show default", shell=True, capture_output=True, text=True)
        if route_proc.returncode == 0 and "dev" in route_proc.stdout:
            parts = route_proc.stdout.split()
            default_net_interface = parts[parts.index("dev") + 1]
    except Exception:
        pass

    config_lines = [
        "[Interface]",
        f"Address = {LEGACY_SERVER_IP}/24",
        f"ListenPort = {port}",
        f"PrivateKey = {get_legacy_server_private_key()}",
        "",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        "",
        f"PostUp = iptables -t nat -A POSTROUTING -o {default_net_interface} -j MASQUERADE; iptables -A FORWARD -i {LEGACY_INTERFACE} -j ACCEPT; iptables -A FORWARD -o {LEGACY_INTERFACE} -j ACCEPT",
        f"PostDown = iptables -t nat -D POSTROUTING -o {default_net_interface} -j MASQUERADE; iptables -D FORWARD -i {LEGACY_INTERFACE} -j ACCEPT; iptables -D FORWARD -o {LEGACY_INTERFACE} -j ACCEPT",
        "",
    ]

    for client in clients:
        clean_name = re.sub(r'[\r\n]', ' ', client['name'] or '')
        config_lines.extend([
            f"# ClientName: {clean_name}",
            f"# ClientID: {client['id']}",
            "[Peer]",
            f"PublicKey = {client['public_key']}",
        ])
        if client["preshared_key"]:
            config_lines.append(f"PresharedKey = {client['preshared_key']}")
        config_lines.extend([
            f"AllowedIPs = {legacy_ip_from_client_ip(client['ip_address'])}/32",
            "",
        ])

    LEGACY_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LEGACY_CONFIG_FILE.write_text("\n".join(config_lines))
    os.chmod(LEGACY_CONFIG_FILE, 0o600)
    logger.info(f"Legacy config updated: {LEGACY_CONFIG_FILE}")

    if os.name != "nt":
        try:
            if not os.path.exists(f"/sys/class/net/{LEGACY_INTERFACE}"):
                subprocess.run(["systemctl", "enable", f"awg-quick@{LEGACY_INTERFACE}"], check=False)
                subprocess.run(["systemctl", "start", f"awg-quick@{LEGACY_INTERFACE}"], check=True)
                record_sync_status(LEGACY_INTERFACE, True, "legacy systemctl start applied")
            else:
                strip_proc = subprocess.run(["awg-quick", "strip", str(LEGACY_CONFIG_FILE)], capture_output=True, text=True, check=True)
                with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as tmp:
                    tmp.write(strip_proc.stdout)
                    tmp_path = tmp.name
                try:
                    subprocess.run(["awg", "syncconf", LEGACY_INTERFACE, tmp_path], check=True)
                    record_sync_status(LEGACY_INTERFACE, True, "legacy syncconf applied")
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            logger.info(f"Legacy interface {LEGACY_INTERFACE} applied.")
        except Exception as e:
            logger.warning(f"Legacy sync/start failed ({e}); trying restart.")
            try:
                subprocess.run(["systemctl", "restart", f"awg-quick@{LEGACY_INTERFACE}"], check=True)
                record_sync_status(LEGACY_INTERFACE, True, "legacy systemctl restart applied")
            except Exception as se:
                logger.error(f"Legacy restart failed: {se}")
                if not os.path.exists(f"/sys/class/net/{LEGACY_INTERFACE}"):
                    try:
                        subprocess.run(["awg-quick", "up", str(LEGACY_CONFIG_FILE)], check=True)
                        record_sync_status(LEGACY_INTERFACE, True, "legacy awg-quick up applied")
                        logger.info(f"Legacy interface {LEGACY_INTERFACE} started with awg-quick up.")
                    except Exception as up_exc:
                        logger.error(f"Legacy awg-quick up failed: {up_exc}")
                        record_sync_status(LEGACY_INTERFACE, False, f"legacy sync failed: {up_exc}")
                else:
                    record_sync_status(LEGACY_INTERFACE, False, f"legacy sync failed: {se}")

_original_rebuild_and_sync_vpn_config = rebuild_and_sync_vpn_config

def rebuild_and_sync_vpn_config():
    _original_rebuild_and_sync_vpn_config()
    rebuild_and_sync_legacy_vpn_config()

BLOCKED_IPS = [
    # Meta (Instagram, Facebook, Threads, WhatsApp)
    "3.120.0.0/14", "31.13.24.0/21", "31.13.64.0/18", "45.64.40.0/22", "66.220.144.0/20",
    "69.63.176.0/20", "69.171.224.0/19", "74.119.76.0/22", "102.132.96.0/20", "103.4.96.0/22",
    "129.134.0.0/17", "157.240.0.0/16", "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22",
    "204.15.20.0/22",
    
    # Twitter (X)
    "104.244.40.0/21", "192.133.76.0/22", "199.16.156.0/22", "199.59.148.0/22", "199.96.56.0/21",
    "202.160.128.0/22", "209.237.16.0/20",

    # Telegram / MTProto
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.20.0/22", "91.108.56.0/22", "149.154.160.0/20",
    "95.161.64.0/20",
    
    # OpenAI (ChatGPT)
    "23.96.0.0/13", "40.74.0.0/15", "40.76.0.0/14", "40.80.0.0/12", "104.40.0.0/13",
    "104.208.0.0/13",
    
    # Anthropic (Claude AI)
    "160.79.104.0/21",
    
    # Google & YouTube
    "74.125.0.0/16", "172.217.0.0/16", "142.250.0.0/15", "216.58.192.0/19", "108.177.0.0/17",
    "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18", "209.85.128.0/17",
    "8.8.4.4/32", "8.8.8.8/32",
    
    # Крупные зарубежные CDN (Cloudflare, Fastly), обслуживающие 90% зарубежных заблокированных сайтов
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15", "198.41.128.0/17",
    "108.162.192.0/18", "190.93.240.0/20", "141.101.64.0/18", "151.101.0.0/16"
]

DEFAULT_SPLIT_TUNNEL_ROUTES = "\n".join(BLOCKED_IPS)
DOMAIN_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
SPLIT_DNS_CACHE_TTL_SECONDS = 3600

def _split_route_tokens(raw_value: str) -> list[str]:
    tokens = []
    for line in raw_value.replace(",", "\n").replace(";", "\n").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            tokens.append(line)
    return tokens

def _route_from_ip_text(value: str) -> str | None:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        address = ipaddress.ip_address(value)
        return f"{address}/{'32' if address.version == 4 else '128'}"
    except ValueError:
        return None

def _resolve_domain_routes(domain: str) -> list[str]:
    hostname = domain[2:] if domain.startswith("*.") else domain
    if not DOMAIN_RE.match(domain):
        return []
    routes = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            route = _route_from_ip_text(sockaddr[0])
            if route and route not in routes:
                routes.append(route)
    except socket.gaierror as e:
        logger.warning(f"Не удалось разрешить домен split-туннелирования {domain}: {e}")
    return routes

@functools.lru_cache(maxsize=32)
def _build_split_tunnel_routes(raw_value: str, cache_bucket: int) -> tuple[str, ...]:
    routes = []
    for token in _split_route_tokens(raw_value):
        route = _route_from_ip_text(token)
        resolved = [route] if route else _resolve_domain_routes(token)
        for item in resolved:
            if item not in routes:
                routes.append(item)
    return tuple(routes)

def get_split_tunnel_routes() -> list[str]:
    raw_value = get_vpn_setting("split_tunnel_routes", DEFAULT_SPLIT_TUNNEL_ROUTES)
    cache_bucket = int(time.time() // SPLIT_DNS_CACHE_TTL_SECONDS)
    routes = list(_build_split_tunnel_routes(raw_value, cache_bucket))
    return routes or BLOCKED_IPS

def get_split_tunnel_routes_text() -> str:
    return get_vpn_setting("split_tunnel_routes", DEFAULT_SPLIT_TUNNEL_ROUTES)

def set_split_tunnel_routes_text(value: str):
    set_vpn_setting("split_tunnel_routes", value.strip())
    _build_split_tunnel_routes.cache_clear()

def generate_client_config(client_ip: str, client_private_key: str, split_tunnel: bool = False, preshared_key: str = "") -> str:
    """
    Генерирует текстовый файл конфигурации AmneziaWG / Wireguard для импорта клиентом.
    Включает стандартные Junk параметры маскировки AmneziaWG.
    При split_tunnel=True настраивает AllowedIPs только на заблокированные и зарубежные ресурсы.
    """
    server_public_key = get_server_public_key()
    
    # Считываем динамические настройки
    public_ip = get_vpn_setting("public_ip", SERVER_PUBLIC_IP)
    port = int(get_vpn_setting("port", str(AWG_PORT)))
    dns = get_vpn_setting("dns", "1.1.1.1, 1.0.0.1")
    jc = get_vpn_setting("jc", "4")
    jmin = get_vpn_setting("jmin", "10")
    jmax = get_vpn_setting("jmax", "50")
    s1 = get_vpn_setting("s1", "61")
    s2 = get_vpn_setting("s2", "34")
    s3 = get_vpn_setting("s3", "21")
    s4 = get_vpn_setting("s4", "2")
    h1 = get_vpn_setting("h1", "906396796-1598714541")
    h2 = get_vpn_setting("h2", "2056848576-2126223526")
    h3 = get_vpn_setting("h3", "2141047196-2144456894")
    h4 = get_vpn_setting("h4", "2146243463-2147170402")
    i1 = get_vpn_setting("i1", "")
    i2 = get_vpn_setting("i2", "")
    i3 = get_vpn_setting("i3", "")
    i4 = get_vpn_setting("i4", "")
    i5 = get_vpn_setting("i5", "")
    
    if split_tunnel:
        routes = list(get_split_tunnel_routes())
        # Добавляем адреса DNS-серверов в AllowedIPs для предотвращения DNS-утечек через провайдера
        for d in [ip.strip() for ip in dns.split(",") if ip.strip()]:
            try:
                addr = ipaddress.ip_address(d)
                routes.append(f"{addr}/{'32' if addr.version == 4 else '128'}")
            except Exception:
                pass
        allowed_ips_str = ", ".join(sorted(list(set(routes))))
    else:
        allowed_ips_str = "0.0.0.0/0, ::/0"
    
    config_lines = [
        "[Interface]",
        f"Address = {client_ip}/32",
        f"DNS = {dns}",
        f"PrivateKey = {client_private_key}",
        "MTU = 1280",
        "",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"S3 = {s3}",
        f"S4 = {s4}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
    ]

    for key, value in (("I1", i1), ("I2", i2), ("I3", i3), ("I4", i4), ("I5", i5)):
        if value:
            config_lines.append(f"{key} = {value}")

    config_lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"AllowedIPs = {allowed_ips_str}",
        f"Endpoint = {public_ip}:{port}",
        "PersistentKeepalive = 25",
    ])
    if preshared_key:
        config_lines.insert(-3, f"PresharedKey = {preshared_key}")
    return "\n".join(config_lines)

def generate_legacy_client_config(client_ip: str, client_private_key: str, split_tunnel: bool = False, preshared_key: str = "") -> str:
    server_public_key = get_legacy_server_public_key()
    public_ip = get_vpn_setting("public_ip", SERVER_PUBLIC_IP)
    port = int(get_vpn_setting("legacy_port", LEGACY_PORT_DEFAULT))
    dns = get_vpn_setting("dns", "1.1.1.1, 1.0.0.1")
    jc = get_vpn_setting("legacy_jc", get_vpn_setting("jc", "4"))
    jmin = get_vpn_setting("legacy_jmin", get_vpn_setting("jmin", "10"))
    jmax = get_vpn_setting("legacy_jmax", get_vpn_setting("jmax", "50"))
    s1 = get_vpn_setting("legacy_s1", get_vpn_setting("s1", "61"))
    s2 = get_vpn_setting("legacy_s2", get_vpn_setting("s2", "34"))
    h1 = get_vpn_setting("legacy_h1", get_vpn_setting("h1", "906396796-1598714541"))
    h2 = get_vpn_setting("legacy_h2", get_vpn_setting("h2", "2056848576-2126223526"))
    h3 = get_vpn_setting("legacy_h3", get_vpn_setting("h3", "2141047196-2144456894"))
    h4 = get_vpn_setting("legacy_h4", get_vpn_setting("h4", "2146243463-2147170402"))
    if split_tunnel:
        routes = list(get_split_tunnel_routes())
        # Добавляем адреса DNS-серверов в AllowedIPs для предотвращения DNS-утечек через провайдера
        for d in [ip.strip() for ip in dns.split(",") if ip.strip()]:
            try:
                addr = ipaddress.ip_address(d)
                routes.append(f"{addr}/{'32' if addr.version == 4 else '128'}")
            except Exception:
                pass
        allowed_ips_str = ", ".join(sorted(list(set(routes))))
    else:
        allowed_ips_str = "0.0.0.0/0, ::/0"
    legacy_ip = legacy_ip_from_client_ip(client_ip)

    config_lines = [
        "[Interface]",
        f"Address = {legacy_ip}/32",
        f"DNS = {dns}",
        f"PrivateKey = {client_private_key}",
        "MTU = 1280",
        "",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"AllowedIPs = {allowed_ips_str}",
        f"Endpoint = {public_ip}:{port}",
        "PersistentKeepalive = 25",
    ]
    if preshared_key:
        config_lines.insert(-3, f"PresharedKey = {preshared_key}")
    return "\n".join(config_lines)
