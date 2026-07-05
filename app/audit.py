import datetime
import json
import urllib.parse
import urllib.request

from app.config import logger
from app.database import get_db_connection


def _setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def log_event(
    event_type: str,
    message: str,
    client_id: str | None = None,
    client_name: str | None = None,
    meta: dict | None = None,
    notify: bool = False,
):
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO events (event_type, message, client_id, client_name, meta, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                message,
                client_id,
                client_name,
                json.dumps(meta or {}, ensure_ascii=False),
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    if notify:
        send_admin_notification(message)


def get_events(limit: int = 200) -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, event_type, message, client_id, client_name, meta, created_at
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def send_admin_notification(message: str):
    if _setting("telegram_notifications_enabled", "0") != "1":
        return

    token = _setting("telegram_admin_bot_token", "").strip()
    chat_id = _setting("telegram_admin_chat_id", "").strip()
    if not token or not chat_id:
        return

    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        with urllib.request.urlopen(url, data=data, timeout=5) as response:
            response.read()
    except Exception as exc:
        logger.warning(f"Telegram admin notification failed: {exc}")
