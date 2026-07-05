import sqlite3
import os
import bcrypt
import base64
import secrets
from pathlib import Path
from app.config import DATA_DIR, logger

DB_PATH = DATA_DIR / "panel.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Таблица пользователей
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        must_change_password INTEGER DEFAULT 1
    )
    """)
    
    # 2. Таблица клиентов VPN
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        telegram_id INTEGER,
        ip_address TEXT UNIQUE NOT NULL,
        public_key TEXT UNIQUE NOT NULL,
        private_key TEXT UNIQUE NOT NULL,
        preshared_key TEXT,
        traffic_limit_gb REAL DEFAULT 0,
        traffic_used_bytes INTEGER DEFAULT 0,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        disabled_at TEXT,
        deleted_at TEXT
    )
    """)

    cursor.execute("PRAGMA table_info(clients)")
    client_columns = {row[1] for row in cursor.fetchall()}
    if "preshared_key" not in client_columns:
        cursor.execute("ALTER TABLE clients ADD COLUMN preshared_key TEXT")
    for column_name, definition in {
        "route_type": "TEXT DEFAULT 'local'",
        "remote_client_id": "TEXT",
        "remote_ip_address": "TEXT",
        "config_text_v2": "TEXT",
        "config_text_legacy": "TEXT",
        "config_text_split_v2": "TEXT",
        "config_text_split_legacy": "TEXT",
    }.items():
        if column_name not in client_columns:
            cursor.execute(f"ALTER TABLE clients ADD COLUMN {column_name} {definition}")

    cursor.execute("SELECT id FROM clients WHERE preshared_key IS NULL OR preshared_key = ''")
    for row in cursor.fetchall():
        psk = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
        cursor.execute("UPDATE clients SET preshared_key = ? WHERE id = ?", (psk, row[0]))
    
    # 3. Таблица настроек (на перспективу)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        client_id TEXT,
        client_name TEXT,
        meta TEXT,
        created_at TEXT NOT NULL
    )
    """)
    
    # Проверка наличия пользователя admin
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()
    if not admin:
        logger.info("Пользователь admin не найден. Создаем учетную запись по умолчанию (admin/admin)...")
        # Хешируем стандартный пароль "admin" с помощью native bcrypt
        hashed_password = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
        cursor.execute(
            "INSERT INTO users (username, password_hash, must_change_password) VALUES (?, ?, ?)",
            ("admin", hashed_password, 1)
        )

    conn.commit()
    
    conn.close()
    logger.info("Инициализация базы данных завершена.")

# Запуск инициализации при импорте, чтобы гарантировать наличие БД
if not os.path.exists(DB_PATH):
    init_db()
else:
    # Запускаем проверку схемы, если файл БД уже есть
    init_db()
