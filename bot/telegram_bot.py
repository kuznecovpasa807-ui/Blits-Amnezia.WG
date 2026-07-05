"""
Blits VPN Manager — Telegram-бот для управления клиентами AmneziaWG.

Работает через REST API панели Blits-Amnezia.WG.
"""

import os
import io
import logging
import asyncio
import datetime
from typing import Optional

import httpx
from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup,
    BufferedInputFile
)
from aiogram.filters import CommandStart, Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.enums import ParseMode

# ─── Конфигурация ────────────────────────────────────────────────────────────

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
PANEL_PORT = os.getenv("PANEL_PORT", "8080")
PANEL_URL = os.getenv("PANEL_URL", f"http://127.0.0.1:{PANEL_PORT}")
API_TOKEN = os.getenv("TELEGRAM_API_TOKEN", os.getenv("API_TOKEN", ""))

# Список Telegram ID администраторов (через запятую в env)
ADMIN_IDS_RAW = os.getenv("ADMIN_IDS", "")
ADMIN_IDS: set[int] = set()
if ADMIN_IDS_RAW:
    for uid in ADMIN_IDS_RAW.split(","):
        uid = uid.strip()
        if uid.isdigit():
            ADMIN_IDS.add(int(uid))

# ─── Логирование ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("blits-bot")

# ─── HTTP-клиент для API панели ──────────────────────────────────────────────

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
}

http = httpx.AsyncClient(base_url=PANEL_URL, headers=HEADERS, timeout=30.0)

# ─── FSM-состояния ───────────────────────────────────────────────────────────

class CreateClient(StatesGroup):
    name = State()
    days = State()
    traffic = State()

class ExtendClient(StatesGroup):
    days = State()

class SearchClient(StatesGroup):
    query = State()

# ─── Router ──────────────────────────────────────────────────────────────────

router = Router()

# ─── Хелперы ─────────────────────────────────────────────────────────────────

def is_admin(user_id: int) -> bool:
    """Проверка прав администратора. Если ADMIN_IDS пуст — доступ всем."""
    if not ADMIN_IDS:
        return True
    return user_id in ADMIN_IDS

def human_bytes(b: int) -> str:
    """Человекочитаемый размер трафика."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    else:
        return f"{b / 1024 ** 3:.2f} GB"

def client_status_emoji(client: dict) -> str:
    """Определяет эмодзи статуса клиента."""
    if client.get("disabled_at"):
        return "🔴"
    try:
        exp = datetime.datetime.fromisoformat(client["expires_at"])
        if exp < datetime.datetime.utcnow():
            return "🟡"
    except Exception:
        pass
    return "🟢"

def shorten_id(cid: str) -> str:
    """Укороченный ID для отображения."""
    return cid[:8] if len(cid) > 8 else cid

def format_date(iso: Optional[str]) -> str:
    """Форматирует ISO-дату."""
    if not iso:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(iso)
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return iso

def expires_in(iso: Optional[str]) -> str:
    """Сколько осталось до истечения."""
    if not iso:
        return "—"
    try:
        exp = datetime.datetime.fromisoformat(iso)
        now = datetime.datetime.utcnow()
        delta = exp - now
        if delta.total_seconds() < 0:
            return "⏰ Истёк"
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return f"{days} дн. {hours} ч."
        return f"{hours} ч."
    except Exception:
        return "—"

# ─── Клавиатуры ──────────────────────────────────────────────────────────────

def main_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 Список клиентов", callback_data="clients:list:0")],
        [InlineKeyboardButton(text="➕ Создать клиента", callback_data="clients:create")],
        [InlineKeyboardButton(text="🔍 Поиск клиента", callback_data="clients:search")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="stats")],
    ])

def client_list_kb(clients: list, page: int = 0, per_page: int = 8) -> InlineKeyboardMarkup:
    start = page * per_page
    end = start + per_page
    page_clients = clients[start:end]
    total_pages = max(1, (len(clients) + per_page - 1) // per_page)

    buttons = []
    for c in page_clients:
        emoji = client_status_emoji(c)
        name = c.get("name", "???")[:20]
        cid = c["client_id"]
        buttons.append([InlineKeyboardButton(
            text=f"{emoji} {name}",
            callback_data=f"client:{cid}"
        )])

    # Навигация
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️", callback_data=f"clients:list:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"))
    if end < len(clients):
        nav.append(InlineKeyboardButton(text="➡️", callback_data=f"clients:list:{page + 1}"))
    if nav:
        buttons.append(nav)

    buttons.append([InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def client_detail_kb(client_id: str, is_disabled: bool) -> InlineKeyboardMarkup:
    toggle_text = "🔓 Включить" if is_disabled else "🔒 Отключить"
    toggle_cb = f"client:enable:{client_id}" if is_disabled else f"client:disable:{client_id}"

    return InlineKeyboardMarkup(inline_keyboard=[
        # Amnezia 2.0 (Полный)
        [
            InlineKeyboardButton(text="📱 QR 2.0", callback_data=f"client:qr_gen:v2:{client_id}"),
            InlineKeyboardButton(text="📄 Conf 2.0", callback_data=f"client:conf_send:v2:{client_id}"),
            InlineKeyboardButton(text="🔗 Link 2.0", callback_data=f"client:link_show:v2:{client_id}"),
        ],
        # Amnezia 1.0 (Legacy)
        [
            InlineKeyboardButton(text="📱 QR 1.0", callback_data=f"client:qr_gen:v1:{client_id}"),
            InlineKeyboardButton(text="📄 Conf 1.0", callback_data=f"client:conf_send:v1:{client_id}"),
            InlineKeyboardButton(text="🔗 Link 1.0", callback_data=f"client:link_show:v1:{client_id}"),
        ],
        # Split (Раздельный)
        [
            InlineKeyboardButton(text="📱 QR Split", callback_data=f"client:qr_gen:split:{client_id}"),
            InlineKeyboardButton(text="📄 Conf Split", callback_data=f"client:conf_send:split:{client_id}"),
            InlineKeyboardButton(text="🔗 Link Split", callback_data=f"client:link_show:split:{client_id}"),
        ],
        # Management
        [
            InlineKeyboardButton(text=toggle_text, callback_data=toggle_cb),
            InlineKeyboardButton(text="⏳ Продлить", callback_data=f"client:extend:{client_id}"),
        ],
        [
            InlineKeyboardButton(text="🗑 Удалить клиента", callback_data=f"client:delete_ask:{client_id}"),
        ],
        # Navigation
        [
            InlineKeyboardButton(text="⬅️ Назад к списку", callback_data="clients:list:0"),
            InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu"),
        ],
    ])

def confirm_delete_kb(client_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Да, удалить", callback_data=f"client:delete_yes:{client_id}"),
            InlineKeyboardButton(text="❌ Отмена", callback_data=f"client:{client_id}"),
        ]
    ])

def back_to_client_kb(client_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⬅️ Назад к клиенту", callback_data=f"client:{client_id}")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")],
    ])

def cancel_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu")]
    ])

# ─── Обработчики: Команды ────────────────────────────────────────────────────

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    if not is_admin(message.from_user.id):
        await message.answer("⛔ У вас нет доступа к этому боту.")
        return
    text = (
        "🛡 <b>Blits VPN Manager</b>\n\n"
        "Добро пожаловать в панель управления VPN-клиентами.\n"
        "Выберите действие:"
    )
    await message.answer(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)

@router.message(Command("help"))
async def cmd_help(message: Message):
    if not is_admin(message.from_user.id):
        return
    text = (
        "📖 <b>Справка по командам:</b>\n\n"
        "/start — Главное меню\n"
        "/help — Эта справка\n"
        "/clients — Список клиентов\n"
        "/create — Создать клиента\n"
        "/stats — Статистика\n"
        "/myid — Узнать свой Telegram ID\n"
    )
    await message.answer(text, parse_mode=ParseMode.HTML)

@router.message(Command("myid"))
async def cmd_myid(message: Message):
    await message.answer(f"🆔 Ваш Telegram ID: <code>{message.from_user.id}</code>", parse_mode=ParseMode.HTML)

@router.message(Command("clients"))
async def cmd_clients(message: Message, state: FSMContext):
    await state.clear()
    if not is_admin(message.from_user.id):
        return
    await show_client_list(message, 0)

@router.message(Command("stats"))
async def cmd_stats(message: Message):
    if not is_admin(message.from_user.id):
        return
    await show_stats(message)

@router.message(Command("create"))
async def cmd_create(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    await state.clear()
    await state.set_state(CreateClient.name)
    await message.answer(
        "➕ <b>Создание нового клиента</b>\n\n"
        "Введите имя клиента:",
        parse_mode=ParseMode.HTML,
        reply_markup=cancel_kb()
    )

# ─── Обработчики: Callback-кнопки ────────────────────────────────────────────

@router.callback_query(F.data == "menu")
async def cb_menu(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    text = (
        "🛡 <b>Blits VPN Manager</b>\n\n"
        "Выберите действие:"
    )
    await callback.message.edit_text(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
    await callback.answer()

@router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery):
    await callback.answer()

# ── Список клиентов ──

@router.callback_query(F.data.startswith("clients:list:"))
async def cb_client_list(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    page = int(callback.data.split(":")[-1])
    await show_client_list(callback.message, page, edit=True)
    await callback.answer()

async def show_client_list(target, page: int, edit: bool = False):
    """Показать список клиентов с пагинацией."""
    try:
        resp = await http.get("/api/v1/clients")
        resp.raise_for_status()
        clients = resp.json()
    except Exception as e:
        log.error(f"Ошибка получения списка клиентов: {e}")
        text = "❌ Не удалось получить список клиентов. Панель недоступна."
        if edit:
            await target.edit_text(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        else:
            await target.answer(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return

    if not clients:
        text = "📋 <b>Клиентов пока нет</b>\n\nСоздайте первого клиента!"
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="➕ Создать клиента", callback_data="clients:create")],
            [InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")],
        ])
        if edit:
            await target.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
        else:
            await target.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)
        return

    active = sum(1 for c in clients if not c.get("disabled_at"))
    disabled = len(clients) - active

    text = (
        f"📋 <b>Клиенты</b> ({len(clients)} шт.)\n"
        f"🟢 Активных: {active} | 🔴 Отключённых: {disabled}\n\n"
        f"Выберите клиента:"
    )
    kb = client_list_kb(clients, page)
    if edit:
        await target.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    else:
        await target.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)

# ── Детали клиента ──

@router.callback_query(F.data.regexp(r"^client:[0-9a-f\-]{36}$"))
async def cb_client_detail(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 1)[1]
    await show_client_detail(callback.message, client_id)
    await callback.answer()

async def show_client_detail(message, client_id: str):
    """Показать детали клиента."""
    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            await message.edit_text("❌ Клиент не найден.", reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        else:
            await message.edit_text(f"❌ Ошибка API: {e.response.status_code}", reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return
    except Exception as e:
        await message.edit_text(f"❌ Ошибка: {e}", reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return

    status_emoji = client_status_emoji(c)
    is_disabled = bool(c.get("disabled_at"))
    if is_disabled:
        status_text = "Отключен"
    elif status_emoji == "🟡":
        status_text = "Истёк"
    else:
        status_text = "Активен"

    # Трафик
    used = human_bytes(c.get("traffic_used_bytes", 0))
    limit_gb = c.get("traffic_limit_gb", 0)
    limit_str = f"{limit_gb} GB" if limit_gb and limit_gb > 0 else "безлимит"

    # Прогресс трафика
    if limit_gb and limit_gb > 0:
        used_bytes = c.get("traffic_used_bytes", 0)
        limit_bytes = limit_gb * (1024 ** 3)
        pct = min(100, int(used_bytes / limit_bytes * 100)) if limit_bytes > 0 else 0
        filled = pct // 10
        bar = "■" * filled + "□" * (10 - filled)
        traffic_line = f"<code>{used} / {limit_str}</code> [<code>{bar}</code>] {pct}%"
    else:
        traffic_line = f"<code>{used} / {limit_str}</code>"

    exp_days = expires_in(c.get("expires_at"))

    text = (
        f"{status_emoji} <b>{c.get('name', '???')}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📌 <b>Статус:</b> {status_text}\n"
        f"🌐 <b>IP-адрес:</b> <code>{c.get('ip_address', '—')}</code>\n"
        f"📊 <b>Трафик:</b> {traffic_line}\n"
        f"⏰ <b>Истекает:</b> <code>{format_date(c.get('expires_at'))}</code>\n"
        f"⏳ <b>Осталось:</b> {exp_days}\n"
    )

    if c.get("telegram_id"):
        text += f"👤 <b>Telegram ID:</b> <code>{c['telegram_id']}</code>\n"

    text += (
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚙️ <b>ID:</b> <code>{c['client_id']}</code>"
    )

    kb = client_detail_kb(client_id, is_disabled)
    await message.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)

# ── Создание клиента ──

@router.callback_query(F.data == "clients:create")
async def cb_create_start(callback: CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    await state.clear()
    await state.set_state(CreateClient.name)
    await callback.message.edit_text(
        "➕ <b>Создание нового клиента</b>\n\n"
        "Шаг 1/3 — Введите имя клиента:",
        parse_mode=ParseMode.HTML,
        reply_markup=cancel_kb()
    )
    await callback.answer()

@router.message(CreateClient.name)
async def create_name(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    name = message.text.strip()
    if not name or len(name) > 64:
        await message.answer("⚠️ Имя должно быть от 1 до 64 символов. Попробуйте ещё:")
        return
    await state.update_data(name=name)
    await state.set_state(CreateClient.days)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="7 дней", callback_data="create:days:7"),
            InlineKeyboardButton(text="30 дней", callback_data="create:days:30"),
        ],
        [
            InlineKeyboardButton(text="90 дней", callback_data="create:days:90"),
            InlineKeyboardButton(text="365 дней", callback_data="create:days:365"),
        ],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu")],
    ])
    await message.answer(
        f"✅ Имя: <b>{name}</b>\n\n"
        "Шаг 2/3 — Выберите срок действия или введите число дней:",
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )

@router.callback_query(F.data.startswith("create:days:"))
async def create_days_button(callback: CallbackQuery, state: FSMContext):
    days = int(callback.data.split(":")[-1])
    await state.update_data(days=days)
    await state.set_state(CreateClient.traffic)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="10 GB", callback_data="create:traffic:10"),
            InlineKeyboardButton(text="50 GB", callback_data="create:traffic:50"),
        ],
        [
            InlineKeyboardButton(text="100 GB", callback_data="create:traffic:100"),
            InlineKeyboardButton(text="♾ Без лимита", callback_data="create:traffic:0"),
        ],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu")],
    ])
    await callback.message.edit_text(
        f"✅ Срок: <b>{days} дн.</b>\n\n"
        "Шаг 3/3 — Выберите лимит трафика или введите число (в ГБ):",
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )
    await callback.answer()

@router.message(CreateClient.days)
async def create_days_text(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    try:
        days = int(message.text.strip())
        if days < 1 or days > 3650:
            raise ValueError
    except ValueError:
        await message.answer("⚠️ Введите число от 1 до 3650:")
        return
    await state.update_data(days=days)
    await state.set_state(CreateClient.traffic)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="10 GB", callback_data="create:traffic:10"),
            InlineKeyboardButton(text="50 GB", callback_data="create:traffic:50"),
        ],
        [
            InlineKeyboardButton(text="100 GB", callback_data="create:traffic:100"),
            InlineKeyboardButton(text="♾ Без лимита", callback_data="create:traffic:0"),
        ],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu")],
    ])
    await message.answer(
        f"✅ Срок: <b>{days} дн.</b>\n\n"
        "Шаг 3/3 — Выберите лимит трафика или введите число (в ГБ):",
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )

@router.callback_query(F.data.startswith("create:traffic:"))
async def create_traffic_button(callback: CallbackQuery, state: FSMContext):
    traffic = int(callback.data.split(":")[-1])
    await state.update_data(traffic=traffic)
    await finalize_create(callback.message, state, callback)

@router.message(CreateClient.traffic)
async def create_traffic_text(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    try:
        traffic = int(message.text.strip())
        if traffic < 0 or traffic > 10000:
            raise ValueError
    except ValueError:
        await message.answer("⚠️ Введите число от 0 до 10000 (0 = без лимита):")
        return
    await state.update_data(traffic=traffic)
    await finalize_create(message, state)

async def finalize_create(message, state: FSMContext, callback: CallbackQuery = None):
    """Создаёт клиента через API."""
    data = await state.get_data()
    await state.clear()

    name = data["name"]
    days = data["days"]
    traffic = data.get("traffic", 0)

    wait_text = f"⏳ Создаю клиента <b>{name}</b>..."
    if callback:
        await callback.message.edit_text(wait_text, parse_mode=ParseMode.HTML)
        target = callback.message
    else:
        sent = await message.answer(wait_text, parse_mode=ParseMode.HTML)
        target = sent

    try:
        payload = {
            "name": name,
            "days": days,
            "traffic_limit_gb": traffic,
            "telegram_id": None
        }
        resp = await http.post("/api/v1/clients", json=payload)
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        log.error(f"Ошибка создания клиента: {e}")
        await target.edit_text(
            f"❌ Не удалось создать клиента:\n<code>{e}</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=main_menu_kb()
        )
        return

    if callback:
        await callback.answer("✅ Клиент создан!")

    client_id = c["client_id"]
    is_disabled = bool(c.get("disabled_at"))
    status_emoji = client_status_emoji(c)
    if is_disabled:
        status_text = "Отключен"
    elif status_emoji == "🟡":
        status_text = "Истёк"
    else:
        status_text = "Активен"

    # Трафик
    used = human_bytes(c.get("traffic_used_bytes", 0))
    limit_gb = c.get("traffic_limit_gb", 0)
    limit_str = f"{limit_gb} GB" if limit_gb and limit_gb > 0 else "безлимит"

    # Прогресс трафика
    if limit_gb and limit_gb > 0:
        used_bytes = c.get("traffic_used_bytes", 0)
        limit_bytes = limit_gb * (1024 ** 3)
        pct = min(100, int(used_bytes / limit_bytes * 100)) if limit_bytes > 0 else 0
        filled = pct // 10
        bar = "■" * filled + "□" * (10 - filled)
        traffic_line = f"<code>{used} / {limit_str}</code> [<code>{bar}</code>] {pct}%"
    else:
        traffic_line = f"<code>{used} / {limit_str}</code>"

    exp_days = expires_in(c.get("expires_at"))

    text = (
        f"✅ <b>Клиент создан!</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>Имя:</b> <b>{c.get('name', '???')}</b>\n"
        f"📌 <b>Статус:</b> {status_text}\n"
        f"🌐 <b>IP-адрес:</b> <code>{c.get('ip_address', '—')}</code>\n"
        f"📊 <b>Трафик:</b> {traffic_line}\n"
        f"⏰ <b>Истекает:</b> <code>{format_date(c.get('expires_at'))}</code>\n"
        f"⏳ <b>Осталось:</b> {exp_days}\n"
    )

    if c.get("telegram_id"):
        text += f"👤 <b>Telegram ID:</b> <code>{c['telegram_id']}</code>\n"

    text += (
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚙️ <b>ID:</b> <code>{client_id}</code>"
    )

    kb = client_detail_kb(client_id, is_disabled)
    await target.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)

# ── QR-код ──

@router.callback_query(F.data.startswith("client:qr:"))
async def cb_qr(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]
    await callback.answer("⏳ Генерирую QR-код...")

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
        return

    config_text = c.get("config_text", "")
    if not config_text:
        await callback.message.answer("❌ Конфиг пуст.")
        return

    # Генерируем QR-код локально через библиотеку
    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(config_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        photo = BufferedInputFile(buf.read(), filename=f"vpn_qr_{shorten_id(client_id)}.png")
        await callback.message.answer_photo(
            photo,
            caption=(
                f"📱 <b>QR-код: {c.get('name', '???')}</b>\n\n"
                "Отсканируйте в AmneziaVPN для подключения."
            ),
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )
    except ImportError:
        # Если qrcode не установлен, отправляем конфиг текстом
        await callback.message.answer(
            f"📱 <b>Конфиг для {c.get('name', '???')}:</b>\n\n"
            f"<code>{config_text[:4000]}</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )

# ── Deep Link ──

@router.callback_query(F.data.startswith("client:link:"))
async def cb_deeplink(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return

    deep_link = c.get("deep_link_v2") or c.get("deep_link") or ""
    deep_link_split = c.get("deep_link_split_v2") or c.get("deep_link_split") or ""

    text = f"🔗 <b>Deep Links: {c.get('name', '???')}</b>\n\n"

    if deep_link:
        # Укорачиваем ссылку для отображения (может быть очень длинной)
        display = deep_link[:100] + "..." if len(deep_link) > 100 else deep_link
        text += f"🌍 <b>Полный туннель:</b>\n<code>{deep_link}</code>\n\n"

    if deep_link_split:
        text += f"🔀 <b>Раздельный туннель:</b>\n<code>{deep_link_split}</code>\n\n"

    text += "☝️ Нажмите на ссылку для копирования, затем откройте её в AmneziaVPN."

    # Telegram ограничивает длину сообщения
    if len(text) > 4096:
        # Отправляем как файл
        buf = io.BytesIO()
        buf.write(f"Full tunnel:\n{deep_link}\n\nSplit tunnel:\n{deep_link_split}".encode())
        buf.seek(0)
        doc = BufferedInputFile(buf.read(), filename=f"deeplinks_{shorten_id(client_id)}.txt")
        await callback.message.answer_document(
            doc,
            caption=f"🔗 Deep Links для <b>{c.get('name', '???')}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )
    else:
        await callback.message.answer(
            text,
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id),
            disable_web_page_preview=True
        )
    await callback.answer()

# ── Конфиг (.conf) ──

@router.callback_query(F.data.startswith("client:conf:"))
async def cb_conf(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return

    config_text = c.get("config_text", "")
    if not config_text:
        await callback.answer("❌ Конфиг пуст", show_alert=True)
        return

    buf = io.BytesIO(config_text.encode("utf-8"))
    doc = BufferedInputFile(buf.read(), filename=f"{c.get('name', 'client')}.conf")
    await callback.message.answer_document(
        doc,
        caption=f"📄 Конфиг-файл для <b>{c.get('name', '???')}</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=back_to_client_kb(client_id)
    )
    await callback.answer()


@router.callback_query(F.data.startswith("client:qr_gen:"))
async def cb_qr_gen(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    parts = callback.data.split(":", 3)
    qr_type = parts[2]
    client_id = parts[3]
    await callback.answer("⏳ Генерирую QR-код...")

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка: {e}")
        return

    if qr_type == "v1":
        config_text = c.get("config_text_legacy") or ""
        type_label = "Amnezia 1.0 (Legacy)"
    elif qr_type == "split":
        config_text = c.get("config_text_split") or ""
        type_label = "Split Amnezia 2.0"
    else:
        config_text = c.get("config_text") or ""
        type_label = "Amnezia 2.0"

    if not config_text:
        await callback.message.answer(f"❌ Конфиг {type_label} пуст.")
        return

    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(config_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        photo = BufferedInputFile(buf.read(), filename=f"vpn_qr_{qr_type}_{shorten_id(client_id)}.png")
        await callback.message.answer_photo(
            photo,
            caption=(
                f"📱 <b>QR-код ({type_label}): {c.get('name', '???')}</b>\n\n"
                "Отсканируйте в AmneziaVPN для подключения."
            ),
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )
    except Exception as e:
        await callback.message.answer(
            f"📱 <b>Конфиг ({type_label}) для {c.get('name', '???')}:</b>\n\n"
            f"<code>{config_text[:4000]}</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )


@router.callback_query(F.data.startswith("client:link_show:"))
async def cb_link_show(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    parts = callback.data.split(":", 3)
    link_type = parts[2]
    client_id = parts[3]

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return

    if link_type == "v1":
        link = c.get("deep_link") or ""
        type_label = "Amnezia 1.0 (Legacy)"
    elif link_type == "split":
        link = c.get("deep_link_split_v2") or c.get("deep_link_split") or ""
        type_label = "Split Amnezia 2.0"
    else:
        link = c.get("deep_link_v2") or ""
        type_label = "Amnezia 2.0"

    if not link:
        await callback.answer(f"Ссылка {type_label} отсутствует", show_alert=True)
        return

    text = f"🔗 <b>Deep Link ({type_label}): {c.get('name', '???')}</b>\n\n"
    text += f"<code>{link}</code>\n\n"
    text += "☝️ Нажмите на ссылку для копирования, затем откройте её в AmneziaVPN."

    if len(text) > 4096:
        buf = io.BytesIO()
        buf.write(link.encode())
        buf.seek(0)
        doc = BufferedInputFile(buf.read(), filename=f"deeplink_{link_type}_{shorten_id(client_id)}.txt")
        await callback.message.answer_document(
            doc,
            caption=f"🔗 Deep Link ({type_label}) для <b>{c.get('name', '???')}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id)
        )
    else:
        await callback.message.answer(
            text,
            parse_mode=ParseMode.HTML,
            reply_markup=back_to_client_kb(client_id),
            disable_web_page_preview=True
        )
    await callback.answer()


@router.callback_query(F.data.startswith("client:conf_send:"))
async def cb_conf_send(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    parts = callback.data.split(":", 3)
    conf_type = parts[2]
    client_id = parts[3]
    await callback.answer("⏳ Готовлю файл конфигурации...")

    try:
        resp = await http.get(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
        c = resp.json()
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return

    if conf_type == "v1":
        config_text = c.get("config_text_legacy") or ""
        filename_suffix = "_legacy"
        type_label = "Amnezia 1.0 (Legacy)"
    elif conf_type == "split":
        config_text = c.get("config_text_split") or ""
        filename_suffix = "_split"
        type_label = "Split Amnezia 2.0"
    else:
        config_text = c.get("config_text") or ""
        filename_suffix = "_v2"
        type_label = "Amnezia 2.0"

    if not config_text:
        await callback.answer(f"Конфиг {type_label} отсутствует", show_alert=True)
        return

    buf = io.BytesIO(config_text.encode("utf-8"))
    doc = BufferedInputFile(buf.read(), filename=f"{c.get('name', 'client')}{filename_suffix}.conf")
    await callback.message.answer_document(
        doc,
        caption=f"📄 Конфиг-файл ({type_label}) для <b>{c.get('name', '???')}</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=back_to_client_kb(client_id)
    )
    await callback.answer()

# ── Продление ──

@router.callback_query(F.data.startswith("client:extend:"))
async def cb_extend(callback: CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]
    await state.clear()
    await state.update_data(extend_client_id=client_id)
    await state.set_state(ExtendClient.days)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="7 дней", callback_data=f"extend:days:7"),
            InlineKeyboardButton(text="30 дней", callback_data=f"extend:days:30"),
        ],
        [
            InlineKeyboardButton(text="90 дней", callback_data=f"extend:days:90"),
            InlineKeyboardButton(text="365 дней", callback_data=f"extend:days:365"),
        ],
        [InlineKeyboardButton(text="❌ Отмена", callback_data=f"client:{client_id}")],
    ])
    await callback.message.edit_text(
        "⏳ <b>Продление подписки</b>\n\n"
        "Выберите срок продления или введите число дней:",
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )
    await callback.answer()

@router.callback_query(F.data.startswith("extend:days:"))
async def extend_days_button(callback: CallbackQuery, state: FSMContext):
    days = int(callback.data.split(":")[-1])
    data = await state.get_data()
    client_id = data.get("extend_client_id")
    await state.clear()

    if not client_id:
        await callback.answer("⚠️ Ошибка: клиент не выбран", show_alert=True)
        return

    await callback.message.edit_text("⏳ Продлеваю...", parse_mode=ParseMode.HTML)

    try:
        resp = await http.post(f"/api/v1/clients/{client_id}/extend", json={"days": days})
        resp.raise_for_status()
        result = resp.json()
    except Exception as e:
        await callback.message.edit_text(
            f"❌ Ошибка: {e}",
            reply_markup=back_to_client_kb(client_id),
            parse_mode=ParseMode.HTML
        )
        await callback.answer()
        return

    new_exp = format_date(result.get("expires_at"))
    await callback.message.edit_text(
        f"✅ <b>Подписка продлена на {days} дн.</b>\n\n"
        f"⏰ Новая дата истечения: {new_exp}",
        parse_mode=ParseMode.HTML,
        reply_markup=back_to_client_kb(client_id)
    )
    await callback.answer("✅ Продлено!")

@router.message(ExtendClient.days)
async def extend_days_text(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    try:
        days = int(message.text.strip())
        if days < 1 or days > 3650:
            raise ValueError
    except ValueError:
        await message.answer("⚠️ Введите число от 1 до 3650:")
        return

    data = await state.get_data()
    client_id = data.get("extend_client_id")
    await state.clear()

    if not client_id:
        await message.answer("⚠️ Ошибка: клиент не выбран")
        return

    try:
        resp = await http.post(f"/api/v1/clients/{client_id}/extend", json={"days": days})
        resp.raise_for_status()
        result = resp.json()
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}", reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return

    new_exp = format_date(result.get("expires_at"))
    await message.answer(
        f"✅ <b>Подписка продлена на {days} дн.</b>\n\n"
        f"⏰ Новая дата истечения: {new_exp}",
        parse_mode=ParseMode.HTML,
        reply_markup=back_to_client_kb(client_id)
    )

# ── Отключение / Включение ──

@router.callback_query(F.data.startswith("client:disable:"))
async def cb_disable(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    try:
        resp = await http.post(f"/api/v1/clients/{client_id}/disable")
        resp.raise_for_status()
    except Exception as e:
        await callback.answer(f"❌ Ошибка: {e}", show_alert=True)
        return

    await callback.answer("🔒 Клиент отключён!")
    await show_client_detail(callback.message, client_id)

@router.callback_query(F.data.startswith("client:enable:"))
async def cb_enable(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    try:
        resp = await http.post(f"/api/v1/clients/{client_id}/enable")
        resp.raise_for_status()
    except Exception as e:
        await callback.answer(f"❌ Ошибка: {e}", show_alert=True)
        return

    await callback.answer("🔓 Клиент включён!")
    await show_client_detail(callback.message, client_id)

# ── Удаление ──

@router.callback_query(F.data.startswith("client:delete_ask:"))
async def cb_delete_ask(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    await callback.message.edit_text(
        "⚠️ <b>Подтверждение удаления</b>\n\n"
        f"Вы уверены, что хотите удалить клиента?\n"
        f"🆔 <code>{client_id}</code>\n\n"
        "❗ Это действие нельзя отменить!",
        parse_mode=ParseMode.HTML,
        reply_markup=confirm_delete_kb(client_id)
    )
    await callback.answer()

@router.callback_query(F.data.startswith("client:delete_yes:"))
async def cb_delete_confirm(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    client_id = callback.data.split(":", 2)[2]

    try:
        resp = await http.delete(f"/api/v1/clients/{client_id}")
        resp.raise_for_status()
    except Exception as e:
        await callback.answer(f"❌ Ошибка: {e}", show_alert=True)
        return

    await callback.answer("🗑 Клиент удалён!")
    await callback.message.edit_text(
        "🗑 <b>Клиент удалён</b>\n\n"
        f"ID: <code>{client_id}</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📋 К списку", callback_data="clients:list:0")],
            [InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")],
        ])
    )

# ── Поиск ──

@router.callback_query(F.data == "clients:search")
async def cb_search(callback: CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    await state.clear()
    await state.set_state(SearchClient.query)
    await callback.message.edit_text(
        "🔍 <b>Поиск клиента</b>\n\n"
        "Введите имя, IP-адрес или часть ID клиента:",
        parse_mode=ParseMode.HTML,
        reply_markup=cancel_kb()
    )
    await callback.answer()

@router.message(SearchClient.query)
async def search_handler(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    query = message.text.strip().lower()
    await state.clear()

    try:
        resp = await http.get("/api/v1/clients")
        resp.raise_for_status()
        all_clients = resp.json()
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}", reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return

    results = [
        c for c in all_clients
        if query in c.get("name", "").lower()
        or query in c.get("ip_address", "").lower()
        or query in c.get("client_id", "").lower()
        or query in str(c.get("telegram_id") or "").lower()
    ]

    if not results:
        await message.answer(
            f"🔍 По запросу «<b>{query}</b>» ничего не найдено.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔍 Искать ещё", callback_data="clients:search")],
                [InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")],
            ])
        )
        return

    text = f"🔍 Найдено: <b>{len(results)}</b> клиент(ов)\n\nВыберите:"
    kb = client_list_kb(results, 0)
    await message.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)

# ── Статистика ──

@router.callback_query(F.data == "stats")
async def cb_stats(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    await show_stats(callback.message, edit=True)
    await callback.answer()

async def show_stats(target, edit: bool = False):
    """Показать общую статистику."""
    try:
        resp = await http.get("/api/v1/clients")
        resp.raise_for_status()
        clients = resp.json()
    except Exception as e:
        text = f"❌ Не удалось получить статистику: {e}"
        if edit:
            await target.edit_text(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        else:
            await target.answer(text, reply_markup=main_menu_kb(), parse_mode=ParseMode.HTML)
        return

    total = len(clients)
    now = datetime.datetime.utcnow()

    active = 0
    disabled = 0
    expired = 0
    total_traffic = 0

    for c in clients:
        total_traffic += c.get("traffic_used_bytes", 0)
        if c.get("disabled_at"):
            disabled += 1
        else:
            try:
                exp = datetime.datetime.fromisoformat(c["expires_at"])
                if exp < now:
                    expired += 1
                else:
                    active += 1
            except Exception:
                active += 1

    text = (
        "📊 <b>Статистика панели</b>\n"
        f"{'─' * 28}\n"
        f"👥 Всего клиентов: <b>{total}</b>\n"
        f"🟢 Активных: <b>{active}</b>\n"
        f"🟡 Истёкших: <b>{expired}</b>\n"
        f"🔴 Отключённых: <b>{disabled}</b>\n"
        f"📊 Общий трафик: <b>{human_bytes(total_traffic)}</b>\n"
    )

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 Список клиентов", callback_data="clients:list:0")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="menu")],
    ])

    if edit:
        await target.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    else:
        await target.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)

# ─── Точка входа ─────────────────────────────────────────────────────────────

async def main():
    log.info("🚀 Запуск Blits VPN Manager Bot...")
    log.info(f"📡 Panel URL: {PANEL_URL}")
    log.info(f"🔑 Admin IDs: {ADMIN_IDS or 'ALL (no restriction)'}")

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    # Удаляем вебхук и запускаем polling
    await bot.delete_webhook(drop_pending_updates=True)
    log.info("✅ Бот запущен. Ожидание сообщений...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
