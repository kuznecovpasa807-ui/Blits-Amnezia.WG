import os
import re
import html
import datetime
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from app.database import init_db, get_db_connection
from app.config import DATA_DIR, logger
from app.routes import router as web_router, check_password_change_required
from app.api import router as api_router
from app.audit import log_event
from app.vpn_manager import rebuild_and_sync_vpn_config
from app.web_gate import WebGateMiddleware


def _format_datetime_local(value: str) -> str:
    try:
        return datetime.datetime.fromisoformat(value).strftime("%Y-%m-%dT%H:%M")
    except Exception:
        return ""


def _parse_datetime_local(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("expiration date is required")
    return datetime.datetime.fromisoformat(value).isoformat()


def _clean_client_name(value: str) -> str:
    value = re.sub(r"[\r\n]", " ", value or "").strip()
    value = re.sub(r"[\\'\"`;|&<>$]", "", value)
    return value or "client"


@web_router.get("/clients/{client_id}/edit", response_class=HTMLResponse)
async def edit_client_page(
    request: Request,
    client_id: str,
    user: dict = Depends(check_password_change_required),
):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Клиент не найден")

    client = dict(row)
    name = html.escape(client.get("name") or "")
    expires_at = html.escape(_format_datetime_local(client.get("expires_at") or ""))
    traffic_limit_gb = html.escape(str(client.get("traffic_limit_gb") or 0))
    route_type = html.escape(client.get("route_type") or "local")
    disabled_note = "<p class='hint warning'>Клиент сейчас отключен. Редактирование не включает его автоматически.</p>" if client.get("disabled_at") else ""
    cascade_note = "<p class='hint warning'>Это каскадный клиент. Изменения сохраняются в локальной панели; удаленная панель может требовать отдельной синхронизации.</p>" if route_type == "cascade" else ""

    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Редактировать клиента | Blitz Panel</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>
        body {{ padding: 32px; background: var(--body-bg, #f8fafc); color: var(--text-main, #111827); }}
        .edit-card {{ max-width: 720px; margin: 0 auto; background: var(--card-bg, #fff); border: 1px solid var(--border-color, #e5e7eb); border-radius: 16px; padding: 28px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
        .form-row {{ margin-bottom: 18px; }}
        label {{ display: block; margin-bottom: 8px; font-weight: 700; }}
        input {{ width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1px solid var(--border-color, #d1d5db); border-radius: 10px; font-size: 15px; }}
        .actions {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 22px; }}
        .hint {{ color: var(--text-muted, #64748b); font-size: 14px; line-height: 1.45; }}
        .hint.warning {{ color: #b45309; background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 10px 12px; }}
        .meta {{ margin-bottom: 22px; }}
    </style>
</head>
<body data-theme="{html.escape(request.cookies.get('panel_theme', 'light'))}">
    <div class="edit-card">
        <h1>Редактировать клиента</h1>
        <div class="meta hint">
            ID: <code>{html.escape(client_id)}</code><br>
            Тип: <code>{route_type}</code><br>
            IP: <code>{html.escape(client.get('remote_ip_address') or client.get('ip_address') or '')}</code>
        </div>
        {disabled_note}
        {cascade_note}
        <form action="/clients/{html.escape(client_id)}/edit" method="post">
            <div class="form-row">
                <label for="name">Имя клиента</label>
                <input id="name" name="name" type="text" value="{name}" required>
            </div>
            <div class="form-row">
                <label for="expires_at">Действует до</label>
                <input id="expires_at" name="expires_at" type="datetime-local" value="{expires_at}" required>
            </div>
            <div class="form-row">
                <label for="traffic_limit_gb">Лимит трафика, ГБ</label>
                <input id="traffic_limit_gb" name="traffic_limit_gb" type="number" min="0" step="0.1" value="{traffic_limit_gb}" required>
                <p class="hint">0 = безлимит. Ключи и IP клиента сохраняются.</p>
            </div>
            <div class="actions">
                <button class="btn btn-primary" type="submit">Сохранить</button>
                <a class="btn btn-secondary" href="/clients/{html.escape(client_id)}">Назад к клиенту</a>
                <a class="btn btn-secondary" href="/clients">К списку клиентов</a>
            </div>
        </form>
    </div>
</body>
</html>
""")


@web_router.post("/clients/{client_id}/edit")
async def edit_client_action(
    client_id: str,
    name: str = Form(...),
    expires_at: str = Form(...),
    traffic_limit_gb: float = Form(0.0),
    user: dict = Depends(check_password_change_required),
):
    clean_name = _clean_client_name(name)
    if traffic_limit_gb < 0:
        traffic_limit_gb = 0.0
    if traffic_limit_gb > 1_000_000:
        traffic_limit_gb = 1_000_000.0

    try:
        normalized_expires_at = _parse_datetime_local(expires_at)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некорректная дата окончания")

    conn = get_db_connection()
    try:
        client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
        if not client:
            raise HTTPException(status_code=404, detail="Клиент не найден")
        conn.execute(
            "UPDATE clients SET name = ?, expires_at = ?, traffic_limit_gb = ? WHERE id = ?",
            (clean_name, normalized_expires_at, traffic_limit_gb, client_id),
        )
        conn.commit()
        route_type = client["route_type"] if "route_type" in client.keys() else "local"
    finally:
        conn.close()

    if route_type != "cascade":
        rebuild_and_sync_vpn_config()

    log_event(
        "client_edited",
        f"Клиент {clean_name} отредактирован.",
        client_id,
        clean_name,
        notify=True,
    )
    return RedirectResponse(url=f"/clients/{client_id}", status_code=303)


app = FastAPI(
    title="AmneziaWG Admin Panel MVP",
    description="Веб-панель для управления AmneziaWG пирам и интеграции с Telegram-ботом",
    version="1.0.0"
)
app.add_middleware(WebGateMiddleware)

# Создание необходимых папок при запуске
@app.on_event("startup")
async def startup_event():
    logger.info("Запуск AmneziaWG веб-панели...")
    init_db()

# Обработчик перенаправлений для авторизации в вебе
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 303:
        root_path = request.scope.get("root_path", "").rstrip("/")
        if exc.detail == "Redirect to Login":
            return RedirectResponse(url=f"{root_path}/login", status_code=303)
        if exc.detail == "Redirect to Password Change":
            return RedirectResponse(url=f"{root_path}/settings/password", status_code=303)
            
    # Для API отдаем стандартный JSON, для UI можно было бы отдавать страницу ошибки
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
        
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

# Подключение статических файлов (CSS/JS)
static_path = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_path):
    os.makedirs(static_path, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

# Подключение роутеров
app.include_router(api_router)
app.include_router(web_router)
