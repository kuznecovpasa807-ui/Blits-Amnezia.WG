import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from app.database import init_db
from app.config import DATA_DIR, logger
from app.routes import router as web_router
from app.api import router as api_router
from app.web_gate import WebGateMiddleware

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
