import jwt
import datetime
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
import bcrypt
from app.config import SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, TELEGRAM_API_TOKEN, logger
from app.database import get_db_connection

security_bearer = HTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error(f"Ошибка проверки пароля: {e}")
        return False

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return {}

# Зависимость для веб-панели (Cookie JWT)
async def get_current_admin(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        # Для GET запросов делаем редирект, для остальных отдаем 401
        if request.method == "GET":
            raise HTTPException(status_code=303, detail="Redirect to Login")
        raise HTTPException(status_code=401, detail="Не авторизован")
        
    payload = decode_access_token(token)
    username = payload.get("sub")
    if not username:
        if request.method == "GET":
            raise HTTPException(status_code=303, detail="Redirect to Login")
        raise HTTPException(status_code=401, detail="Не авторизован")
        
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if not user:
        if request.method == "GET":
            raise HTTPException(status_code=303, detail="Redirect to Login")
        raise HTTPException(status_code=401, detail="Не авторизован")
        
    return dict(user)

# Зависимость для проверки смены пароля (веб-панель)
async def check_password_change_required(request: Request, user: dict = Depends(get_current_admin)):
    if user.get("must_change_password") == 1:
        # Если админ заходит на страницу смены пароля или logout, пускаем его
        path = request.url.path
        if path not in ["/settings/password", "/logout", "/static/style.css"]:
            raise HTTPException(status_code=303, detail="Redirect to Password Change")
    return user

# Зависимость для API Telegram-бота (Bearer Token)
async def verify_api_token(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Неверный или отсутствующий API токен")

    token = credentials.credentials
    if token == TELEGRAM_API_TOKEN:
        return token

    payload = decode_access_token(token)
    username = payload.get("sub")
    if username:
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user:
            return token

    raise HTTPException(status_code=401, detail="Неверный или отсутствующий API токен")

