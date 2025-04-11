from fastapi import FastAPI, Depends, HTTPException, status,  Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import jwt
from jwt import PyJWTError
import secrets
import base64
import os


# Функция для генерации случайного ключа
def generate_secret_key(length: int = 32) -> str:
    return base64.b64encode(secrets.token_bytes(length)).decode()


# Функция для генерации refresh token
def generate_refresh_token() -> str:
    return secrets.token_urlsafe(32)


# Конфигурация OAuth2 сервера
class OAuth2Config:
    CLIENT_ID = "c47df55b-4524-494b-9652-ce1492249e8b"
    CLIENT_SECRET = "60b2ba8c-9533-45d8-b323-334f46bd7b2a"
    TOKEN_URL = "/oauth/token"
    REFRESH_TOKEN_URL = "/oauth/refresh"
    SCOPES = ["webhook.read", "webhook.write"]


# Генерируем начальный SECRET_KEY
SECRET_KEY = generate_secret_key()
ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
try:
    # Пытаемся прочитать переменную окружения и преобразовать в целое число
    ACCESS_TOKEN_EXPIRE_MINUTES_STR = os.environ.get(
        "ACCESS_TOKEN_EXPIRE_MINUTES", # Имя переменной окружения
        str(DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES) # Значение по умолчанию (строкой)
    )
    ACCESS_TOKEN_EXPIRE_MINUTES = int(ACCESS_TOKEN_EXPIRE_MINUTES_STR)
    # Простая проверка корректности значения
    if ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
        print(f"Warning: Invalid ACCESS_TOKEN_EXPIRE_MINUTES value ({ACCESS_TOKEN_EXPIRE_MINUTES}). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")
        ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
except ValueError:
    # Если не удалось преобразовать в число, используем значение по умолчанию
    print(f"Warning: Could not parse ACCESS_TOKEN_EXPIRE_MINUTES environment variable ('{ACCESS_TOKEN_EXPIRE_MINUTES_STR}'). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")
    ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES

print(f"INFO: Using access token lifetime: {ACCESS_TOKEN_EXPIRE_MINUTES} minutes")

# Хранилище для активных refresh tokens
# В продакшене следует использовать базу данных
active_tokens = {}
active_refresh_tokens = set()

app = FastAPI()


class WebhookDataFlexible(BaseModel):
    event_name: str
    eventData: Dict[str, Any]
    model_config = {
        "extra": "allow"
    }


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    expires_in: int
    scope: str


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    scope: Optional[str] = None
    refresh_token: Optional[str] = None


class OAuth2Info(BaseModel):
    clientId: str
    clientSecret: str
    tokenUrl: str
    refreshTokenUrl: str
    scopes: List[str]


# Настройка OAuth2
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=OAuth2Config.TOKEN_URL,
    scopes={
        "webhook.read": "Read webhook data",
        "webhook.write": "Send webhook data"
    }
)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    # Генерируем новый SECRET_KEY для токена
    current_secret = generate_secret_key()

    # Добавляем идентификатор токена
    token_id = secrets.token_urlsafe(8)
    to_encode["jti"] = token_id

    # Сохраняем secret key для этого токена
    encoded_jwt = jwt.encode(to_encode, current_secret, algorithm=ALGORITHM)
    active_tokens[encoded_jwt] = current_secret

    return encoded_jwt


async def validate_token(token: str = Depends(oauth2_scheme)):
    try:
        # Получаем secret key для данного токена
        if token not in active_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token not found or expired",
            )

        # secret = active_tokens[token]
        # payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        #
        # if payload.get("scope") not in OAuth2Config.SCOPES:
        #     raise HTTPException(
        #         status_code=status.HTTP_401_UNAUTHORIZED,
        #         detail="Invalid scope",
        #     )
        # return payload
        secret = active_tokens[token]
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])

        token_scope_str = payload.get("scope")  # Получаем строку скоупов из токена

        if not token_scope_str:  # Если скоупа нет вообще
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing scope in token",
            )

        # Разделяем строку скоупов по пробелам и убираем пустые элементы
        token_scopes = set(token_scope_str.split())

        # Проверяем, есть ли *хотя бы одно* пересечение между скоупами токена
        # и разрешенными скоупами сервера.
        # Или, если нужно чтобы все скоупы токена были разрешены:
        # if not token_scopes.issubset(set(OAuth2Config.SCOPES)):

        # Чаще достаточно проверить, что есть *хотя бы один* нужный скоуп.
        # Например, если эндпоинту нужен 'webhook.read':
        required_scope_for_endpoint = "webhook.write"  # Или "webhook.write" смотря что нужно
        if required_scope_for_endpoint not in token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                # 403 Forbidden более корректен, если скоуп валидный, но недостаточный
                detail=f"Token does not have the required scope: {required_scope_for_endpoint}",
            )

        # --- Старая проверка (менее гибкая) ---
        # if token_scope_str not in OAuth2Config.SCOPES:
        #     raise HTTPException(
        #         status_code=status.HTTP_401_UNAUTHORIZED,
        #         detail="Invalid scope",
        #     )
        # ------------------------------------

        return payload  # Возвращаем весь payload, если проверка пройдена
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


@app.get("/oauth2-config")
async def get_oauth2_config():
    return OAuth2Info(
        clientId=OAuth2Config.CLIENT_ID,
        clientSecret=OAuth2Config.CLIENT_SECRET,
        tokenUrl=OAuth2Config.TOKEN_URL,
        refreshTokenUrl=OAuth2Config.REFRESH_TOKEN_URL,
        scopes=OAuth2Config.SCOPES
    )


@app.post(OAuth2Config.TOKEN_URL, response_model=Token)
async def create_token(
    # --- ИЗМЕНЕНО: Принимаем параметры формы вместо JSON ---
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None) # scope опционален
    # refresh_token не нужен для client_credentials
    # ----------------------------------------------------
):
    # Теперь обращаемся к параметрам напрямую по имени
    if grant_type not in ["client_credentials"]: # Эта точка входа только для client_credentials
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant type for this endpoint: {grant_type}"
        )

    # Используем client_id, client_secret напрямую
    if client_id != OAuth2Config.CLIENT_ID or client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Используем scope напрямую, ставим дефолтный если не пришел
    effective_scope = scope or "webhook.read"
    access_token = create_access_token(
        data={
            "sub": client_id, # Используем client_id напрямую
            "scope": effective_scope
        },
        expires_delta=access_token_expires
    )

    # Генерируем новый refresh token
    new_refresh_token = generate_refresh_token()
    active_refresh_tokens.add(new_refresh_token)

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scope=effective_scope # Возвращаем фактически установленный scope
    )


@app.post(OAuth2Config.REFRESH_TOKEN_URL, response_model=Token)
async def refresh_token(
    # --- ИЗМЕНЕНО: Принимаем параметры формы вместо JSON ---
    grant_type: str = Form(...),
    refresh_token: str = Form(...), # refresh_token здесь обязателен
    client_id: str = Form(...),     # client_id/secret часто требуются и при refresh
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None) # Опционально для запроса нового scope
    # ----------------------------------------------------
):
    if grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type"
        )

    # FastAPI уже проверит наличие refresh_token, т.к. он не Optional
    # if not refresh_token: ... (проверка не нужна)

    # Проверяем client credentials (стандартная практика для refresh token)
    if client_id != OAuth2Config.CLIENT_ID or client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    # Проверяем, что refresh token активен (используем refresh_token напрямую)
    if refresh_token not in active_refresh_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Удаляем старый refresh token (используем refresh_token напрямую)
    active_refresh_tokens.remove(refresh_token)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Используем scope напрямую, ставим дефолтный если не пришел
    effective_scope = scope or "webhook.read"
    access_token = create_access_token(
        data={
            "sub": client_id, # Используем client_id напрямую
            "scope": effective_scope
        },
        expires_delta=access_token_expires
    )

    # Генерируем НОВЫЙ refresh token (rotation)
    new_refresh_token = generate_refresh_token()
    active_refresh_tokens.add(new_refresh_token)

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scope=effective_scope # Возвращаем фактически установленный scope
    )


@app.post("/webhook")
async def webhook(data: WebhookDataFlexible, token_data: dict = Depends(validate_token)):
    print(f"Received webhook from client {token_data['sub']}")
    print(f"Event: {data.event_name}")
    print(f"Event: {data.eventData}")

    return {"status": "success", "message": "Webhook received"}




if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000)) # PaaS обычно задает порт через env var PORT
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False) # reload=False для продакшена