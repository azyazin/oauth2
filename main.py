from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import jwt
from jwt import PyJWTError
import secrets
import base64


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
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Хранилище для активных refresh tokens
# В продакшене следует использовать базу данных
active_tokens = {}
active_refresh_tokens = set()

app = FastAPI()


class WebhookData(BaseModel):
    event: str
    data: Dict


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

        secret = active_tokens[token]
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])

        if payload.get("scope") not in OAuth2Config.SCOPES:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid scope",
            )
        return payload
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
async def create_token(request: TokenRequest):
    if request.grant_type not in ["client_credentials", "refresh_token"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type"
        )

    if request.client_id != OAuth2Config.CLIENT_ID or request.client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": request.client_id,
            "scope": request.scope or "webhook.read"
        },
        expires_delta=access_token_expires
    )

    # Генерируем новый refresh token
    refresh_token = generate_refresh_token()
    active_refresh_tokens.add(refresh_token)

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scope=request.scope or "webhook.read"
    )


@app.post(OAuth2Config.REFRESH_TOKEN_URL, response_model=Token)
async def refresh_token(request: TokenRequest):
    if request.grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type"
        )

    if not request.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required"
        )

    if request.client_id != OAuth2Config.CLIENT_ID or request.client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    # Проверяем, что refresh token активен
    if request.refresh_token not in active_refresh_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Удаляем старый refresh token
    active_refresh_tokens.remove(request.refresh_token)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": request.client_id,
            "scope": request.scope or "webhook.read"
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
        scope=request.scope or "webhook.read"
    )


@app.post("/webhook")
async def webhook(data: WebhookData, token_data: dict = Depends(validate_token)):
    print(f"Received webhook from client {token_data['sub']}")
    print(f"Event: {data.event}")
    print(f"Data: {data.data}")
    return {"status": "success", "message": "Webhook received"}




if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000)) # PaaS обычно задает порт через env var PORT
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False) # reload=False для продакшена