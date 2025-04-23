from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Header
from fastapi.security import (
    OAuth2PasswordBearer,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
    APIKeyHeader,
)
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Union # Added Union
import jwt
from jwt import PyJWTError
import secrets
import base64
import os # Required for environment variables

# --- Helper Functions ---

# Function to generate a random key
def generate_secret_key(length: int = 32) -> str:
    return base64.b64encode(secrets.token_bytes(length)).decode()

# Function to generate a refresh token
def generate_refresh_token() -> str:
    return secrets.token_urlsafe(32)

# --- Configuration ---

# Helper function to get env var or default, with logging
def get_env_var(var_name: str, default_value: str, is_secret: bool = False) -> str:
    value = os.environ.get(var_name, default_value)
    if value == default_value:
        print(f"INFO: Using default {var_name}.")
        # Avoid logging default secrets unless explicitly needed for debugging
        # if is_secret:
        #     print(f"INFO: Default {var_name} value: '{value}'") # Be careful logging secrets!
    else:
        log_value = "*******" if is_secret else value
        print(f"INFO: Using {var_name} from environment variable: '{log_value}'")
    return value

# --- OAuth2 Client Credentials ---
DEFAULT_CLIENT_ID = "c47df55b-4524-494b-9652-ce1492249e8b"
DEFAULT_CLIENT_SECRET = "60b2ba8c-9533-45d8-b323-334f46bd7b2a" # Secret!
OAUTH2_CLIENT_ID = get_env_var("OAUTH2_CLIENT_ID", DEFAULT_CLIENT_ID)
OAUTH2_CLIENT_SECRET = get_env_var("OAUTH2_CLIENT_SECRET", DEFAULT_CLIENT_SECRET, is_secret=True)

# --- Basic Authentication Credentials ---
DEFAULT_BASIC_AUTH_USERNAME = "admin"
DEFAULT_BASIC_AUTH_PASSWORD = "1Kosmos123" # Secret!
BASIC_AUTH_USERNAME = get_env_var("BASIC_AUTH_USERNAME", DEFAULT_BASIC_AUTH_USERNAME)
BASIC_AUTH_PASSWORD = get_env_var("BASIC_AUTH_PASSWORD", DEFAULT_BASIC_AUTH_PASSWORD, is_secret=True)

# --- Static Bearer Token ---
DEFAULT_STATIC_BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJBZG1pblgiLCJVc2VybmFtZSI6IkFkbWluIiwiZXhwIjoxNzc2OTYwNTQ3LCJpYXQiOjE3NDU0MjQ1NDd9.0p1Hl3UpIdDomTSAJWRlIx1baP3DmGnYO7SNNHRQ6Ig" # Secret!
STATIC_BEARER_TOKEN = get_env_var("STATIC_BEARER_TOKEN", DEFAULT_STATIC_BEARER_TOKEN, is_secret=True)

# --- API Key ---
DEFAULT_API_KEY_NAME = "X-API-Key"
DEFAULT_API_KEY_VALUE = "1b08578e-d922-47fe-8b89-693732dd717b" # Secret!
API_KEY_NAME = get_env_var("API_KEY_NAME", DEFAULT_API_KEY_NAME)
API_KEY_VALUE = get_env_var("API_KEY_VALUE", DEFAULT_API_KEY_VALUE, is_secret=True)

# --- Token Lifetime ---
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 5
ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
try:
    ACCESS_TOKEN_EXPIRE_MINUTES_STR = os.environ.get(
        "ACCESS_TOKEN_EXPIRE_MINUTES", str(DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    parsed_minutes = int(ACCESS_TOKEN_EXPIRE_MINUTES_STR)
    if parsed_minutes > 0:
        ACCESS_TOKEN_EXPIRE_MINUTES = parsed_minutes
    else:
        print(f"Warning: Invalid ACCESS_TOKEN_EXPIRE_MINUTES value ({parsed_minutes}). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")
except ValueError:
    print(f"Warning: Could not parse ACCESS_TOKEN_EXPIRE_MINUTES environment variable ('{ACCESS_TOKEN_EXPIRE_MINUTES_STR}'). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")

print(f"INFO: Using access token lifetime: {ACCESS_TOKEN_EXPIRE_MINUTES} minutes")

# --- Other Constants ---
ALGORITHM = "HS256"
OAUTH2_TOKEN_URL = "/oauth/token"
OAUTH2_REFRESH_TOKEN_URL = "/oauth/refresh"
OAUTH2_SCOPES = ["webhook.read", "webhook.write"]


# In-memory storage (WARNING: Not production-ready)
active_tokens = {} # Stores JWT -> unique secret
active_refresh_tokens = set()


# --- FastAPI App Instance ---
app = FastAPI()

# Initialize state on the app instance for the latest webhook
app.state.latest_webhook_payload = None
app.state.latest_webhook_auth_method = None # Track how the last webhook was authenticated


# --- Pydantic Models ---

# Model for incoming webhook data (flexible with extra fields)
class WebhookDataFlexible(BaseModel):
    event_name: str
    eventData: Dict[str, Any]
    model_config = {"extra": "allow"}

# Model for the OAuth2 token response
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    expires_in: int
    scope: str

# Model for the NEW /config endpoint response
class FullConfig(BaseModel):
    oauth2ClientId: str
    oauth2ClientSecret: str # WARNING: Exposing secrets is insecure!
    oauth2TokenUrl: str
    oauth2RefreshTokenUrl: str
    oauth2Scopes: List[str]
    basicAuthUsername: str
    basicAuthPassword: str # WARNING: Exposing secrets is insecure!
    staticBearerToken: str # WARNING: Exposing secrets is insecure!
    apiKeyHeaderName: str
    apiKeyValue: str # WARNING: Exposing secrets is insecure!
    accessTokenExpireMinutes: int


# --- Security Schemes Setup ---
# OAuth2 Bearer Token (for /webhook endpoint)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=OAUTH2_TOKEN_URL,
    scopes={scope: f"Scope for {scope}" for scope in OAUTH2_SCOPES}
)

# Basic Authentication
basic_scheme = HTTPBasic()

# Static Bearer Token Authentication
static_bearer_scheme = HTTPBearer()

# API Key Authentication (checks header defined by API_KEY_NAME)
api_key_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False) # auto_error=False to customize 401


# --- Token Helper Functions ---

# Creates a new access token (JWT)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15) # Default fallback
    to_encode.update({"exp": expire})
    current_secret = generate_secret_key() # Unique secret per token
    token_id = secrets.token_urlsafe(8)
    to_encode["jti"] = token_id
    encoded_jwt = jwt.encode(to_encode, current_secret, algorithm=ALGORITHM)
    active_tokens[encoded_jwt] = current_secret # Store token -> secret
    return encoded_jwt

# Validates an incoming access token (for OAuth2 /webhook)
async def validate_oauth2_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials (OAuth2)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_not_found_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token not found or expired (OAuth2)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    missing_scope_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing scope in token (OAuth2)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    insufficient_scope_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Token does not have the required scope (OAuth2)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if token not in active_tokens:
            raise token_not_found_exception
        secret = active_tokens[token]
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        token_scope_str = payload.get("scope")
        if not token_scope_str:
            raise missing_scope_exception
        token_scopes = set(token_scope_str.split())

        # --- Scope Validation Logic (Example: /webhook needs 'webhook.write') ---
        required_scope_for_endpoint = "webhook.write"
        if required_scope_for_endpoint not in token_scopes:
            insufficient_scope_exception.detail = f"Token does not have the required scope: {required_scope_for_endpoint}"
            raise insufficient_scope_exception

        return payload # Return payload if valid and scope sufficient

    except PyJWTError:
        raise credentials_exception
    except KeyError:
        raise token_not_found_exception


# --- Authentication Dependency Functions ---

# Verifies Basic Authentication credentials
async def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(basic_scheme)):
    correct_username = secrets.compare_digest(credentials.username, BASIC_AUTH_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, BASIC_AUTH_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password (Basic Auth)",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username # Return username if successful

# Verifies the static Bearer token
async def verify_static_bearer(token: str = Depends(static_bearer_scheme)):
    # token here is an object with scheme and credentials
    if not secrets.compare_digest(token.credentials, STATIC_BEARER_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing static Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.credentials # Return the token itself if successful (though not usually needed)

# Verifies the API Key from the header
async def verify_api_key(api_key: str = Depends(api_key_scheme)):
    if not api_key: # Handle case where header is missing entirely
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing API Key header: '{API_KEY_NAME}'",
         )
    if not secrets.compare_digest(api_key, API_KEY_VALUE):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid API Key in header '{API_KEY_NAME}'",
        )
    return api_key # Return the key value if successful


# --- Helper Function for Processing Webhooks ---

async def process_and_store_webhook(request: Request, data: WebhookDataFlexible, auth_method: str):
    """
    Common logic to process incoming webhook data and store the latest payload.
    """
    print(f"Received webhook via {auth_method} authentication.")
    print(f"Event Name: {data.event_name}")
    # print(f"Event Data: {data.eventData}") # Can be large

    # --- Store latest webhook payload in memory ---
    # WARNING: Lost on restart, not suitable for multi-worker setups!
    payload_to_store = data.model_dump(mode='json')
    request.app.state.latest_webhook_payload = payload_to_store
    request.app.state.latest_webhook_auth_method = auth_method # Store how it arrived
    print(f"Stored latest webhook payload (event: {data.event_name}, auth: {auth_method})")
    # ---------------------------------------------

    return {"status": "success", "message": f"Webhook received via {auth_method}"}


# --- API Endpoints ---

# --- NEW Configuration Endpoint ---
@app.get("/config", response_model=FullConfig)
async def get_full_config():
    """
    Provides full configuration details to clients.
    WARNING: Exposing secrets (clientSecret, basicPassword, staticToken, apiKeyValue)
             is highly insecure and should be avoided in production environments!
             This is implemented as requested, but use with extreme caution.
    """
    print("WARNING: The /config endpoint is exposing secrets!")
    return FullConfig(
        oauth2ClientId=OAUTH2_CLIENT_ID,
        oauth2ClientSecret=OAUTH2_CLIENT_SECRET, # Secret!
        oauth2TokenUrl=OAUTH2_TOKEN_URL,
        oauth2RefreshTokenUrl=OAUTH2_REFRESH_TOKEN_URL,
        oauth2Scopes=OAUTH2_SCOPES,
        basicAuthUsername=BASIC_AUTH_USERNAME,
        basicAuthPassword=BASIC_AUTH_PASSWORD, # Secret!
        staticBearerToken=STATIC_BEARER_TOKEN, # Secret!
        apiKeyHeaderName=API_KEY_NAME,
        apiKeyValue=API_KEY_VALUE, # Secret!
        accessTokenExpireMinutes=ACCESS_TOKEN_EXPIRE_MINUTES,
    )

# --- OAuth2 Token Endpoints (Original, but using constants) ---
@app.post(OAUTH2_TOKEN_URL, response_model=Token)
async def create_token_endpoint(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None)
):
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant type: {grant_type}. Use client_credentials."
        )
    if not secrets.compare_digest(client_id, OAUTH2_CLIENT_ID) or \
       not secrets.compare_digest(client_secret, OAUTH2_CLIENT_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials (OAuth2)"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # TODO: Validate requested scope against OAUTH2_SCOPES
    effective_scope = scope or " ".join(OAUTH2_SCOPES) # Default to all configured scopes if none requested

    access_token = create_access_token(
        data={"sub": client_id, "scope": effective_scope},
        expires_delta=access_token_expires
    )
    new_refresh_token = generate_refresh_token()
    active_refresh_tokens.add(new_refresh_token)

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
        expires_in=int(access_token_expires.total_seconds()),
        scope=effective_scope
    )

@app.post(OAUTH2_REFRESH_TOKEN_URL, response_model=Token)
async def refresh_token_endpoint(
    grant_type: str = Form(...),
    refresh_token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None)
):
    if grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type. Use refresh_token."
        )
    if not secrets.compare_digest(client_id, OAUTH2_CLIENT_ID) or \
       not secrets.compare_digest(client_secret, OAUTH2_CLIENT_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials (OAuth2 Refresh)"
        )
    if refresh_token not in active_refresh_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid grant: refresh token is invalid or expired"
        )

    active_refresh_tokens.remove(refresh_token) # Invalidate used token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # TODO: Validate requested scope against OAUTH2_SCOPES
    effective_scope = scope or " ".join(OAUTH2_SCOPES) # Default to all configured scopes

    access_token = create_access_token(
        data={"sub": client_id, "scope": effective_scope},
        expires_delta=access_token_expires
    )
    new_refresh_token = generate_refresh_token()
    active_refresh_tokens.add(new_refresh_token) # Store the new one

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token, # Return the new refresh token
        expires_in=int(access_token_expires.total_seconds()),
        scope=effective_scope
    )

# --- Webhook Endpoints ---

# Original Webhook with OAuth2 Bearer Token Auth
@app.post("/webhook")
async def webhook_endpoint_oauth2(
    request: Request,
    data: WebhookDataFlexible,
    token_data: dict = Depends(validate_oauth2_token) # OAuth2 validation
):
    """
    Protected endpoint (OAuth2 Bearer) to receive webhook data.
    Requires a valid Bearer token with 'webhook.write' scope.
    """
    print(f"OAuth2 token validated for client: {token_data.get('sub')}")
    return await process_and_store_webhook(request, data, auth_method="OAuth2 Bearer")

# --- NEW Webhook Endpoints ---

@app.post("/webhook_none")
async def webhook_endpoint_none(request: Request, data: WebhookDataFlexible):
    """
    Public endpoint to receive webhook data. NO AUTHENTICATION REQUIRED.
    """
    return await process_and_store_webhook(request, data, auth_method="None")

@app.post("/webhook_basic")
async def webhook_endpoint_basic(
    request: Request,
    data: WebhookDataFlexible,
    username: str = Depends(verify_basic_auth) # Basic Auth validation
):
    """
    Protected endpoint (HTTP Basic Auth) to receive webhook data.
    Requires valid Basic Auth credentials configured on the server.
    """
    print(f"Basic Auth validated for user: {username}")
    return await process_and_store_webhook(request, data, auth_method="Basic Auth")

@app.post("/webhook_bearer")
async def webhook_endpoint_static_bearer(
    request: Request,
    data: WebhookDataFlexible,
    token: str = Depends(verify_static_bearer) # Static Bearer validation
):
    """
    Protected endpoint (Static Bearer Token) to receive webhook data.
    Requires a valid Bearer token matching the static token configured on the server.
    """
    # We don't typically log the static token itself
    print("Static Bearer token validated.")
    return await process_and_store_webhook(request, data, auth_method="Static Bearer")

@app.post("/webhook_apikey")
async def webhook_endpoint_apikey(
    request: Request,
    data: WebhookDataFlexible,
    api_key: str = Depends(verify_api_key) # API Key validation
):
    """
    Protected endpoint (API Key Header) to receive webhook data.
    Requires a valid API Key in the configured header (default: X-API-Key).
    """
    # Avoid logging the API key value itself unless necessary for debugging
    print(f"API Key validation successful using header '{API_KEY_NAME}'.")
    return await process_and_store_webhook(request, data, auth_method="API Key")

# --- Endpoint to retrieve the latest webhook ---
@app.get("/latest-webhook")
async def get_latest_webhook_endpoint(request: Request):
    """
    Retrieves the payload of the most recent webhook received by the server
    since its last restart. Returns 404 if no webhook has been received yet.
    Also includes the authentication method used.
    """
    latest_payload = request.app.state.latest_webhook_payload
    auth_method = request.app.state.latest_webhook_auth_method

    if latest_payload is not None:
        # Return both the payload and how it was authenticated
        return {
            "auth_method": auth_method,
            "payload": latest_payload
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No webhook has been received yet since the server started."
        )


# --- Server Startup ---
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting server on host 0.0.0.0, port {port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False) # Use the name of your Python file (e.g., main.py -> "main:app")