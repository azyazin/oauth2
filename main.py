from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
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

# Read OAuth2 Client Credentials from Environment Variables
# Use current values as defaults if environment variables are not set
DEFAULT_CLIENT_ID = "c47df55b-4524-494b-9652-ce1492249e8b"
DEFAULT_CLIENT_SECRET = "60b2ba8c-9533-45d8-b323-334f46bd7b2a"

OAUTH2_CLIENT_ID = os.environ.get("OAUTH2_CLIENT_ID", DEFAULT_CLIENT_ID)
# IMPORTANT: Avoid logging the secret in production environments!
# Only log if it's using the default for debugging/awareness.
OAUTH2_CLIENT_SECRET = os.environ.get("OAUTH2_CLIENT_SECRET", DEFAULT_CLIENT_SECRET)
if OAUTH2_CLIENT_SECRET == DEFAULT_CLIENT_SECRET and OAUTH2_CLIENT_ID == DEFAULT_CLIENT_ID:
     print("INFO: Using default CLIENT_ID and CLIENT_SECRET.")
elif OAUTH2_CLIENT_SECRET == DEFAULT_CLIENT_SECRET:
     print(f"INFO: Using CLIENT_ID from environment variable. Using default CLIENT_SECRET.")
else:
     print(f"INFO: Using CLIENT_ID and CLIENT_SECRET from environment variables.")


# OAuth2 Server Configuration Class using loaded values
class OAuth2Config:
    CLIENT_ID = OAUTH2_CLIENT_ID
    CLIENT_SECRET = OAUTH2_CLIENT_SECRET
    TOKEN_URL = "/oauth/token"
    REFRESH_TOKEN_URL = "/oauth/refresh"
    SCOPES = ["webhook.read", "webhook.write"]

# Read token lifetime from environment variable, with a default value
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
try:
    # Try to get value from env var and convert to int
    ACCESS_TOKEN_EXPIRE_MINUTES_STR = os.environ.get(
        "ACCESS_TOKEN_EXPIRE_MINUTES", # Environment variable name
        str(DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES) # Default value (as string)
    )
    ACCESS_TOKEN_EXPIRE_MINUTES = int(ACCESS_TOKEN_EXPIRE_MINUTES_STR)
    # Basic validation
    if ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
        print(f"Warning: Invalid ACCESS_TOKEN_EXPIRE_MINUTES value ({ACCESS_TOKEN_EXPIRE_MINUTES}). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")
        ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
except ValueError:
    # If conversion fails, use the default
    print(f"Warning: Could not parse ACCESS_TOKEN_EXPIRE_MINUTES environment variable ('{ACCESS_TOKEN_EXPIRE_MINUTES_STR}'). Using default: {DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES}")
    ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES

print(f"INFO: Using access token lifetime: {ACCESS_TOKEN_EXPIRE_MINUTES} minutes") # Log the value being used

# JWT Algorithm
ALGORITHM = "HS256"

# In-memory storage for active tokens (secret keys per token) and refresh tokens
# WARNING: Not suitable for production! Use a database or Redis instead.
active_tokens = {}
active_refresh_tokens = set()

# --- FastAPI App Instance ---
app = FastAPI()

# Initialize state on the app instance for the latest webhook
app.state.latest_webhook_payload = None

# --- Pydantic Models ---

# Model for incoming webhook data (flexible with extra fields)
class WebhookDataFlexible(BaseModel):
    # Required fields
    event_name: str
    eventData: Dict[str, Any] # Accepts any dictionary for eventData

    # Pydantic v2+ configuration to allow extra fields
    model_config = {
        "extra": "allow"
    }

# Model for the token response
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    expires_in: int
    scope: str

# Model for token request (used internally for reference, not direct body parsing anymore)
# class TokenRequest(BaseModel):
#     grant_type: str
#     client_id: str
#     client_secret: str
#     scope: Optional[str] = None
#     refresh_token: Optional[str] = None

# Model for the OAuth2 config endpoint response
class OAuth2Info(BaseModel):
    clientId: str
    clientSecret: str # WARNING: Exposing client secret here is insecure
    tokenUrl: str
    refreshTokenUrl: str
    scopes: List[str]

# --- OAuth2 Setup ---
# Configures FastAPI's security utility to extract Bearer tokens
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=OAuth2Config.TOKEN_URL,
    scopes={ # Descriptions for scopes (used in documentation)
        "webhook.read": "Read webhook data",
        "webhook.write": "Send webhook data"
    }
)

# --- Token Helper Functions ---

# Creates a new access token (JWT)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # Default expiration if not provided (e.g., 15 minutes)
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    # Generate a unique secret key FOR THIS SPECIFIC TOKEN
    # This is a non-standard approach; usually a shared secret is used.
    current_secret = generate_secret_key()

    # Add a unique token identifier (JWT ID)
    token_id = secrets.token_urlsafe(8)
    to_encode["jti"] = token_id

    # Encode the token using its unique secret
    encoded_jwt = jwt.encode(to_encode, current_secret, algorithm=ALGORITHM)

    # Store the token and its unique secret in memory
    # WARNING: In-memory storage is lost on restart and doesn't scale!
    active_tokens[encoded_jwt] = current_secret

    return encoded_jwt

# Validates an incoming access token
async def validate_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_not_found_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token not found or expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    missing_scope_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing scope in token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    insufficient_scope_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Token does not have the required scope", # Detail will be formatted later
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Retrieve the unique secret key for this specific token from memory
        if token not in active_tokens:
            raise token_not_found_exception

        secret = active_tokens[token]
        # Decode the JWT using the retrieved secret
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])

        # Extract the scope string from the token payload
        token_scope_str = payload.get("scope")
        if not token_scope_str: # Handle missing scope claim
            raise missing_scope_exception

        # Split the scope string into individual scopes (handles space separation)
        token_scopes = set(token_scope_str.split())

        # --- Scope Validation Logic ---
        # Check if the token has at least one required scope for the target endpoint.
        # This example assumes the /webhook endpoint requires 'webhook.write'.
        # Adjust 'required_scope_for_endpoint' if different endpoints have different needs.
        required_scope_for_endpoint = "webhook.write"
        if required_scope_for_endpoint not in token_scopes:
            insufficient_scope_exception.detail = f"Token does not have the required scope: {required_scope_for_endpoint}"
            raise insufficient_scope_exception

        # Optional: Check if all scopes in the token are allowed by the server configuration
        # allowed_scopes = set(OAuth2Config.SCOPES)
        # if not token_scopes.issubset(allowed_scopes):
        #     raise HTTPException(status_code=403, detail="Token contains disallowed scopes")

        # Return the entire payload if all checks pass
        return payload

    except PyJWTError: # Handle JWT decoding errors (expired, invalid signature etc.)
        raise credentials_exception
    except KeyError: # Handle case where token was in active_tokens but somehow removed concurrently (unlikely)
        raise token_not_found_exception


# --- API Endpoints ---

@app.get("/oauth2-config", response_model=OAuth2Info)
async def get_oauth2_config():
    """
    Provides OAuth2 configuration details to clients.
    WARNING: Exposing clientSecret is insecure for public clients.
    """
    return OAuth2Info(
        clientId=OAuth2Config.CLIENT_ID,
        clientSecret=OAuth2Config.CLIENT_SECRET, # Be cautious about exposing this
        tokenUrl=OAuth2Config.TOKEN_URL,
        refreshTokenUrl=OAuth2Config.REFRESH_TOKEN_URL,
        scopes=OAuth2Config.SCOPES
    )

@app.post(OAuth2Config.TOKEN_URL, response_model=Token)
async def create_token_endpoint( # Renamed function slightly for clarity
    # Expect form data according to OAuth2 spec for client_credentials
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None) # Optional: client can request specific scopes
):
    """
    Handles token requests using the client_credentials grant type.
    Expects data in application/x-www-form-urlencoded format.
    """
    # Validate grant type for this endpoint
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant type for this endpoint: {grant_type}. Use client_credentials."
        )

    # Validate client credentials against configured values
    if client_id != OAuth2Config.CLIENT_ID or client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    # Determine token expiration and scope
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) # Use configured lifetime
    # Use requested scope or default to 'webhook.read' if none requested
    # TODO: Add validation to ensure requested scope is subset of OAuth2Config.SCOPES
    effective_scope = scope or "webhook.read"

    # Create the access token (JWT)
    access_token = create_access_token(
        data={
            "sub": client_id, # 'sub' (subject) claim is the client_id
            "scope": effective_scope
        },
        expires_delta=access_token_expires
    )

    # Generate a new refresh token
    new_refresh_token = generate_refresh_token()
    # Store the refresh token in memory
    # WARNING: In-memory storage is lost on restart!
    active_refresh_tokens.add(new_refresh_token)

    # Return the token response
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60, # Use configured lifetime (in seconds)
        scope=effective_scope # Return the scope granted
    )


@app.post(OAuth2Config.REFRESH_TOKEN_URL, response_model=Token)
async def refresh_token_endpoint( # Renamed function slightly for clarity
    # Expect form data according to OAuth2 spec for refresh_token grant
    grant_type: str = Form(...),
    refresh_token: str = Form(...), # Refresh token is required
    client_id: str = Form(...),     # Client credentials often required for refresh too
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None) # Optional: client can potentially request different scopes
):
    """
    Handles token refresh requests using the refresh_token grant type.
    Expects data in application/x-www-form-urlencoded format.
    Implements refresh token rotation.
    """
    # Validate grant type
    if grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type. Use refresh_token."
        )

    # Validate client credentials
    if client_id != OAuth2Config.CLIENT_ID or client_secret != OAuth2Config.CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    # Check if the provided refresh token is valid (exists in memory)
    # WARNING: In-memory storage is lost on restart!
    if refresh_token not in active_refresh_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            # Avoid detailed errors revealing token validity in production
            detail="Invalid grant: refresh token is invalid or expired"
        )

    # --- Refresh Token Rotation ---
    # Invalidate (remove) the used refresh token
    active_refresh_tokens.remove(refresh_token)

    # Determine expiration and scope for the new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) # Use configured lifetime
    # Use requested scope or default if none requested
    # TODO: Add validation for requested scope
    effective_scope = scope or "webhook.read"

    # Create a new access token
    access_token = create_access_token(
        data={
            "sub": client_id,
            "scope": effective_scope
        },
        expires_delta=access_token_expires
    )

    # Generate a NEW refresh token
    new_refresh_token = generate_refresh_token()
    # Store the new refresh token in memory
    active_refresh_tokens.add(new_refresh_token)

    # Return the new token response
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token, # Return the new refresh token
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60, # Use configured lifetime (in seconds)
        scope=effective_scope # Return the scope granted
    )


@app.post("/webhook")
async def webhook_endpoint( # Renamed function slightly for clarity
    request: Request, # Inject Request to access app state
    data: WebhookDataFlexible, # Use the flexible model allowing extra fields
    token_data: dict = Depends(validate_token) # Protect endpoint, get validated token payload
):
    """
    Protected endpoint to receive webhook data.
    Requires a valid Bearer token with appropriate scope (e.g., 'webhook.write').
    Stores the latest received payload in memory.
    """
    # Access validated token data (e.g., client_id from 'sub')
    print(f"Received webhook from client {token_data.get('sub')}")
    # Access validated webhook data
    print(f"Event Name: {data.event_name}")
    # print(f"Event Data: {data.eventData}") # Can be large

    # --- Store latest webhook payload in memory ---
    # WARNING: Lost on restart, not suitable for multi-worker setups!
    request.app.state.latest_webhook_payload = data.model_dump(mode='json')
    print(f"Stored latest webhook payload for event: {data.event_name}")
    # ---------------------------------------------

    # Return success response
    return {"status": "success", "message": "Webhook received"}

@app.get("/latest-webhook")
async def get_latest_webhook_endpoint(request: Request): # Renamed function slightly for clarity
    """
    Retrieves the payload of the most recent webhook received by the server
    since its last restart. Returns 404 if no webhook has been received yet.
    """
    latest_payload = request.app.state.latest_webhook_payload

    if latest_payload is not None:
        # FastAPI automatically serializes the dict to JSON
        return latest_payload
    else:
        # If no webhook has been received yet
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No webhook has been received yet since the server started."
        )


# --- Server Startup ---
if __name__ == "__main__":
    import uvicorn
    # Read port from environment variable (used by Render and others) or default to 8000
    port = int(os.environ.get("PORT", 8000))
    # Run the Uvicorn server
    # reload=False is important for production
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

