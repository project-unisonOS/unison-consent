from fastapi import FastAPI, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import uvicorn
import time
import uuid
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel, Field

# P0.2: Import RSA key manager and JWKS router
try:
    from .crypto import get_key_manager
    from .jwks import router as jwks_router
    from .settings import ConsentServiceSettings
except ImportError:
    # Fallback for direct execution
    from crypto import get_key_manager
    from jwks import router as jwks_router
    from settings import ConsentServiceSettings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SETTINGS = ConsentServiceSettings.from_env()

# Configuration
# P0.2: Removed SECRET_KEY and HS256 - now using RS256 with RSA keys
ALGORITHM = SETTINGS.jwt.algorithm  # RS256 by default
AUDIENCE = SETTINGS.jwt.audience
ISSUER = SETTINGS.jwt.issuer
DEFAULT_TTL = SETTINGS.jwt.default_ttl_seconds

# P0.2: Initialize RSA key manager
key_manager = get_key_manager(
    keys_dir=SETTINGS.key_manager.keys_dir,
    rotation_interval_hours=SETTINGS.key_manager.rotation_hours,
)

app = FastAPI(
    title="unison-consent",
    description="Consent management service for Unison platform",
    version="1.0.0"
)

# P0.2: Include JWKS router for public key distribution
app.include_router(jwks_router, tags=["jwks"])

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

# In-memory grant store (in production, use a proper database)
grants_db = {}
revoked_grants = set()

class GrantRequest(BaseModel):
    """Request model for grant issuance"""
    subject: str = Field(..., description="Subject identifier (user ID)")
    scopes: List[str] = Field(..., description="List of granted scopes")
    purpose: str = Field(..., description="Purpose of the grant")
    ttl: Optional[int] = Field(default=DEFAULT_TTL, description="Time to live in seconds")
    audience: Optional[str] = Field(default=AUDIENCE, description="Audience for the grant")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context")

class GrantResponse(BaseModel):
    """Response model for grant issuance"""
    jti: str = Field(..., description="Grant ID")
    jwt: str = Field(..., description="JWT grant token")
    expires_at: datetime = Field(..., description="Expiration time")

class RevocationRequest(BaseModel):
    """Request model for grant revocation"""
    jti: str = Field(..., description="Grant ID to revoke")

def create_grant_jwt(
    subject: str,
    scopes: List[str],
    purpose: str,
    ttl: int = DEFAULT_TTL,
    audience: str = AUDIENCE,
    jti: str = None
) -> str:
    """Create a JWT grant token"""
    if jti is None:
        jti = str(uuid.uuid4())
    
    now = int(time.time())
    expires_at = now + ttl
    
    payload = {
        "sub": subject,
        "aud": audience,
        "iss": ISSUER,
        "iat": now,
        "exp": expires_at,
        "jti": jti,
        "scopes": scopes,
        "purpose": purpose,
        "type": "consent_grant"
    }
    
    # P0.2: Use RSA key manager to sign with RS256
    return key_manager.sign_token(payload)

def verify_grant_jwt(token: str) -> Dict[str, Any]:
    """Verify a grant JWT token"""
    try:
        # P0.2: Use RSA key manager to verify with RS256
        payload = key_manager.verify_token(token)
        
        # Verify audience and issuer
        if payload.get("aud") != AUDIENCE:
            raise JWTError(f"Invalid audience: {payload.get('aud')}")
        if payload.get("iss") != ISSUER:
            raise JWTError(f"Invalid issuer: {payload.get('iss')}")
        
        # Check if grant is revoked
        jti = payload.get("jti")
        if jti in revoked_grants:
            raise JWTError("Grant has been revoked")
        
        return payload
        
    except JWTError as e:
        logger.error(f"Grant verification failed: {e}")
        raise

@app.post("/grants", response_model=GrantResponse)
def issue_grant(
    request: GrantRequest,
    credentials: Optional[Any] = Depends(security)
):
    """Issue a new consent grant"""
    # TODO: Verify caller has authority to issue grants
    # For now, allow any authenticated request
    
    jti = str(uuid.uuid4())
    
    # Create JWT grant
    grant_jwt = create_grant_jwt(
        subject=request.subject,
        scopes=request.scopes,
        purpose=request.purpose,
        ttl=request.ttl,
        audience=request.audience,
        jti=jti
    )
    
    # Store grant metadata
    grants_db[jti] = {
        "subject": request.subject,
        "scopes": request.scopes,
        "purpose": request.purpose,
        "audience": request.audience,
        "issued_at": now_utc(),
        "expires_at": now_utc() + timedelta(seconds=request.ttl),
        "context": request.context or {}
    }
    
    expires_at = now_utc() + timedelta(seconds=request.ttl)
    
    logger.info(f"Issued grant {jti} for subject {request.subject} with scopes {request.scopes}")
    
    return GrantResponse(
        jti=jti,
        jwt=grant_jwt,
        expires_at=expires_at
    )

@app.post("/revoke")
def revoke_grant(
    request: RevocationRequest,
    credentials: Optional[Any] = Depends(security)
):
    """Revoke a consent grant"""
    jti = request.jti
    
    if jti not in grants_db:
        raise HTTPException(status_code=404, detail="Grant not found")
    
    # Mark as revoked
    revoked_grants.add(jti)
    
    # Remove from active grants
    grant_info = grants_db.pop(jti, None)
    
    logger.info(f"Revoked grant {jti}")
    
    return {"ok": True, "message": "Grant revoked successfully"}

@app.post("/introspect")
def introspect_grant(
    token: str = Body(..., embed=True),
    credentials: Optional[Any] = Depends(security)
):
    """Introspect a grant token"""
    try:
        payload = verify_grant_jwt(token)
        
        jti = payload.get("jti")
        grant_info = grants_db.get(jti, {})
        
        return {
            "active": True,
            "jti": jti,
            "subject": payload.get("sub"),
            "scopes": payload.get("scopes"),
            "purpose": payload.get("purpose"),
            "audience": payload.get("aud"),
            "expires_at": datetime.fromtimestamp(payload.get("exp")),
            "issued_at": datetime.fromtimestamp(payload.get("iat"))
        }
        
    except JWTError as e:
        return {
            "active": False,
            "error": str(e)
        }

@app.get("/grants/{subject}")
def list_grants(
    subject: str,
    credentials: Optional[Any] = Depends(security)
):
    """List active grants for a subject"""
    subject_grants = []
    
    for jti, grant_info in grants_db.items():
        if grant_info["subject"] == subject and jti not in revoked_grants:
            subject_grants.append({
                "jti": jti,
                "scopes": grant_info["scopes"],
                "purpose": grant_info["purpose"],
                "issued_at": grant_info["issued_at"],
                "expires_at": grant_info["expires_at"]
            })
    
    return {"grants": subject_grants}

@app.get("/revoked")
def get_revoked_grants():
    """
    Get list of revoked grant JTIs (P0.2)
    
    This endpoint allows services to check revocation status locally.
    Clients should cache this list and refresh periodically (60 seconds).
    """
    return {
        "revoked": list(revoked_grants),
        "count": len(revoked_grants),
        "cache_ttl": 60  # Suggest 60 second cache
    }

@app.get("/healthz")
@app.get("/health")
def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "unison-consent"}

@app.get("/readyz")
@app.get("/ready")
def ready():
    """Readiness check endpoint"""
    return {"status": "ready", "service": "unison-consent"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=SETTINGS.app_port)
from unison_common.datetime_utils import now_utc
