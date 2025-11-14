"""
JWKS (JSON Web Key Set) endpoint for consent service (P0.2)
"""

from fastapi import APIRouter, Response
from typing import Dict
import logging

try:
    from .crypto import get_key_manager
    from .settings import ConsentServiceSettings
except ImportError:
    from crypto import get_key_manager
    from settings import ConsentServiceSettings

logger = logging.getLogger(__name__)

router = APIRouter()
SETTINGS = ConsentServiceSettings.from_env()


@router.get("/jwks.json")
async def get_jwks(response: Response) -> Dict:
    """
    Get JWKS (JSON Web Key Set) for consent grant verification.
    
    Returns public keys in JWKS format for token verification.
    Clients should cache this response and refresh periodically.
    
    Response includes Cache-Control headers for efficient caching.
    """
    try:
        key_manager = get_key_manager(
            keys_dir=SETTINGS.key_manager.keys_dir,
            rotation_interval_hours=SETTINGS.key_manager.rotation_hours,
        )
        jwks = key_manager.get_jwks()
        
        # Set cache headers (5 minutes)
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["Content-Type"] = "application/json"
        
        logger.debug(f"Serving consent JWKS with {len(jwks['keys'])} keys")
        
        return jwks
        
    except Exception as e:
        logger.error(f"Failed to generate JWKS: {e}")
        raise


@router.get("/.well-known/jwks.json")
async def get_jwks_well_known(response: Response) -> Dict:
    """
    Well-known JWKS endpoint (alternative standard location).
    
    Same as /jwks.json but at the standard .well-known location.
    """
    return await get_jwks(response)
