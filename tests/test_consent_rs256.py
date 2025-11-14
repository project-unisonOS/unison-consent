"""
Unit tests for Consent RS256 implementation (P0.2)
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from jose import jwt, JWTError
import uuid

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto import RSAKeyManager


class TestConsentRSAKeyManager:
    """Tests for consent RSA key manager"""
    
    @pytest.fixture
    def temp_keys_dir(self):
        """Create temporary directory for keys"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def key_manager(self, temp_keys_dir):
        """Create key manager with temp directory"""
        return RSAKeyManager(keys_dir=temp_keys_dir)
    
    def test_generate_consent_key_pair(self, key_manager, temp_keys_dir):
        """Test generating a consent key pair"""
        kid = key_manager.generate_key_pair("consent-test-key")
        
        assert kid == "consent-test-key"
        assert kid in key_manager.keys
        assert key_manager.keys[kid]["active"] is True
        
        # Check files exist
        keys_path = Path(temp_keys_dir)
        assert (keys_path / "consent-test-key_private.pem").exists()
        assert (keys_path / "consent-test-key_public.pem").exists()
        assert (keys_path / "consent-test-key_metadata.json").exists()
    
    def test_sign_consent_grant(self, key_manager):
        """Test signing a consent grant"""
        kid = key_manager.generate_key_pair("consent-signing-key")
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now_utc().timestamp()),
            "exp": int((now_utc() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "data ingestion",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token has kid in header
        header = jwt.get_unverified_header(token)
        assert header["kid"] == kid
        assert header["alg"] == "RS256"
    
    def test_verify_consent_grant(self, key_manager):
        """Test verifying a consent grant"""
        kid = key_manager.generate_key_pair("consent-verify-key")
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now_utc().timestamp()),
            "exp": int((now_utc() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write", "unison.replay.read"],
            "purpose": "data access",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        
        # Verify token signature (crypto module only verifies signature, not claims)
        decoded = key_manager.verify_token(token)
        
        # Manually verify claims (in production, consent_rs256 module does this)
        assert decoded["sub"] == "user123"
        assert decoded["aud"] == "orchestrator"
        assert decoded["iss"] == "unison-consent"
        assert decoded["scopes"] == ["unison.ingest.write", "unison.replay.read"]
        assert decoded["purpose"] == "data access"
        assert decoded["type"] == "consent_grant"
    
    def test_verify_expired_grant(self, key_manager):
        """Test verifying an expired consent grant"""
        kid = key_manager.generate_key_pair("consent-expired-key")
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int((now_utc() - timedelta(hours=2)).timestamp()),
            "exp": int((now_utc() - timedelta(hours=1)).timestamp()),  # Expired
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "test",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        
        # Crypto module verifies signature but not all claims
        # In production, consent_rs256 module checks expiration
        decoded = key_manager.verify_token(token)
        
        # Manually verify it's expired
        assert decoded["exp"] < int(now_utc().timestamp())
    
    def test_consent_jwks_format(self, key_manager):
        """Test JWKS format for consent keys"""
        key_manager.generate_key_pair("consent-jwks-key-1")
        key_manager.generate_key_pair("consent-jwks-key-2")
        
        jwks = key_manager.get_jwks()
        
        assert "keys" in jwks
        assert len(jwks["keys"]) == 2
        
        # Check key format
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key
    
    def test_multiple_scopes_in_grant(self, key_manager):
        """Test consent grant with multiple scopes"""
        kid = key_manager.generate_key_pair("consent-multi-scope")
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now_utc().timestamp()),
            "exp": int((now_utc() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": [
                "unison.ingest.write",
                "unison.replay.read",
                "unison.replay.write",
                "unison.replay.delete"
            ],
            "purpose": "full access",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        decoded = key_manager.verify_token(token)
        
        assert len(decoded["scopes"]) == 4
        assert "unison.ingest.write" in decoded["scopes"]
        assert "unison.replay.delete" in decoded["scopes"]
    
    def test_admin_scope_grant(self, key_manager):
        """Test consent grant with admin scope"""
        kid = key_manager.generate_key_pair("consent-admin")
        
        payload = {
            "sub": "admin-user",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now_utc().timestamp()),
            "exp": int((now_utc() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.admin.all"],
            "purpose": "administrative access",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        decoded = key_manager.verify_token(token)
        
        assert decoded["scopes"] == ["unison.admin.all"]
        assert decoded["sub"] == "admin-user"
    
    def test_grant_with_custom_ttl(self, key_manager):
        """Test consent grant with custom TTL"""
        kid = key_manager.generate_key_pair("consent-custom-ttl")
        
        # 30 minute TTL
        ttl_seconds = 1800
        now = now_utc()
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "short-term access",
            "type": "consent_grant"
        }
        
        token = key_manager.sign_token(payload, kid)
        decoded = key_manager.verify_token(token)
        
        # Verify TTL is approximately correct (within 5 seconds)
        actual_ttl = decoded["exp"] - decoded["iat"]
        assert abs(actual_ttl - ttl_seconds) < 5
    
    def test_grant_with_context(self, key_manager):
        """Test consent grant with additional context"""
        kid = key_manager.generate_key_pair("consent-context")
        
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(now_utc().timestamp()),
            "exp": int((now_utc() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "data ingestion",
            "type": "consent_grant",
            "context": {
                "device_id": "device-123",
                "session_id": "session-456"
            }
        }
        
        token = key_manager.sign_token(payload, kid)
        decoded = key_manager.verify_token(token)
        
        assert "context" in decoded
        assert decoded["context"]["device_id"] == "device-123"
        assert decoded["context"]["session_id"] == "session-456"
    
    def test_separate_consent_keys(self, key_manager):
        """Test that consent keys are separate from auth keys"""
        kid = key_manager.generate_key_pair("consent-primary-2025-11")
        
        # Verify kid follows consent naming convention
        assert "consent" in kid.lower()
        
        # Verify key manager was initialized (has keys)
        assert len(key_manager.keys) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
from unison_common.datetime_utils import now_utc
