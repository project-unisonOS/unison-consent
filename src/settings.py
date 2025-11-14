"""Typed configuration for the unison-consent service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class RedisSettings:
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None


@dataclass(frozen=True)
class KeyManagerSettings:
    keys_dir: str = "/app/consent-keys"
    rotation_hours: int = 720


@dataclass(frozen=True)
class JwtSettings:
    issuer: str = "unison-consent"
    audience: str = "orchestrator"
    default_ttl_seconds: int = 3600
    algorithm: str = "RS256"


@dataclass(frozen=True)
class ConsentServiceSettings:
    redis: RedisSettings = field(default_factory=RedisSettings)
    jwt: JwtSettings = field(default_factory=JwtSettings)
    key_manager: KeyManagerSettings = field(default_factory=KeyManagerSettings)
    app_port: int = 7072

    @classmethod
    def from_env(cls) -> "ConsentServiceSettings":
        return cls(
            redis=RedisSettings(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                password=os.getenv("REDIS_PASSWORD"),
            ),
            jwt=JwtSettings(
                issuer=os.getenv("UNISON_CONSENT_ISSUER", "unison-consent"),
                audience=os.getenv("UNISON_CONSENT_AUDIENCE", "orchestrator"),
                default_ttl_seconds=int(
                    os.getenv("UNISON_CONSENT_DEFAULT_TTL", "3600")
                ),
                algorithm=os.getenv("UNISON_CONSENT_JWT_ALGORITHM", "RS256"),
            ),
            key_manager=KeyManagerSettings(
                keys_dir=os.getenv("UNISON_CONSENT_KEYS_DIR", "/app/consent-keys"),
                rotation_hours=int(
                    os.getenv("UNISON_CONSENT_KEY_ROTATION_HOURS", "720")
                ),
            ),
            app_port=int(os.getenv("UNISON_CONSENT_PORT", "7072")),
        )


__all__ = [
    "ConsentServiceSettings",
    "RedisSettings",
    "JwtSettings",
    "KeyManagerSettings",
]
