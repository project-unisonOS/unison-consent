import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from settings import ConsentServiceSettings


def test_consent_settings_defaults(monkeypatch):
    for key in (
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_PASSWORD",
        "UNISON_CONSENT_ISSUER",
        "UNISON_CONSENT_AUDIENCE",
        "UNISON_CONSENT_DEFAULT_TTL",
        "UNISON_CONSENT_JWT_ALGORITHM",
        "UNISON_CONSENT_KEYS_DIR",
        "UNISON_CONSENT_KEY_ROTATION_HOURS",
        "UNISON_CONSENT_PORT",
    ):
        monkeypatch.delenv(key, raising=False)

    settings = ConsentServiceSettings.from_env()

    assert settings.redis.host == "localhost"
    assert settings.redis.port == 6379
    assert settings.redis.password is None
    assert settings.jwt.issuer == "unison-consent"
    assert settings.jwt.audience == "orchestrator"
    assert settings.jwt.default_ttl_seconds == 3600
    assert settings.jwt.algorithm == "RS256"
    assert settings.key_manager.keys_dir == "/app/consent-keys"
    assert settings.key_manager.rotation_hours == 720
    assert settings.app_port == 7072


def test_consent_settings_env_overrides(monkeypatch):
    overrides = {
        "REDIS_HOST": "redis.internal",
        "REDIS_PORT": "6390",
        "REDIS_PASSWORD": "topsecret",
        "UNISON_CONSENT_ISSUER": "custom-issuer",
        "UNISON_CONSENT_AUDIENCE": "custom-audience",
        "UNISON_CONSENT_DEFAULT_TTL": "90",
        "UNISON_CONSENT_JWT_ALGORITHM": "HS256",
        "UNISON_CONSENT_KEYS_DIR": "/tmp/keys",
        "UNISON_CONSENT_KEY_ROTATION_HOURS": "42",
        "UNISON_CONSENT_PORT": "9000",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)

    settings = ConsentServiceSettings.from_env()

    assert settings.redis.host == "redis.internal"
    assert settings.redis.port == 6390
    assert settings.redis.password == "topsecret"
    assert settings.jwt.issuer == "custom-issuer"
    assert settings.jwt.audience == "custom-audience"
    assert settings.jwt.default_ttl_seconds == 90
    assert settings.jwt.algorithm == "HS256"
    assert settings.key_manager.keys_dir == "/tmp/keys"
    assert settings.key_manager.rotation_hours == 42
    assert settings.app_port == 9000
