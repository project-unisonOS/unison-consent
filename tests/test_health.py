import os
import pathlib
import sys
import tempfile

from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "src"))
os.environ.setdefault(
    "UNISON_CONSENT_KEYS_DIR",
    tempfile.mkdtemp(prefix="unison-consent-test-keys-"),
)

from main import app  # noqa: E402


def test_health_endpoint():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json().get("service") == "unison-consent"
