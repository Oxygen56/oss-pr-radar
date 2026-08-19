from __future__ import annotations

import pytest


@pytest.fixture
def current_signing_key(monkeypatch):
    """Explicit opt-in key for tests that create newly authorized evidence."""

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "managed-test-signing-key-0123456789abcdef")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "test-current")
