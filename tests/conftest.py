from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def deterministic_test_signing_key(monkeypatch):
    """Keep signed test fixtures independent of the host shell environment."""

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 64)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "test-current")


@pytest.fixture
def current_signing_key(monkeypatch):
    """Explicit opt-in key for tests that create newly authorized evidence."""

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "managed-test-signing-key-0123456789abcdef")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "test-current")
