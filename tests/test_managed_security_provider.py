from __future__ import annotations

from types import SimpleNamespace

from oss_pr_radar import managed_security as security


def test_keychain_current_provider_signs_and_verifies_without_exposing_secret(monkeypatch):
    secret = "keychain-only-secret-value"
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY", raising=False)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "keychain-current")
    monkeypatch.setattr(security.sys, "platform", "darwin")
    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=secret + "\n"),
    )
    payload = {"event": "keychain"}
    signed = security.sign_current(payload, context="managed-snapshot-v1")
    assert signed["keyId"] == "keychain-current"
    assert security.verify_current_or_previous(
        payload,
        context="managed-snapshot-v1",
        key_id=signed["keyId"],
        signature=signed["signature"],
    )
    assert secret not in str(signed)


def test_keychain_failure_rejects_signing_and_previous_does_not_authorize(monkeypatch):
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY", raising=False)
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS", raising=False)
    monkeypatch.setattr(security.sys, "platform", "darwin")
    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    assert security.sign_current({}, context="managed-snapshot-v1") == {
        "keyId": None,
        "signature": None,
    }
    assert security.current_signing_key_available() is False
