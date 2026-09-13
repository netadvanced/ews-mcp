"""Gateway probe/reset behavior — the false-warm fix (Phase B critical #4).

``inbox.total_count`` is a cached property after its first read, so probing
it reported warm forever (the /readyz lie). The probe must round-trip every
call, and reset() must evict exchangelib's protocol cache so a wedged
session actually renegotiates auth.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
from conftest import make_settings
from exchangelib.errors import UnauthorizedError

from ewsmcp.errors import ToolError
from ewsmcp.gateway import client as client_mod
from ewsmcp.gateway.client import EWSGateway, NoRetryOn401
from ewsmcp.gateway.connection import STATE_AUTH_FAILED, ConnectionManager


def _gateway_with_mock_account():
    gw = EWSGateway(make_settings())
    account = MagicMock(name="account")
    gw._account = account
    return gw, account


def test_probe_round_trips_on_every_call():
    gw, account = _gateway_with_mock_account()
    assert gw.test_connection() is True
    assert gw.test_connection() is True
    assert account.root.refresh.call_count == 2  # not a cached-property read


def test_probe_failure_is_reported_not_cached():
    gw, account = _gateway_with_mock_account()
    account.root.refresh.side_effect = ConnectionError("front door down")
    assert gw.test_connection() is False
    assert "front door down" in gw.last_connection_error
    account.root.refresh.side_effect = None
    assert gw.test_connection() is True  # recovery observed immediately
    assert gw.last_connection_error is None


def test_reset_evicts_protocol_cache_and_folder_cache(monkeypatch):
    cleared = []
    monkeypatch.setattr(client_mod.CachingProtocol, "clear_cache",
                        lambda: cleared.append(True))
    gw, account = _gateway_with_mock_account()
    gw._folder_cache = {"path": object()}
    gw._folder_cache_ts = 123.0
    gw.reset()
    assert gw._account is None
    account.protocol.close.assert_called_once()
    assert cleared == [True]  # without this, the wedged Protocol comes back
    assert gw._folder_cache == {}
    assert gw._folder_cache_ts == 0.0


def test_reset_survives_close_and_clear_failures(monkeypatch):
    monkeypatch.setattr(
        client_mod.CachingProtocol, "clear_cache",
        lambda: (_ for _ in ()).throw(RuntimeError("cache locked")))
    gw, account = _gateway_with_mock_account()
    account.protocol.close.side_effect = OSError("socket gone")
    gw.reset()  # must not raise
    assert gw._account is None


# --- EWS_AUTH_FAIL_FAST ---------------------------------------------------------


def _fail_fast_gateway():
    gw = EWSGateway(make_settings(ews_auth_fail_fast=True))
    account = MagicMock(name="account")
    gw._account = account
    account.root.refresh.side_effect = UnauthorizedError("Invalid credentials")
    return gw, account


def test_401_is_raised_not_retried():
    resp = MagicMock(status_code=401, url="https://x/EWS", headers={}, content=b"")
    with pytest.raises(UnauthorizedError):
        NoRetryOn401(max_wait=300).raise_response_errors(resp)


def test_rejected_login_blocks_later_calls():
    gw, account = _fail_fast_gateway()
    assert gw.test_connection() is False
    assert gw.test_connection() is False
    assert account.root.refresh.call_count == 1
    with pytest.raises(ToolError):
        asyncio.run(gw.call(lambda acc: acc.inbox))


def test_other_errors_do_not_block():
    gw, account = _fail_fast_gateway()
    account.root.refresh.side_effect = ConnectionError("reset by peer")
    assert gw.test_connection() is False
    assert gw.auth_failed is None


def test_default_keeps_existing_retry_behaviour(monkeypatch):
    policies = []
    monkeypatch.setattr(client_mod, "Configuration",
                        lambda **kw: policies.append(kw["retry_policy"]))
    monkeypatch.setattr(client_mod, "Account", MagicMock())
    EWSGateway(make_settings())._build_account()
    EWSGateway(make_settings(ews_auth_fail_fast=True))._build_account()
    assert type(policies[0]) is client_mod.FaultTolerance
    assert type(policies[1]) is NoRetryOn401

    gw, account = _gateway_with_mock_account()
    account.root.refresh.side_effect = UnauthorizedError("Invalid credentials")
    assert gw.test_connection() is False
    assert gw.test_connection() is False
    assert account.root.refresh.call_count == 2
    assert gw.auth_failed is None


def test_locked_out_and_cas_errors_keep_their_message():
    locked = MagicMock(status_code=401, url="https://x/EWS", headers={},
                       content=b"The referenced account is currently locked out")
    with pytest.raises(UnauthorizedError, match="locked out"):
        NoRetryOn401(max_wait=300).raise_response_errors(locked)


def test_warmup_stops_after_rejected_login():
    gw, account = _fail_fast_gateway()
    mgr = ConnectionManager(gw, initial_backoff=0.01, max_backoff=0.01)

    async def run():
        await mgr.start()
        await asyncio.wait_for(mgr._task, timeout=2)

    asyncio.run(run())
    assert mgr.state == STATE_AUTH_FAILED
    assert account.root.refresh.call_count == 1
