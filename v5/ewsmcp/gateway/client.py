"""EWS gateway — one Account per process, EWS off the event loop.

Auth rule (verified live 2026-06-12): NEVER pin auth_type against this
Exchange; only exchangelib auto-negotiation works, and during front-door
lockdown windows nothing fresh authenticates at all — which is why the
ConnectionManager treats connecting as a state, not a failure.
"""

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from exchangelib import Account, Build, Configuration, Credentials, DELEGATE, EWSTimeZone, Version
from exchangelib.errors import UnauthorizedError
from exchangelib.protocol import (
    BaseProtocol,
    CachingProtocol,
    FaultTolerance,
    NoVerifyHTTPAdapter,
)

from ..config import Settings
from ..errors import ToolError

logger = logging.getLogger(__name__)

WELL_KNOWN = {
    "f:inbox": "inbox", "f:sent": "sent", "f:drafts": "drafts",
    "f:trash": "trash", "f:junk": "junk", "f:outbox": "outbox",
    "f:calendar": "calendar", "f:contacts": "contacts", "f:tasks": "tasks",
}


AUTH_LATCH_FILE = "auth_blocked.json"


class AuthFailFast(FaultTolerance):
    """FaultTolerance for transient errors, but NEVER retry a 401.

    Stock FaultTolerance maps HTTP 401 to ErrorServerBusy and keeps retrying
    for up to max_wait seconds — with a wrong password that is a lockout
    loop (the AD account locks after ~3 bad logins).
    """

    def raise_response_errors(self, response):
        if response.status_code == 401:
            raise UnauthorizedError(f"Invalid credentials for {response.url}")
        return super().raise_response_errors(response)


def is_auth_error(exc: BaseException) -> bool:
    if isinstance(exc, UnauthorizedError):
        return True
    text = str(exc).lower()
    return any(k in text for k in ("401", "unauthorized", "invalid credentials", "locked out"))


class EWSGateway:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._account: Optional[Account] = None
        self._account_lock = threading.Lock()
        # Until one request has authenticated successfully, EWS work is
        # single-flight: concurrent first calls would each send the
        # (possibly wrong) password and burn several lockout attempts.
        self._auth_verified = False
        self._first_auth_lock = threading.Lock()
        self._latch_path = os.path.join(settings.data_dir, AUTH_LATCH_FILE)
        self.auth_blocked: Optional[str] = self._load_auth_latch()
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, settings.ews_max_concurrency),
            thread_name_prefix="ews",
        )
        self.last_connection_error: Optional[str] = None
        self._folder_cache: Dict[str, Any] = {}
        self._folder_cache_ts = 0.0
        if settings.ews_insecure_skip_verify:
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
            logger.warning("TLS verification DISABLED for Exchange traffic")

    # ------------------------------------------------------------- account

    # ---------------------------------------------------------- auth latch

    def _credential_fingerprint(self) -> str:
        s = self.settings
        raw = f"{s.ews_username or s.ews_email}\0{s.ews_password or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _load_auth_latch(self) -> Optional[str]:
        """A latch survives restarts, but only for the SAME credentials:
        editing the password in .env re-arms exactly one new attempt."""
        try:
            with open(self._latch_path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:  # unreadable latch → stay blocked (fail closed)
            return f"auth latch unreadable ({e}); delete {self._latch_path} to retry"
        if data.get("fingerprint") != self._credential_fingerprint():
            logger.warning("credentials changed since last auth failure — clearing auth latch")
            try:
                os.remove(self._latch_path)
            except OSError:
                pass
            return None
        return data.get("error") or "authentication failed previously"

    def _trip_auth_latch(self, exc: BaseException) -> None:
        msg = f"{type(exc).__name__}: {exc}"[:500]
        self.auth_blocked = msg
        self._auth_verified = False
        logger.error("AUTH FAILED — all Exchange access halted, no retries: %s", msg)
        try:
            os.makedirs(os.path.dirname(self._latch_path), exist_ok=True)
            with open(self._latch_path, "w") as f:
                json.dump({"fingerprint": self._credential_fingerprint(),
                           "error": msg, "ts": time.time()}, f)
        except OSError as e:
            logger.error("could not persist auth latch: %s", e)

    def _auth_blocked_error(self) -> ToolError:
        return ToolError(
            "auth_failed",
            f"Exchange login is halted after an authentication failure: {self.auth_blocked}",
            hint=("No automatic retries (account lockout protection). Fix EWS_PASSWORD "
                  f"in .env and restart, or delete {self._latch_path} to allow one new attempt."),
        )

    def _guarded(self, fn: Callable[[], Any]) -> Any:
        """Run one blocking EWS operation under the auth latch."""
        if self.auth_blocked:
            raise self._auth_blocked_error()
        if self._auth_verified:
            try:
                return fn()
            except Exception as e:
                if is_auth_error(e):
                    self._trip_auth_latch(e)
                raise
        with self._first_auth_lock:
            if self.auth_blocked:
                raise self._auth_blocked_error()
            try:
                result = fn()
            except Exception as e:
                if is_auth_error(e):
                    self._trip_auth_latch(e)
                raise
            self._auth_verified = True
            return result

    @property
    def account(self) -> Account:
        if self.auth_blocked:
            raise self._auth_blocked_error()
        with self._account_lock:
            if self._account is None:
                self._account = self._build_account()
            return self._account

    def _build_account(self) -> Account:
        s = self.settings
        BaseProtocol.TIMEOUT = s.request_timeout
        kwargs: Dict[str, Any] = dict(
            service_endpoint=s.ews_server_url,
            credentials=Credentials(s.ews_username or s.ews_email, s.ews_password or ""),
            retry_policy=AuthFailFast(max_wait=s.ews_retry_max_wait_seconds),
        )
        if s.ews_auth_type_force:  # escape hatch for a DIFFERENT Exchange only
            logger.warning("auth_type FORCED to %s — the primary Exchange requires auto-negotiation",
                           s.ews_auth_type_force)
            kwargs["auth_type"] = s.ews_auth_type_force
        if s.ews_version_build:  # skip exchangelib's Version.guess() probe entirely
            major, minor, major_build, minor_build = (int(p) for p in s.ews_version_build.split("."))
            build = Build(major, minor, major_build, minor_build)
            kwargs["version"] = Version(build=build, api_version=s.ews_api_version)
            logger.info("EWS version pinned to %s / %s (skipping auto-detect probe)",
                        s.ews_version_build, kwargs["version"].api_version)
        config = Configuration(**kwargs)
        return Account(
            primary_smtp_address=s.ews_email,
            config=config,
            autodiscover=False,
            access_type=DELEGATE,
            default_timezone=EWSTimeZone(s.ews_tz),
        )

    def reset(self) -> None:
        """Drop the cached account AND exchangelib's protocol-cache entry.

        Dropping only our Account is not enough: ``CachingProtocol`` hands
        the same wedged Protocol (with its already-negotiated auth type)
        right back on the next build, so a session that died mid-outage
        would never renegotiate. Clearing the cache forces a genuinely
        fresh session + auth negotiation on the next access.
        """
        with self._account_lock:
            if self._account is not None:
                try:
                    self._account.protocol.close()
                except Exception:
                    pass
                self._account = None
        try:
            CachingProtocol.clear_cache()
        except Exception as e:
            logger.debug("protocol cache clear failed: %s", e)
        self._folder_cache.clear()
        self._folder_cache_ts = 0.0

    def test_connection(self) -> bool:
        """Real network probe — must round-trip on EVERY call.

        ``inbox.total_count`` is a cached property after its first read, so
        probing it reported warm forever once it had succeeded once (the
        false-warm bug: /readyz lied through outages and the reset ladder
        never ran). ``root.refresh()`` issues a GetFolder request each time.
        """
        try:
            self._guarded(lambda: self.account.root.refresh())
            self.last_connection_error = None
            return True
        except Exception as e:
            self.last_connection_error = f"{type(e).__name__}: {e}"
            logger.error("connection test failed: %s", self.last_connection_error)
            return False

    # ------------------------------------------------------------- calling

    async def call(self, fn: Callable[[Account], Any]) -> Any:
        """Run blocking EWS work on the bounded pool; the pool size IS the
        EWS concurrency cap (polite guest on the per-user throttle budget)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._pool, lambda: self._guarded(lambda: fn(self.account)))

    # ------------------------------------------------------------- folders

    def _folder_map(self, account: Account) -> Dict[str, Any]:
        """{raw_id|lower_path: Folder} cache, rebuilt every 300s (sync)."""
        now = time.time()
        if self._folder_cache and now - self._folder_cache_ts < 300:
            return self._folder_cache
        cache: Dict[str, Any] = {}
        try:
            for folder in account.msg_folder_root.walk():
                if getattr(folder, "id", None):
                    cache[folder.id] = folder
                try:
                    path = "/".join(
                        p.name for p in folder.parts[2:]  # drop root/Top of Info Store
                    ) or folder.name
                except Exception:
                    path = folder.name
                cache[path.lower()] = folder
        except Exception as e:
            logger.warning("folder walk failed: %s", e)
        if cache:
            self._folder_cache = cache
            self._folder_cache_ts = now
        return cache

    def resolve_folder(self, account: Account, ref: Optional[str], aliaser) -> Any:
        """well-known alias | folder alias (f12) | path | raw id → Folder (sync)."""
        if not ref:
            return account.inbox
        key = ref.strip()
        attr = WELL_KNOWN.get(key.lower()) or WELL_KNOWN.get(f"f:{key.lower()}")
        if attr:
            return getattr(account, attr)
        try:
            key = aliaser.resolve(key)  # f12 → raw id; raw/path pass through
        except KeyError as e:
            raise ToolError("validation", str(e.args[0] if e.args else e))
        cache = self._folder_map(account)
        folder = cache.get(key) or cache.get(key.lower())
        if folder is None:
            raise ToolError(
                "not_found", f"No folder matches {ref!r}.",
                hint="Use list_folders and pass one of its ids or paths.",
            )
        return folder


def paginate(query: Any, *, offset: int, limit: int,
             chunk: int = 50) -> Tuple[List[Any], Optional[int]]:
    """Materialize query[offset:offset+limit] in chunks (sync, raises on
    mid-iteration failure — the caller's error mapper classifies it).

    Returns ``(items, next_offset)``. NEVER calls ``QuerySet.count()`` —
    in exchangelib that iterates every matching id server-side, so a 20k
    inbox paid ~20k ids of round trips on every "read 10 emails". Whether
    another page exists comes from a one-item lookahead instead; callers
    that want an exact total use a refreshed ``folder.total_count`` (only
    valid for unfiltered listings) or a local mirror count.
    """
    offset = max(0, offset)
    limit = max(0, limit)
    lookahead = limit + 1
    items: List[Any] = []
    cursor = offset
    chunk = max(1, min(chunk, 250))
    while len(items) < lookahead:
        want = min(chunk, lookahead - len(items))
        batch = list(query[cursor:cursor + want])
        if not batch:
            break
        items.extend(batch)
        cursor += len(batch)
        if len(batch) < want:
            break
    next_offset = offset + limit if len(items) > limit else None
    return items[:limit], next_offset
