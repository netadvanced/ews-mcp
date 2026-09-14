"""Connection lifecycle manager — lazy, self-healing, never exits.

The corporate Exchange answers exchangelib's unauthenticated auth-type
probe unreliably for *fresh* connections ("Failed to get auth type from
service") while warm, long-lived processes keep working: exchangelib
probes once per process and caches the negotiated auth type. Startup
therefore must never gate on a successful connection. Tools register and
transports bind immediately; this manager keeps trying in the background
with exponential backoff + full jitter until Exchange answers, and keeps
state observable via ``/readyz`` and ``whoami``.

States:
    connecting  — never connected since process start; warmup loop running
    warm        — last probe/connect succeeded
    degraded    — was warm, a later heartbeat failed; warmup loop re-armed
    auth_failed — login rejected with EWS_AUTH_FAIL_FAST on; no more attempts
"""

import asyncio
import logging
import random
import threading
import time
from collections.abc import Callable, Coroutine
from typing import Any

STATE_CONNECTING = "connecting"
STATE_WARM = "warm"
STATE_DEGRADED = "degraded"
STATE_AUTH_FAILED = "auth_failed"

# After this many consecutive failures, escalate the recovery ladder:
# drop the cached Account/Protocol so the next attempt re-runs the full
# auth negotiation on a fresh session instead of reusing a wedged one.
_RESET_EVERY_N_FAILURES = 3


class ConnectionManager:
    """Owns the background warmup/heartbeat lifecycle for one EWSClient."""

    def __init__(
        self,
        ews_client,
        initial_backoff: float = 1.0,
        max_backoff: float = 300.0,
        heartbeat_seconds: int = 600,
    ):
        self._client = ews_client
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._heartbeat_seconds = heartbeat_seconds
        self.logger = logging.getLogger(__name__)

        # Status fields are read from the event loop (readyz/whoami) and
        # written from worker threads — guard with a plain lock.
        self._lock = threading.Lock()
        self._state = STATE_CONNECTING
        self._attempts = 0
        self._last_error: str | None = None
        self._last_success_ts: float | None = None
        self._next_retry_ts: float | None = None

        self._task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._stopped = False
        self._on_warm: Callable[[], Coroutine[Any, Any, None]] | None = None
        self._on_warm_fired = False

    # ------------------------------------------------------------------ state

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def is_warm(self) -> bool:
        return self.state == STATE_WARM

    def status(self) -> dict[str, Any]:
        """Snapshot for /readyz and whoami. Never raises, never blocks on EWS."""
        with self._lock:
            now = time.time()
            return {
                "state": self._state,
                "attempts": self._attempts,
                "last_error": self._last_error,
                "last_success_age_s": (
                    int(now - self._last_success_ts)
                    if self._last_success_ts is not None
                    else None
                ),
                "next_retry_in_s": (
                    max(0, int(self._next_retry_ts - now))
                    if self._next_retry_ts is not None
                    and self._state != STATE_WARM
                    else None
                ),
            }

    # ------------------------------------------------------------- lifecycle

    async def start(
        self,
        on_warm: Callable[[], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Begin the background warmup loop. Returns immediately."""
        self._on_warm = on_warm
        self._task = asyncio.create_task(self._warmup_loop(), name="ews-warmup")

    async def stop(self) -> None:
        self._stopped = True
        for task in (self._task, self._heartbeat_task):
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    async def _warmup_loop(self) -> None:
        backoff = self._initial_backoff
        while not self._stopped:
            ok = await asyncio.to_thread(self._try_connect)
            if ok:
                self._mark_warm()
                await self._fire_on_warm()
                self._start_heartbeat()
                return
            if self._stop_on_auth_failure():
                return
            with self._lock:
                attempts = self._attempts
            # Recovery ladder: every Nth failure, drop the cached
            # Account/Protocol so the next try renegotiates auth on a
            # genuinely fresh session.
            if attempts % _RESET_EVERY_N_FAILURES == 0:
                try:
                    await asyncio.to_thread(self._client.reset)
                    self.logger.info(
                        "warmup: reset cached EWS session after %d failed attempts",
                        attempts,
                    )
                except Exception as exc:
                    self.logger.debug("warmup: session reset failed: %s", exc)
            # Full jitter: sleep U(0, backoff); cap growth at max_backoff.
            delay = random.uniform(0, backoff)
            with self._lock:
                self._next_retry_ts = time.time() + delay
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, self._max_backoff)

    def _try_connect(self) -> bool:
        """Blocking connect/probe attempt; runs in a worker thread."""
        try:
            ok = self._client.test_connection()
            if not ok:
                self._mark_failure(
                    getattr(self._client, "last_connection_error", None)
                    or "connection test returned False"
                )
            return ok
        except Exception as exc:
            self._mark_failure(f"{type(exc).__name__}: {exc}")
            return False

    # ------------------------------------------------------------- heartbeat

    def _start_heartbeat(self) -> None:
        if self._heartbeat_seconds <= 0 or self._stopped:
            return
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="ews-heartbeat"
        )

    async def _heartbeat_loop(self) -> None:
        while not self._stopped:
            await asyncio.sleep(self._heartbeat_seconds)
            ok = await asyncio.to_thread(self._probe)
            if ok:
                self._mark_warm()
            elif self._stop_on_auth_failure():
                return
            else:
                with self._lock:
                    self._state = STATE_DEGRADED
                self.logger.warning(
                    "heartbeat: EWS probe failed — state=degraded, re-arming warmup"
                )
                # Re-enter the warmup loop (which restarts the heartbeat on
                # success). Exit this heartbeat; warmup owns recovery now.
                self._task = asyncio.create_task(
                    self._warmup_loop(), name="ews-warmup"
                )
                return

    def _probe(self) -> bool:
        """Cheap liveness probe against the cached account."""
        try:
            account = getattr(self._client, "_account", None)
            if account is None:
                return self._client.test_connection()
            self._client._run(lambda: account.root.refresh())
            return True
        except Exception as exc:
            self._mark_failure(f"{type(exc).__name__}: {exc}")
            return False

    # --------------------------------------------------------------- helpers

    def _stop_on_auth_failure(self) -> bool:
        # Retrying a rejected password only adds failed logins on the
        # account, so the loop ends here instead of backing off.
        reason = getattr(self._client, "auth_failed", None)
        if not reason:
            return False
        with self._lock:
            self._state = STATE_AUTH_FAILED
            self._next_retry_ts = None
        self.logger.error("EWS login rejected, warmup stopped: %s", reason)
        return True

    def _mark_warm(self) -> None:
        with self._lock:
            previous = self._state
            self._state = STATE_WARM
            self._last_success_ts = time.time()
            self._next_retry_ts = None
            self._last_error = None
        if previous != STATE_WARM:
            self.logger.info("EWS connection established (state=warm)")

    def _mark_failure(self, error: str) -> None:
        with self._lock:
            self._attempts += 1
            self._last_error = error[:500]

    async def _fire_on_warm(self) -> None:
        """Run the on-warm callback exactly once per process."""
        if self._on_warm is None or self._on_warm_fired:
            return
        self._on_warm_fired = True
        try:
            await self._on_warm()
        except Exception as exc:
            self.logger.warning("on_warm callback failed: %s", exc)
