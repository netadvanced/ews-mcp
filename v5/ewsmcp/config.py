"""Environment-driven configuration (12-factor; every knob defaults safe)."""

import re
from pathlib import Path
from typing import Literal, Optional

from exchangelib.version import VERSIONS
from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Path fragments that identify cloud-synced folders. The data dir holds
# mail-at-rest (alias DB, audit chain, cache mirror) — it must never ride
# a sync client onto other machines or a vendor cloud.
_SYNCED_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud")

# Exchange build number as in the X-OWA-Version header: 15.2.2562.43
_BUILD_RE = re.compile(r"[0-9]+(\.[0-9]+){3}")
# RequestServerVersion values exchangelib knows, e.g. Exchange2016
_API_VERSIONS = sorted({api_version for _, api_version, _ in VERSIONS})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # --- Exchange upstream -------------------------------------------------
    ews_server_url: str
    ews_email: str
    ews_username: Optional[str] = None
    ews_password: Optional[str] = None
    # NEVER pin auth_type against this Exchange: the front door only works
    # via exchangelib auto-negotiation (verified live 2026-06-12; pinning
    # BASIC/NTLM both fail). Escape hatch for a *different* server only.
    ews_auth_type_force: Optional[Literal["basic", "ntlm", "digest"]] = None
    # Pin the server version instead of letting exchangelib probe for it.
    # EWS_VERSION_BUILD is the Exchange build, e.g. "15.2.2562.43" (the
    # X-OWA-Version response header shows it). EWS_API_VERSION overrides the
    # RequestServerVersion sent on every request (e.g. "Exchange2016") for
    # servers that reject the one exchangelib derives from the build; it needs
    # EWS_VERSION_BUILD. Both unset = auto-detect, as before.
    ews_version_build: str | None = None
    ews_api_version: str | None = None
    ews_insecure_skip_verify: bool = False
    ews_tz: str = "Asia/Riyadh"
    request_timeout: int = 30

    # --- Reliability --------------------------------------------------------
    ews_warmup_max_backoff_seconds: int = 300
    ews_heartbeat_seconds: int = 600
    ews_retry_max_wait_seconds: int = 300
    # exchangelib's FaultTolerance treats HTTP 401 as "server busy" and keeps
    # retrying. Against an AD account with a lockout policy a wrong password
    # then locks the account. When true, the first rejected login is final:
    # it is saved as DATA_DIR/auth_blocked.json and stays in force across
    # restarts until the username or password changes.
    ews_auth_fail_fast: bool = False
    ews_max_concurrency: int = 4
    circuit_failure_threshold: int = 5
    circuit_open_seconds: int = 60

    # --- Safety -------------------------------------------------------------
    ews_capability_tier: Literal["read", "draft", "full"] = "draft"
    send_enabled: bool = False  # kill-switch: v5 defaults SAFE (off)
    send_confirm_secret: Optional[str] = None
    confirm_ttl_seconds: int = 600  # ONE default everywhere (== confirm.DEFAULT_TTL_SECONDS)
    ews_recipient_allowlist: str = ""
    ews_recipient_denylist: str = ""
    ews_max_sends_per_hour: int = 10

    # --- Serving ------------------------------------------------------------
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    mcp_api_key: Optional[str] = None
    log_level: str = "INFO"

    # --- Storage (NEVER a synced folder) -------------------------------------
    data_dir: str = ""  # empty → ~/.ewsmcp; always resolved to an absolute path
    data_dir_allow_synced: bool = False  # explicit opt-out of the synced-path guard

    # --- Cache mirror (cache-first reads; false = pure EWS, fully functional)
    ews_cache_enabled: bool = True
    ews_cache_folders: str = "inbox,sent"
    ews_cache_sync_seconds: int = 45
    ews_cache_hierarchy_seconds: int = 600
    ews_cache_window_days: int = 365
    ews_cache_purge_on_boot: bool = False  # admin path: wipe + resync from scratch

    # --- Optional semantic tier (adapter; core stays dependency-free) --------
    ews_semantic_index: Literal["none", "pgvector"] = "none"
    ews_semantic_pg_dsn: Optional[str] = None  # from env only, never committed
    ews_semantic_ollama_url: str = "http://localhost:11434"
    ews_semantic_model: str = "bge-m3"  # 1024-d, Arabic-capable

    # --- Response economy ----------------------------------------------------
    default_page_size: int = Field(default=20, le=50)
    body_max_chars: int = 4000

    @model_validator(mode="after")
    def _resolve_data_dir(self) -> "Settings":
        raw = self.data_dir or str(Path.home() / ".ewsmcp")
        resolved = Path(raw).expanduser().resolve()
        if not self.data_dir_allow_synced:
            lowered = str(resolved).lower()
            marker = next((m for m in _SYNCED_MARKERS if m in lowered), None)
            if marker is not None:
                raise ValueError(
                    f"DATA_DIR {resolved} appears to be inside a cloud-synced "
                    f"folder ({marker!r}). It stores mail-at-rest (aliases, "
                    "audit chain, cache) and must stay local — point DATA_DIR "
                    "at a local path, or set DATA_DIR_ALLOW_SYNCED=true to "
                    "accept the risk deliberately."
                )
        self.data_dir = str(resolved)
        return self

    # Field validators rather than a model validator: pydantic's error message
    # then echoes only the offending value, not every setting (password included).
    @field_validator("ews_version_build")
    @classmethod
    def _check_version_build(cls, build: str | None) -> str | None:
        build = (build or "").strip() or None  # blank in .env means unset
        if build is not None and (not _BUILD_RE.fullmatch(build) or int(build.split(".")[0]) < 8):
            raise ValueError(
                f"EWS_VERSION_BUILD={build!r} is not an Exchange build number. Expected "
                "major.minor.build.revision with a major version of 8 or later, "
                "e.g. 15.2.2562.43."
            )
        return build

    @field_validator("ews_api_version")
    @classmethod
    def _check_api_version(cls, api_version: str | None, info: ValidationInfo) -> str | None:
        api_version = (api_version or "").strip() or None
        if api_version is None:
            return None
        # Absent from info.data when EWS_VERSION_BUILD itself failed validation.
        if "ews_version_build" in info.data and info.data["ews_version_build"] is None:
            raise ValueError(
                "EWS_API_VERSION only works together with EWS_VERSION_BUILD. "
                "Set both, or unset EWS_API_VERSION to keep auto-detection."
            )
        if api_version not in _API_VERSIONS:
            raise ValueError(
                f"EWS_API_VERSION={api_version!r} is not a known EWS API version. "
                f"Use one of: {', '.join(_API_VERSIONS)}."
            )
        return api_version


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
