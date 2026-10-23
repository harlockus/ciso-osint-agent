"""Load the API key from the environment or a local .env file."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from ciso_intel.textutil import classify_url

PLACEHOLDERS = {"", "your_api_key", "replace-me", "changeme", "xxx", "xai-your-key"}
EFFORTS = {"low", "medium", "high", "xhigh"}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    api_host: str
    model: str
    effort: str
    timeout: float
    collection_ids: list[str]
    mcp_servers: list[dict]
    env_file: Path | None
    env_warning: str | None

    @property
    def key_ready(self) -> bool:
        return bool(self.api_key)


def load_settings(env_file: Path | None = None, *, cwd: Path | None = None) -> Settings:
    root = cwd or Path.cwd()
    chosen = env_file
    if chosen is None:
        candidate = root / ".env"
        chosen = candidate if candidate.is_file() else None
    warning = None
    if chosen is not None:
        if not chosen.is_file():
            raise ConfigError(f"Env file not found: {chosen}")
        load_dotenv(chosen, override=False)
        mode = chosen.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            warning = f"{chosen} is readable by group or others. Run: chmod 600 {chosen}"
    key = _clean_key(os.environ.get("XAI_API_KEY"))
    effort = os.environ.get("CISO_INTEL_REASONING_EFFORT", "xhigh").strip().lower()
    if effort not in EFFORTS:
        raise ConfigError("CISO_INTEL_REASONING_EFFORT must be low, medium, high, or xhigh.")
    timeout = float(os.environ.get("CISO_INTEL_TIMEOUT_SECONDS", "3600"))
    if timeout < 30:
        raise ConfigError("CISO_INTEL_TIMEOUT_SECONDS must be at least 30.")
    return Settings(
        api_key=key,
        api_host=os.environ.get("XAI_API_HOST", "api.x.ai").strip() or "api.x.ai",
        model=os.environ.get("CISO_INTEL_MODEL", "grok-4.7").strip() or "grok-4.7",
        effort=effort,
        timeout=timeout,
        collection_ids=_csv(os.environ.get("XAI_COLLECTION_IDS", "")),
        mcp_servers=_mcp(os.environ.get("CISO_INTEL_MCP_CONFIG")),
        env_file=chosen if chosen is not None and chosen.is_file() else None,
        env_warning=warning,
    )


def require_key(settings: Settings) -> str:
    if not settings.api_key:
        raise ConfigError(
            "XAI_API_KEY is not set. Copy .env.example to .env, put the key from "
            "https://console.x.ai there, and keep that file out of git."
        )
    return settings.api_key


def redact(text: str, secret: str | None) -> str:
    if secret and secret in text:
        return text.replace(secret, "[redacted]")
    return text


def _clean_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = value.strip().strip('"').strip("'")
    if key.lower() in PLACEHOLDERS:
        return None
    return key


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _mcp(path_value: str | None) -> list[dict]:
    if not path_value:
        return []
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise ConfigError(f"CISO_INTEL_MCP_CONFIG does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"MCP config is not valid JSON: {path}") from exc
    if not isinstance(payload, list):
        raise ConfigError("MCP config must be a JSON list of servers.")
    servers: list[dict] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ConfigError(f"MCP server {index} must be an object.")
        url = str(item.get("server_url") or "").strip()
        decision = classify_url(url)
        if not url.startswith("https://") or decision != "ok":
            raise ConfigError(f"MCP server {index} must be a public https URL ({decision}).")
        servers.append(
            {
                "server_url": url,
                "server_label": str(item.get("server_label") or f"mcp{index}").strip(),
                "server_description": item.get("server_description") or None,
                "allowed_tool_names": item.get("allowed_tool_names") or None,
                "authorization": item.get("authorization") or None,
            }
        )
    return servers
