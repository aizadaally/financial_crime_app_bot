from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _csv(name: str) -> set[str]:
    return {x.strip() for x in os.getenv(name, "").split(",") if x.strip()}


@dataclass(frozen=True)
class Config:
    token: str
    ban_score: int
    log_chat_id: int | None
    allowed_domains: set[str]
    whitelist_user_ids: set[int]
    extra_rules_file: str | None
    dry_run: bool


def load_config() -> Config:
    load_dotenv()
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("BOT_TOKEN is not set (see .env.example)")
    log_chat = os.getenv("LOG_CHAT_ID", "").strip()
    return Config(
        token=token,
        ban_score=int(os.getenv("BAN_SCORE", "4")),
        log_chat_id=int(log_chat) if log_chat else None,
        allowed_domains=_csv("ALLOWED_DOMAINS"),
        whitelist_user_ids={int(x) for x in _csv("WHITELIST_USER_IDS")},
        extra_rules_file=os.getenv("EXTRA_RULES_FILE") or None,
        dry_run=os.getenv("DRY_RUN", "").strip().lower() in {"1", "true", "yes", "on"},
    )
