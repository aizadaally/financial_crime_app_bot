from __future__ import annotations

import os
import re
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
    allowed_chat_ids: set[int]
    log_all: bool = False
    delete_delay: float = 0.0
    ai_enabled: bool = False
    ai_mode: str = "suspicious"
    ai_model: str = "claude-opus-5-5"
    ai_max_calls_per_minute: int = 30
    punishment: str = "ban"
    strict_mode: bool = False
    context_window_minutes: int = 10
    punish_minutes: int = 0


def load_config() -> Config:
    load_dotenv()
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("BOT_TOKEN is not set (see .env.example)")
    if not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{30,}", token):
        raise SystemExit("BOT_TOKEN does not look like a Telegram bot token (expected 123456:ABC...)")
    log_chat = os.getenv("LOG_CHAT_ID", "").strip()
    try:
        ban_score = int(os.getenv("BAN_SCORE", "4"))
        log_chat_id = int(log_chat) if log_chat else None
        whitelist = {int(x) for x in _csv("WHITELIST_USER_IDS")}
        allowed_chats = {int(x) for x in _csv("ALLOWED_CHAT_IDS")}
        delete_delay = max(0.0, min(float(os.getenv("DELETE_DELAY_SECONDS", "0") or 0), 30.0))
    except ValueError as e:
        raise SystemExit(f"Invalid number in .env: {e}")
    ai_enabled = os.getenv("AI_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
    ai_mode = (os.getenv("AI_MODE", "suspicious").strip().lower() or "suspicious")
    if ai_mode not in {"suspicious", "borderline", "all"}:
        raise SystemExit("AI_MODE must be suspicious, borderline or all")
    try:
        ai_max_calls = max(1, int(os.getenv("AI_MAX_CALLS_PER_MINUTE", "30") or 30))
    except ValueError:
        raise SystemExit("AI_MAX_CALLS_PER_MINUTE must be a number")
    if ai_enabled and not os.getenv("ANTHROPIC_API_KEY", "").strip():
        raise SystemExit("AI_ENABLED=true needs ANTHROPIC_API_KEY in .env (or set AI_ENABLED=false)")
    punishment = (os.getenv("PUNISHMENT", "ban").strip().lower() or "ban")
    if punishment not in {"ban", "mute"}:
        raise SystemExit("PUNISHMENT must be ban or mute")
    try:
        punish_minutes = int(os.getenv("PUNISH_MINUTES", "0") or 0)
    except ValueError:
        raise SystemExit("PUNISH_MINUTES must be a whole number of minutes")
    if not (punish_minutes == 0 or 1 <= punish_minutes <= 366 * 24 * 60):
        raise SystemExit("PUNISH_MINUTES must be 0 (permanent) or between 1 and 527040")
    try:
        context_window = max(0, min(int(os.getenv("CONTEXT_WINDOW_MINUTES", "10") or 0), 120))
    except ValueError:
        raise SystemExit("CONTEXT_WINDOW_MINUTES must be a whole number (0 = off)")
    if ban_score < 1:
        raise SystemExit("BAN_SCORE must be at least 1")
    return Config(
        token=token,
        ban_score=ban_score,
        log_chat_id=log_chat_id,
        allowed_domains=_csv("ALLOWED_DOMAINS"),
        whitelist_user_ids=whitelist,
        allowed_chat_ids=allowed_chats,
        delete_delay=delete_delay,
        context_window_minutes=context_window,
        strict_mode=os.getenv("STRICT_MODE", "").strip().lower() in {"1", "true", "yes", "on"},
        punishment=punishment,
        punish_minutes=punish_minutes,
        ai_enabled=ai_enabled,
        ai_mode=ai_mode,
        ai_model=os.getenv("AI_MODEL", "").strip() or "claude-opus-5-5",
        ai_max_calls_per_minute=ai_max_calls,
        log_all=os.getenv("LOG_ALL", "").strip().lower() in {"1", "true", "yes", "on"},
        extra_rules_file=os.getenv("EXTRA_RULES_FILE") or None,
        dry_run=os.getenv("DRY_RUN", "").strip().lower() in {"1", "true", "yes", "on"},
    )
