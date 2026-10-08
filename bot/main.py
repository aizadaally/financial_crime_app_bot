from __future__ import annotations

import asyncio
import logging
import re

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.types import LinkPreviewOptions, Message

from .config import Config, load_config
from .detector import Detector

log = logging.getLogger("spambot")
ADMIN_STATUSES = {ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR}


def defang(text: str) -> str:
    """Make links/mentions in a report non-clickable so admins can't tap into a criminal chat by accident."""
    text = re.sub(r"(?i)https?://", "hxxp://", text)
    text = re.sub(r"(?i)\b(t(?:elegram)?)\.(me|dog)\b", r"\1[.]\2", text)
    text = re.sub(r"(?i)tg://", "tg[:]//", text)
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return text.replace("@", "(at)")


def extract(message: Message) -> tuple[str, list[str]]:
    text = message.text or message.caption or ""
    entities = (message.entities or []) + (message.caption_entities or [])
    urls = [e.url for e in entities if e.type == "text_link" and e.url]
    # URLs typed directly are already in `text`; hidden ones live in entities.
    if message.reply_markup and getattr(message.reply_markup, "inline_keyboard", None):
        urls += [b.url for row in message.reply_markup.inline_keyboard for b in row if b.url]
    return text, urls


async def handle(message: Message, bot: Bot, cfg: Config, detector: Detector) -> None:
    if cfg.allowed_chat_ids and message.chat.id not in cfg.allowed_chat_ids:
        # Someone added the bot to a chat the owner did not approve: do nothing there and leave.
        log.warning("added to unapproved chat %s, leaving", message.chat.id)
        try:
            await bot.leave_chat(message.chat.id)
        except Exception:
            log.exception("could not leave chat")
        return
    user = message.from_user
    if user is None or user.is_bot or user.id in cfg.whitelist_user_ids:
        return
    # Anonymous admins / linked-channel posts have sender_chat; skip those.
    if message.sender_chat is not None:
        return

    text, urls = extract(message)
    verdict = detector.analyze(text, urls)
    if cfg.log_all:
        log.info("saw message in chat %s from user %s: score=%s", message.chat.id, user.id, verdict.score)
    if not verdict.is_spam(cfg.ban_score):
        return

    try:
        member = await bot.get_chat_member(message.chat.id, user.id)
    except Exception:
        log.exception("could not verify sender status; not acting")
        return  # fail safe: never ban someone we could not check
    if member.status in ADMIN_STATUSES:
        return

    log.info("%sspam from %s in %s score=%s %s", "[DRY RUN] " if cfg.dry_run else "", user.id, message.chat.id, verdict.score, verdict.reasons)
    if not cfg.dry_run:
        try:
            await message.delete()
        except Exception:
            log.exception("delete failed (does the bot have 'delete messages' right?)")
        try:
            await bot.ban_chat_member(message.chat.id, user.id, revoke_messages=True)
        except Exception:
            log.exception("ban failed (does the bot have 'ban users' right?)")

    if cfg.log_chat_id:
        snippet = defang((text[:300] + "…") if len(text) > 300 else text)
        report = (
            f"{'🧪 WOULD BAN (dry run)' if cfg.dry_run else '🚫 Banned'} {defang(user.full_name)} (id {user.id}) in {defang(str(message.chat.title or message.chat.id))}\n"
            f"Score {verdict.score}: {defang(', '.join(verdict.reasons))}\n\n{snippet}"
        )
        try:
            await bot.send_message(
                cfg.log_chat_id, report, parse_mode=None,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except Exception:
            log.exception("could not send report")


async def run() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("aiogram").setLevel(logging.WARNING)  # keep request details out of logs
    cfg = load_config()
    detector = Detector(cfg.allowed_domains, cfg.extra_rules_file)
    bot = Bot(cfg.token)
    dp = Dispatcher()
    groups = F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP})

    @dp.message(groups)
    @dp.edited_message(groups)
    async def _on_message(message: Message) -> None:
        await handle(message, bot, cfg, detector)

    me = await bot.get_me()
    log.info("Started as @%s | dry_run=%s | ban_score=%s | log_all=%s. Waiting for group messages...",
             me.username, cfg.dry_run, cfg.ban_score, cfg.log_all)
    await dp.start_polling(bot, allowed_updates=["message", "edited_message"])


if __name__ == "__main__":
    asyncio.run(run())
