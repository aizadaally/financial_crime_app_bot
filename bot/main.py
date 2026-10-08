from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.types import Message

from .config import Config, load_config
from .detector import Detector

log = logging.getLogger("spambot")
ADMIN_STATUSES = {ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR}


def extract(message: Message) -> tuple[str, list[str]]:
    text = message.text or message.caption or ""
    entities = (message.entities or []) + (message.caption_entities or [])
    urls = [e.url for e in entities if e.type == "text_link" and e.url]
    # URLs typed directly are already in `text`; hidden ones live in entities.
    if message.reply_markup and getattr(message.reply_markup, "inline_keyboard", None):
        urls += [b.url for row in message.reply_markup.inline_keyboard for b in row if b.url]
    return text, urls


async def handle(message: Message, bot: Bot, cfg: Config, detector: Detector) -> None:
    user = message.from_user
    if user is None or user.is_bot or user.id in cfg.whitelist_user_ids:
        return
    # Anonymous admins / linked-channel posts have sender_chat; skip those.
    if message.sender_chat is not None:
        return

    text, urls = extract(message)
    verdict = detector.analyze(text, urls)
    if not verdict.is_spam(cfg.ban_score):
        return

    member = await bot.get_chat_member(message.chat.id, user.id)
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
        snippet = (text[:300] + "…") if len(text) > 300 else text
        report = (
            f"{'🧪 WOULD BAN (dry run)' if cfg.dry_run else '🚫 Banned'} {user.full_name} (id {user.id}) in {message.chat.title or message.chat.id}\n"
            f"Score {verdict.score}: {', '.join(verdict.reasons)}\n\n{snippet}"
        )
        try:
            await bot.send_message(cfg.log_chat_id, report, parse_mode=None)
        except Exception:
            log.exception("could not send report")


async def run() -> None:
    logging.basicConfig(level=logging.INFO)
    cfg = load_config()
    detector = Detector(cfg.allowed_domains, cfg.extra_rules_file)
    bot = Bot(cfg.token)
    dp = Dispatcher()
    groups = F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP})

    @dp.message(groups)
    @dp.edited_message(groups)
    async def _on_message(message: Message) -> None:
        await handle(message, bot, cfg, detector)

    await dp.start_polling(bot, allowed_updates=["message", "edited_message"])


if __name__ == "__main__":
    asyncio.run(run())
