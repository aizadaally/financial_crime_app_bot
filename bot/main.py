from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.types import ChatPermissions, LinkPreviewOptions, Message

from .config import Config, load_config
from .detector import Detector, is_warning_context

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


MUTED = ChatPermissions(
    can_send_messages=False, can_send_audios=False, can_send_documents=False, can_send_photos=False,
    can_send_videos=False, can_send_video_notes=False, can_send_voice_notes=False, can_send_polls=False,
    can_send_other_messages=False, can_add_web_page_previews=False,
)


async def punish(bot: Bot, cfg: Config, chat_id: int, user_id: int) -> None:
    """ban (default) removes the user; mute keeps them in the group but unable to write.
    With PUNISH_MINUTES > 0 Telegram lifts the punishment by itself when the time is up."""
    until = datetime.now(timezone.utc) + timedelta(minutes=cfg.punish_minutes) if cfg.punish_minutes else None
    try:
        if cfg.punishment == "mute":
            await bot.restrict_chat_member(chat_id, user_id, permissions=MUTED, until_date=until)
        else:
            await bot.ban_chat_member(chat_id, user_id, until_date=until, revoke_messages=True)
    except Exception:
        log.exception("%s failed (does the bot have the 'ban users' right?)", cfg.punishment)


async def handle(message: Message, bot: Bot, cfg: Config, detector: Detector, classifier=None) -> None:
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
    # Text that warns about crime (news, advice) needs a clearly higher score before it is punished.
    warning = is_warning_context(text)
    rule_ban = verdict.is_spam(cfg.ban_score + (2 if warning else 0))
    if not rule_ban and cfg.strict_mode:
        # Strict: any criminal subject bans, unless the text reads like a warning, news or advice.
        category = verdict.criminal_hit
        if category and not warning:
            rule_ban = True
            verdict.reasons.append(f"strict:{category}")
    ask_ai = (
        not rule_ban
        and classifier is not None
        and classifier.worth_asking(text, urls, verdict.score, cfg.ban_score)
    )
    if not rule_ban and not ask_ai:
        return

    try:
        member = await bot.get_chat_member(message.chat.id, user.id)
    except Exception:
        log.exception("could not verify sender status; not acting")
        return  # fail safe: never ban someone we could not check
    if member.status in ADMIN_STATUSES:
        return

    action = "ban" if rule_ban else None
    reasons = list(verdict.reasons)
    if ask_ai:
        ai = await classifier.classify(text)
        if cfg.log_all:
            log.info("AI verdict for user %s: %s", user.id, ai)
        if ai is not None and ai.is_scam and ai.confidence != "low":
            action = "ban" if ai.confidence == "high" else "delete"  # medium: remove the post, keep the user
            reasons.append(f"ai:{ai.category}/{ai.confidence}: {ai.reason}")
    if action is None:
        return

    log.info("%s%s from %s in %s score=%s %s", "[DRY RUN] " if cfg.dry_run else "", action, user.id,
             message.chat.id, verdict.score, reasons)
    if not cfg.dry_run:
        if cfg.delete_delay:
            await asyncio.sleep(cfg.delete_delay)  # demo mode: let the message stay visible briefly
        try:
            await message.delete()
        except Exception:
            log.exception("delete failed (does the bot have 'delete messages' right?)")
        if action == "ban":
            await punish(bot, cfg, message.chat.id, user.id)

    if cfg.log_chat_id:
        snippet = defang((text[:300] + "…") if len(text) > 300 else text)
        verb = {"ban": "Muted" if cfg.punishment == "mute" else "Banned", "delete": "Deleted message of"}[action]
        head = f"🧪 WOULD DO (dry run): {verb}" if cfg.dry_run else f"🚫 {verb}"
        report = (
            f"{head} {defang(user.full_name)} (id {user.id}) in {defang(str(message.chat.title or message.chat.id))}\n"
            f"Score {verdict.score}: {defang('; '.join(reasons))}\n\n{snippet}"
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
    classifier = None
    if cfg.ai_enabled:
        from .ai_classifier import AIClassifier

        classifier = AIClassifier(cfg.ai_model, cfg.ai_mode, cfg.ai_max_calls_per_minute)
    bot = Bot(cfg.token)
    dp = Dispatcher()
    groups = F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP})

    @dp.message(groups)
    @dp.edited_message(groups)
    async def _on_message(message: Message) -> None:
        await handle(message, bot, cfg, detector, classifier)

    me = await bot.get_me()
    log.info("Started as @%s | dry_run=%s | ban_score=%s | log_all=%s | strict=%s | ai=%s%s. Waiting for group messages...",
             me.username, cfg.dry_run, cfg.ban_score, cfg.log_all, cfg.strict_mode,
             "on" if classifier else "off", f" ({cfg.ai_model}, {cfg.ai_mode})" if classifier else "")
    await dp.start_polling(bot, allowed_updates=["message", "edited_message"])


if __name__ == "__main__":
    asyncio.run(run())
