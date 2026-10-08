import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

from bot.config import Config
from bot.detector import Detector
from bot.main import handle

SPAM = "Ищем дропов, обнал! Пиши в лс https://t.me/+AbCdEf123"


def make_cfg(**kw):
    base = dict(token="x", ban_score=4, log_chat_id=999, allowed_domains=set(), whitelist_user_ids=set(),
                extra_rules_file=None, dry_run=False, allowed_chat_ids=set())
    base.update(kw)
    return Config(**base)


def make_msg(text=SPAM, user_id=1, chat_id=-100, sender_chat=None, is_bot=False):
    m = MagicMock()
    m.text, m.caption, m.entities, m.caption_entities, m.reply_markup = text, None, None, None, None
    m.from_user = NS(id=user_id, is_bot=is_bot, full_name="Evil @user")
    m.chat = NS(id=chat_id, title="My Group")
    m.sender_chat = sender_chat
    m.delete = AsyncMock()
    return m


def make_bot(status="member"):
    bot = MagicMock()
    bot.get_chat_member = AsyncMock(return_value=NS(status=status))
    for name in ("ban_chat_member", "send_message", "leave_chat"):
        setattr(bot, name, AsyncMock())
    return bot


def run(msg, bot, cfg):
    asyncio.run(handle(msg, bot, cfg, Detector()))


def test_spam_is_deleted_banned_and_reported_defanged():
    msg, bot = make_msg(), make_bot()
    run(msg, bot, make_cfg())
    msg.delete.assert_awaited_once()
    bot.ban_chat_member.assert_awaited_once()
    report = bot.send_message.await_args.args[1]
    assert "t.me" not in report and "https://" not in report and "@" not in report
    assert bot.send_message.await_args.kwargs["link_preview_options"].is_disabled


def test_dry_run_does_nothing_but_reports():
    msg, bot = make_msg(), make_bot()
    run(msg, bot, make_cfg(dry_run=True))
    msg.delete.assert_not_awaited()
    bot.ban_chat_member.assert_not_awaited()
    assert "dry run" in bot.send_message.await_args.args[1]


def test_admin_is_never_touched():
    for status in ("administrator", "creator"):
        msg, bot = make_msg(), make_bot(status)
        run(msg, bot, make_cfg())
        msg.delete.assert_not_awaited()
        bot.ban_chat_member.assert_not_awaited()


def test_normal_message_is_ignored():
    msg, bot = make_msg("Привет, как дела?"), make_bot()
    run(msg, bot, make_cfg())
    msg.delete.assert_not_awaited()
    bot.get_chat_member.assert_not_awaited()


def test_whitelist_bot_and_channel_senders_skipped():
    for msg in (make_msg(user_id=5), make_msg(is_bot=True), make_msg(sender_chat=object())):
        bot = make_bot()
        run(msg, bot, make_cfg(whitelist_user_ids={5}))
        msg.delete.assert_not_awaited()


def test_cannot_verify_sender_means_no_action():
    msg, bot = make_msg(), make_bot()
    bot.get_chat_member = AsyncMock(side_effect=RuntimeError("telegram down"))
    run(msg, bot, make_cfg())
    msg.delete.assert_not_awaited()
    bot.ban_chat_member.assert_not_awaited()


def test_unapproved_chat_is_left_without_moderating():
    msg, bot = make_msg(chat_id=-555), make_bot()
    run(msg, bot, make_cfg(allowed_chat_ids={-100}))
    bot.leave_chat.assert_awaited_once_with(-555)
    msg.delete.assert_not_awaited()
    bot.ban_chat_member.assert_not_awaited()


def test_delete_delay_waits_then_acts(monkeypatch):
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    monkeypatch.setattr("bot.main.asyncio.sleep", fake_sleep)
    msg, bot = make_msg(), make_bot()
    run(msg, bot, make_cfg(delete_delay=3.0))
    assert slept == [3.0]
    msg.delete.assert_awaited_once()
    bot.ban_chat_member.assert_awaited_once()
