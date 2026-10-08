import asyncio

from bot.history import ScoreHistory
from tests.test_handler import make_bot, make_cfg, make_msg  # noqa: E402
from bot.detector import Detector
from bot.main import handle


def test_scores_add_up_inside_the_window():
    h = ScoreHistory(600)
    assert h.total(1, 7, 2, now=0) == 2
    assert h.total(1, 7, 1, now=60) == 3      # earlier 2 + now 1


def test_expired_and_other_users_and_other_chats_do_not_count():
    h = ScoreHistory(600)
    h.total(1, 7, 3, now=0)
    assert h.total(1, 7, 1, now=700) == 1     # window over
    assert h.total(1, 8, 1, now=10) == 1      # other user
    assert h.total(2, 7, 1, now=10) == 1      # other chat


def test_weak_messages_never_build_up():
    h = ScoreHistory(600, min_score=2)
    for t in range(10):
        assert h.total(1, 7, 1, now=t) == 1


def test_memory_is_bounded():
    h = ScoreHistory(600, max_users=3)
    for u in range(10):
        h.total(1, u, 3, now=0)
    assert len(h._data) <= 3


def _run(texts, history, user_id=7, **cfg):
    bot = make_bot()
    msgs = []
    for t in texts:
        m = make_msg(t, user_id=user_id)
        msgs.append(m)
        asyncio.run(handle(m, bot, make_cfg(ban_score=3, **cfg), Detector(), None, history))
    return bot, msgs


def test_scam_split_over_two_messages_is_banned_on_the_second():
    bot, msgs = _run(["Легкая работа", "За час 500 тысяч тг"], ScoreHistory(600))
    assert bot.ban_chat_member.await_count == 1
    msgs[0].delete.assert_not_awaited()
    msgs[1].delete.assert_awaited_once()


def test_same_messages_from_two_different_people_are_not_combined():
    bot = make_bot()
    h = ScoreHistory(600)
    for uid, t in ((1, "Легкая работа"), (2, "За час 500 тысяч тг")):
        asyncio.run(handle(make_msg(t, user_id=uid), bot, make_cfg(ban_score=3), Detector(), None, h))
    bot.ban_chat_member.assert_not_awaited()


def test_without_history_split_messages_are_not_combined():
    bot, _ = _run(["Легкая работа", "За час 500 тысяч тг"], None)
    bot.ban_chat_member.assert_not_awaited()
