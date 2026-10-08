import pytest

from bot.detector import Detector

d = Detector(allowed_domains={"mygroup"})
THRESHOLD = 4

SPAM = [
    "Ищем дропов! Обнал, высокий процент. Пиши в лс https://t.me/+AbCdEf123",
    "Кардинг обучение, cvv fullz, вступай в закрытый чат t.me/joinchat/XyZ12345",
    "К а р д и н г + обнал, заходи https://t.me/shadowcash",
    "Need drops and money mules, cash-out service, join t.me/+abcdef",
    "Пробив по базам, левые карты, пиши в лс @someone t.me/probiv_bot",
    "Cаrding (latin c/a/r) cvv dumps, join https://t.me/+secret123",
]
HAM = [
    "Привет всем, как дела?",
    "Check out our group https://t.me/mygroup",
    "Нужен совет по ипотеке, какой банк лучше?",
    "Join us for the meetup tomorrow at 6pm",
    "Я читал статью про борьбу с обналом и дропами в банках",  # discussion, one weak-ish hit
]


@pytest.mark.parametrize("text", SPAM)
def test_spam_detected(text):
    v = d.analyze(text)
    assert v.is_spam(THRESHOLD), (v.score, v.reasons)


@pytest.mark.parametrize("text", HAM)
def test_ham_passes(text):
    v = d.analyze(text)
    assert not v.is_spam(THRESHOLD), (v.score, v.reasons)


def test_hidden_link_in_entity():
    v = d.analyze("Заходи, дропы нужны", ["https://t.me/+hiddenInvite1"])
    assert v.is_spam(THRESHOLD)
