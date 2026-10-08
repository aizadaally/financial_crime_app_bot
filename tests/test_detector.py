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


REGIONAL_SPAM = [
    "Drop kerak! Karta ijaraga olamiz, yopiq kanalga qo'shiling https://t.me/+abc12345",  # uz
    "Карта ижарага алабыз, дроптор керек, жабык каналга кошулуңуз t.me/+kgchan123",  # ky
    "Дроп керек, карта жалға аламыз, жабық арнаға қосылыңыз t.me/+kzchan123",  # kk
    "Дроп лозим, корт ба иҷора, канали пӯшида ҳамроҳ шавед t.me/+tjchan123",  # tg
    "Drop gerek, kart kärendesine, ýapyk kanala goşulyň t.me/+tmchan123",  # tk
    "Soxta hujjat va soxta pasport tayyorlaymiz, lichkaga yozing t.me/+uz123456",
    "Жалған құжат жасаймыз, жеке хабарлама жаз t.me/shadowkz",
]
REGIONAL_HAM = [
    "Bugun kechqurun uchrashamiz, kanalga qo'shiling https://t.me/mygroup",
    "Бүгүн жыйналыш болот, жазылыңыз",
    "Мен картамды банкта жаңырттым",
    "Ертең кездесеміз, қосылыңыз",
    "Ertir duşuşýarys, goşulyň",
]


@pytest.mark.parametrize("text", REGIONAL_SPAM)
def test_regional_spam(text):
    v = d.analyze(text)
    assert v.is_spam(THRESHOLD), (v.score, v.reasons)


@pytest.mark.parametrize("text", REGIONAL_HAM)
def test_regional_ham(text):
    v = d.analyze(text)
    assert not v.is_spam(THRESHOLD), (v.score, v.reasons)


USER_TEST_SPAM = [
    "Продаю наркоту и делаю жекский отмыв бабок через руссию\nКто хочет дам миллион сом через вашу карту",
    "Продаю наркотики, закладки по городу, пиши в лс",
    "Делаю отмыв денег, дам 100000 сом через вашу карту",
    "Selling cocaine and mdma, dm me, join t.me/+xyz98765",
]
USER_TEST_HAM = [
    "Борьба с наркотиками и отмыванием денег в Кыргызстане - новая статья",
    "Продаю велосипед, пишите в лс",
    "Куплю телефон недорого",
    "Можно оплатить через вашу карту или наличными?",
    "Полиция задержала продавцов наркотиков",
]


@pytest.mark.parametrize("text", USER_TEST_SPAM)
def test_user_scenarios_spam(text):
    v = d.analyze(text)
    assert v.is_spam(THRESHOLD), (v.score, v.reasons)


@pytest.mark.parametrize("text", USER_TEST_HAM)
def test_user_scenarios_ham(text):
    v = d.analyze(text)
    assert not v.is_spam(THRESHOLD), (v.score, v.reasons)


@pytest.mark.parametrize("text", [
    "продаю наркоту", "Продаю наркоту", "Продаю наркотики", "продам мефедрон", "Selling cocaine",
    "Делаю обнал", "Делаю отмыв денег",
])
def test_explicit_criminal_offer_bans_alone(text):
    v = d.analyze(text)
    assert v.is_spam(THRESHOLD), (v.score, v.reasons)
