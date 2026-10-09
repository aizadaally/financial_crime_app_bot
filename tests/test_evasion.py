"""Disguised scams must still be caught; disguised-looking *normal* text must not be."""
import time

import pytest

from bot.detector import Detector, is_warning_context

d = Detector()


def acted(text):
    """Same decision the bot makes with BAN_SCORE=3 and STRICT_MODE on."""
    v = d.analyze(text)
    warning = is_warning_context(text)
    return v.score >= 3 + (2 if warning else 0) or bool(v.criminal_hit and not warning)


EVASIVE = [
    # spaced / dotted letters
    "П р о д а ю  н а р к о т у", "Н у ж н ы  д р о п ы", "п.р.о.б.и.в по базам", "д-р-о-п-ы нужны", "О б н а л",
    # leetspeak
    "Продаю нарк0ту", "Нужны др0пы", "Пр0бив по базам", "0бнал делаю", "Данные карты ск1нь",
    # look-alike Latin letters
    "Прoдaю нapкoту", "Нужны дрoпы", "Oбнaл делаю", "Пpoбив по базам",
    # repeated letters
    "Продаююю наркотууу", "Нужны дропыыы", "Обналлл делаю",
    # Russian typed in Latin letters
    "Prodayu narkotu", "Nuzhny dropy", "Probiv po bazam", "Dannye karty skin", "Delayu obnal",
    # emoji / symbols between words and letters
    "Продаю 💊 наркоту", "Нужны 💰 дропы", "Про*дам нар*коту", "Обн@л делаю",
    # Uzbek written in Cyrillic
    "Гиёҳванд сотаман", "Дроп керак, карта ижарага оламиз", "Банк картасини сотиб оламиз",
]

NORMAL_LOOKALIKES = [
    "Prodayu mashinu, 5000 dollar", "Segodnya vyezzhayu v Karakol v 8 utra", "Privet, kak dela? Chto novogo?",
    "Prodayu kvartiru v Bishkeke", "Nuzhen voditel Bishkek Karakol", "Spasibo bolshoe, vse prishlo",
    "Я читал статью про борьбу с обналом и дропами в банках", "Привет, как дела?", "Выезжаю в 8 утра, 700 сом",
    "Mening ismim Ali, men Toshkentdanman", "Мен үйгө бара жатам", "1 2 3 4 5 тест", "a b c d e",
    "Цена: 5000 сом, звоните 0555 123 456", "Сдаю квартиру на 3 месяца, 25000 сом",
]


@pytest.mark.parametrize("text", EVASIVE)
def test_disguised_scam_is_caught(text):
    assert acted(text), (text, d.analyze(text).reasons)


@pytest.mark.parametrize("text", NORMAL_LOOKALIKES)
def test_normal_text_is_not_flagged(text):
    assert not acted(text), (text, d.analyze(text).score, d.analyze(text).reasons)


@pytest.mark.parametrize("payload", [
    "п " * 4000, "п." * 4000, "a1 " * 2000, "prodayu " * 600, "а" * 8000, "💊" * 4000, "п р о д а ю  " * 600,
])
def test_variants_stay_fast_on_hostile_input(payload):
    start = time.perf_counter()
    d.analyze(payload)
    assert time.perf_counter() - start < 1.5
