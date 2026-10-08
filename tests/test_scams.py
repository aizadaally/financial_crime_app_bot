import pytest

from bot.detector import Detector

d = Detector()
T = 4

SCAM = {
    # --- fake easy job ---
    "job-kk": "100% қауіпсіз жұмыс\nТәжірибе керек жоқ\nАптасына 100 мың тенге",
    "job-ru": "100% безопасная работа, без опыта, 5000 сом в день, пиши в лс",
    "job-en": "100% safe online job, no experience needed, earn $500 per week",
    "job-ky": "100% коопсуз жумуш, тажрыйба талап кылынбайт, жумасына 15000 сом",
    "job-uz": "100% xavfsiz ish, tajriba kerak emas, haftasiga 2000000 sum",
    "job-tg": "100% бехатар кор, таҷриба лозим нест, ҳар ҳафта 1500 сомони",
    "job-tk": "100% howpsuz iş, tejribe gerek däl, hepdede 500 manat",
    # --- card details / code phishing ---
    "card-ru": "Быстрее данные карты скинь",
    "card-ru2": "Срочно назови код из смс",
    "card-en": "Urgent, send me your card details and the SMS code",
    "card-kk": "Тезірек карта деректерін жібер",
    "card-ky": "Шашылыш карта маалыматын жөнөт",
    "card-uz": "Shoshilinch karta ma'lumotlarini yuboring",
    "card-tg": "Таъҷилӣ маълумоти кортро фиристед",
    "card-tk": "Gyssagly kart maglumatlaryny iber",
    # --- urgent borrow-money scam ---
    "borrow-ky": "Салам! Абдан шашылыш иш болуп калды. Картамдан акча өтпөй жатат, мага 2 саатка 5 000 сом берип тура аласыңбы? Азыр эле кайтарып берем",
    "borrow-ru": "Привет! Срочно, карта не работает, можешь одолжить 5000 сом? Верну сразу",
    "borrow-en": "Hi! Urgent, my card is not working, can you send me 5000 som? I'll pay you back right away",
    "borrow-kk": "Сәлем! Шұғыл, картам жұмыс істемей тұр, қарызға 5000 тенге бере аласың ба? Қайтарып беремін",
    "borrow-uz": "Salom! Shoshilinch, kartam ishlamay qoldi, 5000 so'm qarz berib tura olasizmi? Qaytarib beraman",
}

NORMAL = {
    "job-legit": "Требуется курьер, опыт не нужен, оплата 3000 сом в день. Звоните",
    "job-legit-ky": "Жумуш бар, тажрыйба талап кылынбайт, жумасына 10000 сом",
    "pay-details": "Скиньте реквизиты для оплаты, я переведу",
    "pay-number": "Отправьте номер карты, переведу за поездку",
    "borrow-polite": "Привет, одолжи 500 сом, верну вечером",
    "urgent-only": "Срочно нужен водитель Бишкек - Каракол",
    "ride": "Выезжаю в 8 утра, 2 места, 700 сом с человека",
    "greeting-ky": "Салам, баарына кутман таң!",
    "bank-talk": "Банк мне заблокировал карту, что делать?",
    "otp-warning": "Никому не сообщайте код из смс, это мошенники",
    "en-chat": "Can you send me the address? I will pay you tomorrow",
}


@pytest.mark.parametrize("name", SCAM)
def test_scam_caught(name):
    v = d.analyze(SCAM[name])
    assert v.is_spam(T), (name, v.score, v.reasons)


@pytest.mark.parametrize("name", NORMAL)
def test_normal_not_banned(name):
    v = d.analyze(NORMAL[name])
    assert not v.is_spam(T), (name, v.score, v.reasons)


# ---- real test messages from the user's group (23:08 and 22:34) ----
FROM_GROUP = {
    "crypto-teaser": ("Хотите крипту и бабки миллион долларов в день", 4),
    "tajik-borrow": ("Салом! Ин хеле таъчил аст. Кортам пул намегирад, 5000 сумро барои 2 соат дода метавонед? Ман онро фавран бармегардонам", 4),
    "easy-work-hour": ("Легкая работа\nЗа час 500 тысяч тг", 3),
}


@pytest.mark.parametrize("name", FROM_GROUP)
def test_messages_from_user_group(name):
    text, minimum = FROM_GROUP[name]
    v = d.analyze(text)
    assert v.score >= minimum, (name, v.score, v.reasons)


@pytest.mark.parametrize("text", ["Хотите чаю?", "Зарплата 3000 сом в час у них, это нормально?",
                                  "Выезжаю в 8 утра, 700 сом за место"])
def test_similar_normal_messages_stay_below_ban(text):
    assert not d.analyze(text).is_spam(3), text


def test_user_group_message_with_crypto_and_laundering():
    v = d.analyze("Дети кто хочет крипту и отмыв бабок")
    assert v.score >= 4 and v.criminal_hit == "laundering", (v.score, v.reasons)
