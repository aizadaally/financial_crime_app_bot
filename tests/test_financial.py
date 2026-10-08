import pytest

from bot.detector import Detector

d = Detector()
T = 4

SCAM = {
    "invest-ru": "Инвестиции в крипту! Гарантированный доход 5% в день, удвоим депозит за неделю. Пиши в лс t.me/+AbCdEf123",
    "invest-en": "Crypto trading signals, guaranteed profit 10% daily, double your money! join t.me/+abc12345",
    "wallet": "Connect your wallet to claim your airdrop, enter your seed phrase to verify",
    "loan-ru": "Кредит без отказа и проверки, одобрение 100%! Нужна предоплата за оформление кредита",
    "bank-ru": "Здравствуйте, я из службы безопасности банка. Ваш счёт заблокирован, переведите деньги на безопасный счёт",
    "bank-phish": "Your account has been suspended. Click the link to verify your identity: https://bit.ly/3abcd",
    "prize-ru": "Поздравляем, вы выиграли приз! Для получения приза оплатите комиссию 500 сом t.me/+prize1234",
    "task-ru": "Зарабатывай на телефоне! Лайки и просмотры, платим за каждое задание, лёгкие деньги, пиши в лс",
    "pyramid-ru": "Сетевой маркетинг, пассивный доход, приводи друзей и получай бонусы https://t.me/+pyramid77",
    "casino": "Казино 1xbet промокод BONUS500, ставки на спорт https://t.me/+bets12345",
    "buy-account": "Куплю банковские карты и аккаунты банка, дорого, пиши в лс t.me/+buy123456",
    "kk": "Инвестиция салыңыз, пассивті табыс, ұтып алдыңыз! t.me/+kkinvest1",
    "ky": "Инвестиция салыңыз, пассивдүү киреше, утуп алдыңыз! t.me/+kyinvest1",
    "uz": "Investitsiya kiriting, passiv daromad, yutib oldingiz! t.me/+uzinvest1",
}

NORMAL = {
    "forex-talk": "Кто-нибудь разбирается в форексе? Хочу понять как это работает",
    "bank-news": "В новостях пишут, что мошенники звонят от имени службы безопасности банка. Будьте осторожны",
    "seed-warning": "Никогда не сообщайте seed phrase никому, это мошенники",
    "loan-question": "Подскажите, в каком банке лучше взять кредит на машину?",
    "casino-news": "Закрыли онлайн казино в Бишкеке, говорят нелегальное",
    "giveaway-legit": "Розыгрыш приза среди участников чата завтра в 18:00",
    "mlm-talk": "Мой друг попал в сетевой маркетинг, как ему помочь выйти?",
    "ride": "Выезжаю в Каракол завтра в 8:00, есть 2 места, 700 сом",
    "rent": "Сдаётся 2-комнатная квартира, 30000 сом в месяц, звоните",
    "sim-legit": "Куплю сим-карту Мегаком, у кого есть лишняя?",
    "short-link": "Вот ссылка на карту: https://bit.ly/3abcd",
}


@pytest.mark.parametrize("name", SCAM)
def test_financial_scam_caught(name):
    v = d.analyze(SCAM[name])
    assert v.is_spam(T), (name, v.score, v.reasons)


@pytest.mark.parametrize("name", NORMAL)
def test_normal_not_banned(name):
    v = d.analyze(NORMAL[name])
    assert not v.is_spam(T), (name, v.score, v.reasons)
