"""Per-language coverage: criminal messages are caught, ordinary chat is not (in all 7 languages)."""
import pytest

from bot.detector import Detector, is_warning_context

d = Detector()

CRIMINAL = [
    # Russian
    "Продаю наркотики, закладки по городу", "Нужны дропы, оплата сразу", "Куплю банковскую карту",
    "Делаю левые справки", "Скинь данные карты и код из смс", "Пробив по базам", "Гарантированный доход 5% в день",
    # English
    "Selling cocaine, dm me", "Drops needed, paying daily", "Buying bank accounts", "Fake documents for sale",
    "Send me your card details and the SMS code", "Guaranteed profit 10% daily, double your money",
    "Your account has been blocked, verify now",
    # Kyrgyz
    "Баңги зат сатам, закладка бар", "Дроптор керек, карта ижарага алабыз", "Банк картасын сатып алабыз",
    "Жасалма документ жасайбыз", "Карта маалыматын жана смс кодду жөнөт", "Кепилденген киреше, инвестиция салыңыз",
    "Эсебиңиз бөгөттөлдү, ссылканы басыңыз",
    # Kazakh
    "Есірткі сатамын, закладка бар", "Дроп керек, карта жалға аламыз", "Банк картасын сатып аламыз",
    "Жалған құжат жасаймыз", "Карта деректерін және смс кодты жібер", "Кепілдендірілген табыс, инвестиция салыңыз",
    "Шотыңыз бұғатталды, сілтемені басыңыз",
    # Uzbek
    "Giyohvand sotaman, zakladka bor", "Drop kerak, karta ijaraga olamiz", "Bank kartasini sotib olamiz",
    "Soxta hujjat qilamiz", "Karta ma'lumotlarini va sms kodni yuboring", "Kafolatli daromad, investitsiya kiriting",
    "Hisobingiz bloklandi, havolani bosing",
    # Tajik
    "Маводи мухаддир мефурӯшам", "Дроп лозим, корт ба иҷора мегирем", "Корти бонкӣ мехарем",
    "Ҳуҷҷати қалбакӣ месозем", "Маълумоти корт ва рамзи смс фиристед", "Даромади кафолатнок, сармоягузорӣ кунед",
    "Ҳисоби шумо банд шуд, истинодро пахш кунед",
    # Turkmen
    "Neşe satýaryn, zakladka bar", "Drop gerek, kart kärendesine alýarys", "Bank kartyny satyn alýarys",
    "Galp resminama ýasaýarys", "Kart maglumatlaryny we sms kody iber", "Kepillikli girdeji, maýa goýum ediň",
    "Hasabyňyz petiklendi, baglanyşygy basyň",
]

NORMAL = [
    "Привет всем, как дела?", "Выезжаю в Каракол в 8 утра, 2 места, 700 сом", "Сдаётся квартира, 30000 сом в месяц",
    "Hello everyone, is the road to Karakol open today?", "I can drive from Bishkek tomorrow morning",
    "Салам, баарына кутман таң! Бүгүн Каракол жакка бара жатам", "Бишкектен Ошко жол кандай?",
    "Сәлем, бүгін Алматыға бара жатырмын, 2 орын бар", "Қайырлы таң, жол қалай?",
    "Salom, bugun Toshkentga ketyapman, 2 ta joy bor", "Yo'l qanday, ochiqmi?",
    "Салом, имрӯз ба Душанбе меравам, 2 ҷой ҳаст", "Роҳ чӣ хел аст?",
    "Salam, şu gün Aşgabada gidýärin, 2 ýer bar", "Ýol nähili, açykmy?",
    "Я сегодня оплатил кредит в банке, всё прошло",
]


@pytest.mark.parametrize("text", CRIMINAL)
def test_criminal_message_is_acted_on(text):
    v = d.analyze(text)
    assert v.score >= 3 or (v.criminal_hit and not is_warning_context(text)), (text, v.score, v.reasons)


@pytest.mark.parametrize("text", NORMAL)
def test_normal_message_is_left_alone(text):
    v = d.analyze(text)
    assert v.score < 3 and not (v.criminal_hit and not is_warning_context(text)), (text, v.score, v.reasons)
