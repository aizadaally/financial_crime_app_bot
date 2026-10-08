"""Built-in detection rules.

Patterns are matched against *normalized* text (lowercased, NFKC, zero-width
characters removed, Latin look-alikes folded to Cyrillic where the word is
mostly Cyrillic is NOT attempted; instead both a raw and a de-obfuscated form
are checked). Weights add up to a score; see detector.py.
"""

# (category, weight, regex)
STRONG = 3
MEDIUM = 2
WEAK = 1
BAN = 4  # explicit offer of a criminal service/goods: enough to ban on its own

KEYWORD_RULES: list[tuple[str, int, str]] = [
    # --- carding / stolen data ---
    ("carding", STRONG, r"\b(carding|carder|cvv2?|fullz|dumps?\s*(with|\+)\s*pins?|bins?\s*list|sniffer\s*logs?)\b"),
    ("carding", STRONG, r"кардинг|кардер|дамп[ыа]?\s*(с|\+)\s*пин|сниффер|скимм?инг|шиммер"),
    ("carding", MEDIUM, r"(слив|база|базы)\s+(карт|клиентов|банков)|свежие\s+(лог[иы]|карты|дамп)"),
    # --- droppers / cash-out / money mules ---
    ("dropper", STRONG, r"\b(дроп(ы|овод|ов|а)?|дропшиппинг\s+карт|drops?\s+needed|money\s*mules?|mule\s+accounts?)\b"),
    ("dropper", STRONG, r"обнал(ичк[аи]|ичивани[ея])?|обналичу|кэшаут|cash\s*-?out|вывод\s+(средств|денег)\s+(с|из)\s+(краденых|левых)"),
    ("dropper", MEDIUM, r"(ищем|нужны|набираем|требуются)\s+(дроп|кур[ьи]ер|обнальщик|держател[ьи]\s+карт)"),
    ("dropper", MEDIUM, r"(сдам|сниму|куплю|продам)\s+(карт[ауы]|аккаунт|счет|счёт)\s*(под|для)?\s*(залив|обнал|дроп)?"),
    # --- fraud / scams ---
    ("fraud", STRONG, r"(пробив|пробить)\s+(по\s+)?(базам?|номер|фио|карт|паспорт|банк)|пробив\s+клиент"),
    ("fraud", STRONG, r"\b(scam\s*pages?|phishing\s*kits?|spoof(ing)?\s+calls?|sim\s*swap|bank\s*logs?|bank\s*drops?)\b"),
    ("fraud", STRONG, r"фишинг(овые)?\s*(страниц|сайт|панел)|скам\s*(страниц|схем)|левые\s+(карты|паспорт|документы|симки|сим-карты)"),
    ("fraud", MEDIUM, r"(обход|обойти)\s+(антифрод|kyc|верификаци|3ds|3-d\s*secure)|антидетект"),
    ("fraud", MEDIUM, r"\b(kyc\s+bypass|verified\s+accounts?\s+for\s+sale|clone\s+cards?|cloned\s+cards?)\b"),
    ("fraud", MEDIUM, r"(фальшив|поддельн|липов)\w*\s+(купюр|деньги|документ|паспорт|справк|диплом)"),
    ("fraud", MEDIUM, r"отмыв\w*\s+(денег|средств|кэш)|money\s+laundering\s+(service|for\s+hire)"),
    # --- illegal "easy money" offers ---
    ("easy_money", MEDIUM, r"(заработок|доход)\s+(на|от)\s+(схем|заливе|обнале|дропах)|схем[аы]\s+заработка\s+(без\s+вложений)?"),
    ("easy_money", MEDIUM, r"\b(guaranteed\s+(profit|returns?)|double\s+your\s+(money|btc|crypto)|flash\s+(usdt|btc|bitcoin))\b"),
    ("easy_money", MEDIUM, r"(гарантированн\w+\s+(доход|прибыль)|удво\w+\s+(депозит|вложени|крипт))"),
    ("easy_money", WEAK, r"заработ\w+\s+от\s+\d+\s*(\$|usd|usdt|руб|₽|тыс)\s*(в\s+(день|сутки|неделю))?"),
    # --- selling drugs (needs an offering verb, so news/discussion text does not match) ---
    ("drugs", BAN, r"(продаю|продам|продаём|продаем|куплю|есть\s+в\s+наличии|в\s+наличии|заказывай\w*|доставка|доставлю)\s+(\w+\s+){0,2}(нарк\w+|героин\w*|кокаин\w*|амфетамин\w*|мефедрон\w*|гашиш\w*|марихуан\w*|экстази|лсд|спайс\w*|закладк\w+)"),
    ("drugs", BAN, r"\b(selling|sell|buy|for\s+sale)\s+(\w+\s+){0,2}(drugs|cocaine|heroin|mdma|meth|weed|cannabis|fentanyl)\b"),
    # --- offering laundering / cash-out services ---
    ("laundering", BAN, r"(делаю|сделаю|делаем|предлагаю|занимаюсь|оказываю|помогу|помогаем)\s+(\w+\s+){0,3}(отмыв\w*|обнал\w*|легализаци\w+\s+(денег|средств|бабок))"),
    # --- "give me your card/account and I pay you" (dropper recruitment, plain wording) ---
    ("dropper", STRONG, r"(дам|дадим|заплачу|заплатим|плачу|платим|получите|получишь)\s+(\w+\s+){0,3}(сом\w*|руб\w*|тенге|сум\w*|долл\w*|usd|usdt|\$|₽|тысяч\w*|миллион\w*)\s+(\w+\s+){0,3}(через|за|на)\s+(вашу|ваш|свою|твою|твой|вашей|ваше)\s+(карт\w+|сч[её]т\w*|аккаунт\w*|кошел\w+)"),
    ("dropper", MEDIUM, r"(через|за)\s+(вашу|ваш|твою|твой)\s+(карт\w+|сч[её]т\w*)\s*[.!]?\s*(\n|$|пиши|пишите|лс|в\s+лс)|кто\s+хочет\s+(дам|заработ\w+)"),
    # --- other illegal goods commonly spammed alongside ---
    ("illegal_goods", STRONG, r"(закладк[иа]|мефедрон|гашиш|шишки\s+купить|amphetamine\s+for\s+sale|buy\s+(cocaine|mdma|fake\s+id))"),
]

# Call-to-action to join a chat/channel; only counts together with another signal.
JOIN_CTA_RULES: list[tuple[str, int, str]] = [
    ("join_cta", WEAK, r"(вступ(ай|айте|ить)|заход(и|ите)|подпиш(ись|итесь)|переходи(те)?|пиши(те)?\s+в\s+лс|писать\s+в\s+лс|жми(те)?)"),
    ("join_cta", WEAK, r"\b(join|subscribe|dm\s+me|pm\s+me|contact\s+me|inbox\s+me|text\s+me)\b"),
    ("join_cta", WEAK, r"(закрыт(ый|ом)\s+(канал|чат|клуб)|приват(ный|ка)\s+(канал|чат|группа))|private\s+(channel|group|chat)"),
]

# Telegram invite / channel links. Invite links get a bonus because they point
# straight into another chat.
INVITE_LINK_RE = r"(?:https?://)?(?:t(?:elegram)?\.me|telegram\.dog)/(?:\+|joinchat/)[\w\-]+|tg://join\?invite=[\w\-]+"
TME_USERNAME_RE = r"(?:https?://)?(?:t(?:elegram)?\.me|telegram\.dog)/(?!\+|joinchat)(?P<name>[A-Za-z][\w]{3,31})"
URL_RE = r"(?:https?://|www\.)[^\s<>\"]+"

INVITE_LINK_WEIGHT = 2
TME_LINK_WEIGHT = 1

# Obfuscation fixes: Latin look-alikes -> Cyrillic are NOT forced; instead we
# produce a second variant of the text with Cyrillic look-alikes -> Latin and
# vice versa, and match both.
CYR_TO_LAT = str.maketrans("асеорхуіјкмнтв", "aceopxyijkmht" + "b")
LAT_TO_CYR = str.maketrans("aceopxykmhtb", "асеорхукмнтв")

from .rules_regional import JOIN_CTA_RULES as _RJ, KEYWORD_RULES as _RK  # noqa: E402

from .rules_scams import KEYWORD_RULES as _RS  # noqa: E402

from .rules_financial import KEYWORD_RULES as _RF  # noqa: E402

KEYWORD_RULES = KEYWORD_RULES + _RK + _RS + _RF
JOIN_CTA_RULES = JOIN_CTA_RULES + _RJ
