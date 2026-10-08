"""Social-engineering scams in Russian, English, Kyrgyz, Uzbek, Kazakh, Tajik and Turkmen.

Three families, each deliberately built from several weak signals so that a single
ordinary phrase ("опыт не нужен", "одолжи 500 сом") never reaches the ban score on its own:

1. Fake easy-job offers      : "100% safe", "no experience", "100k per week"
2. Card-detail / code phishing: "send card data", "tell me the SMS code"
3. Urgent borrow-money scam  : "urgent, my card doesn't work, lend me 5000, I'll return at once"

The Tajik and Turkmen wording is a first pass - tune it with real samples.
"""
from .rules import MEDIUM, STRONG, WEAK

Q = "['`]?"  # optional apostrophe in Latin Uzbek/Turkmen


def _alt(*parts: str) -> str:
    return "(?:" + "|".join(parts) + ")"


# ---------------------------------------------------------------- 1. fake job
SAFE_100 = (
    r"100\s*%\s*" + _alt(
        r"қауіпсіз", r"коопсуз", r"безопасн\w*", r"гарант\w*", r"надёжн\w*", r"надежн\w*",
        r"safe", r"secure", r"guarantee\w*", r"legit", rf"xavfsiz", r"бехатар", r"howpsuz", r"kafolat\w*", r"кепіл\w*", r"кепил\w*",
    )
)
NO_EXPERIENCE = _alt(
    r"без\s+опыта", r"опыт\s+не\s+(?:нужен|требуется|важен)", r"без\s+вложений", r"вложений\s+не\s+требуется",
    r"no\s+experience", r"without\s+experience", r"no\s+investment", r"zero\s+investment",
    r"тәжірибе\s+(?:керек\s+жоқ|қажет\s+емес|талап\s+етілмейді)", r"тәжірибесіз", r"салымсыз",
    r"тажрыйба\s+(?:талап\s+кылынбайт|керек\s+эмес|зарыл\s+эмес)", r"тажрыйбасыз",
    r"tajriba\s+(?:kerak\s+emas|talab\s+qilinmaydi)", r"tajribasiz", r"sarmoyasiz", r"investitsiyasiz",
    r"таҷриба\s+(?:лозим\s+нест|даркор\s+нест|талаб\s+намешавад)", r"бе\s+таҷриба", r"бе\s+сармоя",
    r"tejribe\s+(?:gerek\s+däl|talap\s+edilmeýär)", r"tejribesiz", r"goýumsyz",
)
_CUR = r"(?:тенге|₸|сом\w*|руб\w*|₽|сум\w*|somoni|сомони|манат\w*|manat|usd|usdt|\$|долл\w*|тг\b|dollar\w*|som\b|so['`]?m\b|sum\b|rub\b|tenge|eur|€)"
_NUM = r"\d[\d\s.,]*\s*(?:мың|тыс\w*|ming|k|к|million|миллион\w*)?"
AMOUNT = _alt(_NUM + r"\s*" + _CUR, r"[$€₽₸]\s*" + _NUM)
PERIOD = _alt(
    r"аптасына", r"күніне", r"жумасына", r"күнүнө", r"кунуна", r"haftasiga", r"kuniga",
    r"в\s+неделю", r"в\s+день", r"в\s+сутки", r"за\s+день", r"за\s+неделю", r"per\s+week", r"per\s+day",
    r"a\s+week", r"a\s+day", r"weekly", r"daily", r"ҳар\s+ҳафта", r"ҳар\s+рӯз", r"дар\s+як\s+ҳафта",
    r"hepdede", r"günde", r"gunde", r"за\s+час", r"в\s+час", r"per\s+hour", r"ҳар\s+соат", r"сағатына", r"саатына",
)
EARN_CLAIM = _alt(
    PERIOD + r"\s*[:\-–]?\s*(?:от\s+|до\s+|from\s+|up\s+to\s+)?" + AMOUNT,
    AMOUNT + r"\s*(?:в|per|a|/)?\s*" + PERIOD,
)

# ------------------------------------------------- 2. card-detail / code phishing
CARD_DATA = _alt(
    r"данны\w+\s+(?:\w+\s+)?карт\w*", r"карт\w*\s+данны\w+", r"cvv2?", r"cvc2?",
    r"код\w*\s+(?:из\s+)?(?:смс|sms|сообщени\w+|подтверждени\w+)", r"смс[\s-]*код\w*", r"пин[\s-]*код\w*",
    r"срок\s+действия\s+карт\w+", r"фото\s+карт\w+",
    r"card\s+(?:details|data|info\w*)", r"(?:sms|otp|verification)\s+code", r"pin\s+code",
    r"карта\w*\s+(?:деректер\w*|мәлімет\w*)", r"(?:деректер\w*|мәліметтер\w*)\s+карта\w*",
    r"карта\w*\s+маалымат\w*", r"маалымат\w*\s+карта\w*",
    rf"karta\w*\s+(?:ma{Q}lumot\w*|rekvizit\w*)", rf"sms\s*kod\w*", rf"pin\s*kod\w*",
    r"маълумот\w*\s+корт\w*", r"корт\w*\s+маълумот\w*", r"рамзи\s+(?:смс|sms)",
    r"kart\w*\s+maglumat\w*", r"maglumat\w*\s+kart\w*",
)
SEND_VERB = _alt(
    r"скин\w+", r"отправ\w+", r"пришл\w+", r"присла\w+", r"дай\w*", r"сообщи\w*", r"назов\w+", r"назови\w*",
    r"продиктуй\w*", r"сфоткай\w*", r"вышли\w*", r"кинь\w*", r"кидай\w*", r"скажи\w*",
    r"send", r"give", r"share", r"tell", r"provide", r"forward", r"dm",
    r"жібер\w*", r"таста\w*", r"айт\w*", r"бер\w*", r"жолда\w*",
    r"жөнөт\w*", r"таштап\w*", r"айтып\w*", r"жиберип\w*",
    r"yubor\w*", r"tashla\w*", r"ayt\w*", rf"jo{Q}nat\w*", r"ber\w*",
    r"фирист\w*", r"гӯед", r"гуед", r"диҳед", r"дихед",
    r"iber\w*", r"ugrat\w*", r"aýt\w*", r"ýaz\w*",
)
CARD_REQUEST = _alt(
    CARD_DATA + r"\s+(?:\w+\s+){0,3}" + SEND_VERB,
    SEND_VERB + r"\s+(?:\w+\s+){0,3}" + CARD_DATA,
)

URGENT = _alt(
    r"быстрее", r"срочно", r"скорее", r"немедленно", r"прямо\s+сейчас", r"urgent\w*", r"asap", r"quick\w*", r"hurry", r"right\s+now",
    r"шұғыл", r"асығыс", r"тезірек", r"шашылыш", r"тезирээк", r"азыр\s+эле", r"shoshilinch", r"tezroq", r"hoziroq",
    r"таъҷилӣ", r"таъчил\w*", r"таъҷил\w*", r"фаврӣ", r"фавран", r"зудтар", r"gyssagly", r"çalt", r"şuwagt",
)

# ------------------------------------------------------------ 3. borrow scam
BORROW = _alt(
    r"одолж\w+", r"занять", r"займи\w*", r"выручи\w*", r"подкинь\w*", r"в\s+долг", r"дашь\s+в\s+долг",
    r"(?:lend|borrow|loan)\s+me", r"can\s+you\s+(?:send|give|transfer|lend)\s+me",
    r"қарыз\w*", r"бере\s+аласың\w*", r"бере\s+аласыз\w*", r"аудара\s+аласың\w*",
    r"берип\s+тура\s+аласы\w*", r"бере\s+аласы\w*", r"карыз\w*", r"которуп\s+бере\s+аласы\w*",
    r"qarz\w*", r"berib\s+tura\s+olasi\w*", r"bera\s+olasi\w*", rf"o{Q}tkazib\s+bera\s+olasi\w*",
    r"қарз\w*", r"дода\s+метавонед\w*", r"karz\w*", r"berip\s+bilersi\w*",
)
RETURN_FAST = _alt(
    r"верну\s+(?:сразу|сейчас|через|скоро|вечером)", r"отдам\s+(?:сразу|сейчас|через|скоро|вечером)",
    r"(?:i\W?ll|will)\s+(?:pay|send|return)\s+(?:you\s+)?back", r"pay\s+you\s+back",
    r"қайтарып\s+беремін", r"қайтарамын", r"кайтарып\s+берем", r"кайтарам",
    r"qaytarib\s+beraman", r"qaytaraman", r"баргардонам", r"баргардон\w*", r"бармегардон\w*",
    r"gaýtaryp\s+bererin", r"gaýtararyn", r"yzyna\s+bererin",
)
CARD_PROBLEM = _alt(
    r"карта\s+не\s+(?:работает|проходит)", r"деньги\s+не\s+(?:проходят|идут|переводятся)", r"не\s+проходит\s+оплат\w*",
    r"(?:my\s+)?card\s+(?:is\s+)?(?:not\s+working|declined|blocked)", r"(?:payment|transfer)\s+(?:is\s+)?not\s+going\s+through",
    r"карта\w*\s+(?:жұмыс\s+істемей|ақша\s+өтпей)", r"ақша\s+өтпей\s+жатыр",
    r"картам\w*\s+(?:акча\s+өтпөй|иштебей)", r"акча\s+өтпөй\s+жатат",
    r"kartam\s+ishlamay", rf"pul\s+o{Q}tmay",
    r"корт\w*\s+кор\s+намекунад", r"корт\w*\s+пул\s+(?:намегирад|намеравад|намегузарад)", r"kartym\s+işlemeýär",
)

KEYWORD_RULES: list[tuple[str, int, str]] = [
    ("fake_job", MEDIUM, SAFE_100),
    ("fake_job", WEAK, NO_EXPERIENCE),
    ("fake_job", WEAK, EARN_CLAIM),
    ("card_phishing", STRONG, CARD_REQUEST),
    ("urgency", WEAK, URGENT),
    ("borrow_scam", WEAK, BORROW),
    ("borrow_scam", WEAK, RETURN_FAST),
    ("borrow_scam", MEDIUM, CARD_PROBLEM),
    # "easy money" teasers and huge unrealistic pay (no digits needed: "миллион долларов в день")
    ("fake_job", STRONG, r"(?:тысяч\w*|миллион\w*|млн|миллиард\w*)\s+(?:долларов|доллар\w*|\$|usd|usdt|сом\w*|руб\w*|евро|тенге|тг)\s+(?:в|за)\s+(?:день|сутки|неделю|час)"),
    ("fake_job", STRONG, r"(?:million|thousand)s?\s+(?:dollars|usd|\$)\s+(?:a|per|every)\s+(?:day|week|hour)"),
    ("fake_job", MEDIUM, r"хотите\s+(?:\w+\s+){0,3}(?:крипт\w+|бабк\w+|деньг\w+|заработ\w+|миллион\w*)|хочешь\s+(?:\w+\s+){0,3}(?:крипт\w+|бабк\w+|заработ\w+|миллион\w*)|do\s+you\s+want\s+(?:\w+\s+){0,3}(?:crypto|money|to\s+earn|millions?)"),
    # invitations to join a money scheme: "кто хочет крипту / заработать / бабки"
    ("fake_job", MEDIUM, r"кто\s+хочет\s+(?:\w+\s+){0,2}(?:крипт\w+|бабк\w+|деньг\w+|заработ\w+|подзаработ\w+|миллион\w*)|кто\s+хочет\s+(?:\w+\s+){0,2}(?:подзаработать|заработать)|who\s+wants\s+(?:\w+\s+){0,2}(?:crypto|money|to\s+earn)"),
    ("laundering", MEDIUM, r"\bотмыв[аы]?\s+(?:бабок|бабки|денег|деньги|средств|кэша|нала|налички|крипт\w+)|\bобнал[а]?\s+(?:бабок|денег|крипт\w+|кэша)"),
    ("fake_job", MEDIUM, r"л[её]гк\w+\s+(?:работ\w+|заработ\w+|деньг\w+)|easy\s+(?:job|work)"),
]
