"""Broad financial-scam coverage (fast, offline, free).

Families: investment/crypto, seed-phrase & wallet theft, advance-fee loans, bank/police
impersonation & phishing, prizes/lotteries, paid-task scams, pyramids/MLM, gambling ads,
buying bank accounts/cards/passports. Local-language lines (kk/ky/uz/tg/tk) are a first
pass - the AI layer (bot/ai_classifier.py) covers the wording these rules miss.

Weights follow rules.py: a single weak phrase never bans; several signals together do.
"""
from .rules import MEDIUM, STRONG, WEAK

KEYWORD_RULES: list[tuple[str, int, str]] = [
    # ---------------- investment / crypto / forex ----------------
    ("invest_scam", STRONG, r"(гарантированн\w+|гарантия)\s+(доход\w*|прибыл\w+|заработ\w+)|удвои\w+\s+(депозит\w*|вложени\w+|деньги|биткоин\w*)|х\s?[2-9]\s+(за|через)\s+\d+"),
    ("invest_scam", STRONG, r"(прибыл\w+|доход\w*|профит)\s+(от\s+|до\s+)?\d{1,3}\s*%\s*(в\s+(день|сутки|неделю)|ежедневно|за\s+(день|сутки|неделю))"),
    ("invest_scam", STRONG, r"\b\d{1,3}\s*%\s*(daily|per\s+day|a\s+day|weekly|per\s+week)\b|double\s+your\s+(money|investment|btc|bitcoin|deposit)|guaranteed\s+(profit|returns?)|risk[-\s]*free\s+(profit|investment|returns?)"),
    ("invest_scam", MEDIUM, r"сигналы\s+(по|для|на)\s+(крипт\w+|форекс|трейдинг\w*|бирж\w+)|трейдинг[\s-]*бот|торговый\s+бот|trading\s+(signals|bot)|crypto\s+(signals|investment|arbitrage)|арбитраж\s+крипт\w+|криптоарбитраж\w*"),
    ("invest_scam", WEAK, r"пассивн\w+\s+доход|инвестиционн\w+\s+(проект|платформ\w+|клуб|пул)|форекс|\bforex\b|трейдинг\w*|passive\s+income"),
    ("invest_scam", MEDIUM, r"(вложи\w*|инвестиру\w*|инвестируйте|invest)\s+(\w+\s+){0,3}(получи\w*|заработ\w+|верн\w+|get|earn|receive)\s+(\w+\s+){0,3}(\d+\s*%|x\s?\d|в\s+\d+\s+раз|\d+\s+times)"),
    ("wallet_theft", STRONG, r"seed[\s-]*phrase|сид[\s-]*фраз\w*|секретн\w+\s+фраз\w*|приватн\w+\s+ключ\w*|private\s+key|recovery\s+phrase|мнемоническ\w+\s+фраз\w*"),
    ("wallet_theft", MEDIUM, r"connect\s+(your\s+)?wallet|подключи\w*\s+(свой\s+)?кошел\w+|claim\s+(your\s+)?(airdrop|reward|tokens?|bonus)|\bairdrop\b|эйрдроп|аирдроп"),
    # ---------------- advance-fee loans / credit ----------------
    ("loan_scam", STRONG, r"(кредит|займ|заём|ссуд\w+|loan)\w*\s+(без\s+(отказа|проверки|справок|залога|поручител\w+|предоплат\w+)|в\s+любом\s+случае)|одобрени\w+\s+(100\s*%|гарантир\w+)|(100\s*%|гарантированн\w+)\s+одобрени\w+|no\s+credit\s+check|guaranteed\s+(loan|approval)"),
    ("loan_scam", STRONG, r"(предоплат\w+|аванс|комисси\w+|страховк\w+|налог\w*|взнос\w*)\s+(за\s+|на\s+|для\s+)?(оформлени\w+|одобрени\w+|получени\w+|разблокировк\w+|вывод\w*)\s+(кредит\w*|займ\w*|выплат\w*|приз\w*|выигрыш\w*|перевод\w*|средств\w*|денег|компенсаци\w+)"),
    ("loan_scam", MEDIUM, r"кредит\w*\s+(даже\s+)?(с|при)\s+плох\w+\s+кредитн\w+\s+истори\w+|плох\w+\s+кредитн\w+\s+истори\w+\s+не\s+проблем\w+|(займ|кредит)\w*\s+на\s+карт\w+\s+(за\s+)?\d+\s+минут"),
    # ---------------- impersonation / phishing ----------------
    ("impersonation", STRONG, r"(перевед\w+|переведите|переводите|перекин\w+)\s+(\w+\s+){0,4}на\s+(безопасн\w+|защищённ\w+|защищенн\w+|резервн\w+)\s+(счёт|счет|карт\w+|кошел\w+)|безопасн\w+\s+(счёт|счет)"),
    ("impersonation", STRONG, r"ваш\w*\s+(счёт|счет|карта|аккаунт|учётн\w+\s+запис\w+|учетн\w+\s+запис\w+)\s+(был\w*\s+|будет\s+|уже\s+)?(заблокирован\w*|взломан\w*|скомпрометирован\w*|приостановлен\w*)|your\s+(account|card|wallet|bank\s+account)\s+(has\s+been|is|was|will\s+be)\s+(blocked|suspended|locked|compromised|hacked|closed)"),
    ("impersonation", MEDIUM, r"служб\w+\s+безопасности\s+(\w+\s+)?банк\w*|сотрудник\w*\s+(банка|полиции|гкнб|прокуратур\w+|следственн\w+\s+\w+|мвд|фсб|налоговой)|я\s+(из|от)\s+(банка|полиции|гкнб|налогов\w+)|\b(bank\s+security|security\s+department)\b"),
    ("impersonation", MEDIUM, r"подозрительн\w+\s+(операци\w+|транзакци\w+|активност\w+|вход)|suspicious\s+(activity|transaction|login)|несанкционированн\w+\s+(списани\w+|доступ|операци\w+)"),
    ("phishing_link", MEDIUM, r"(перейд\w+|перейдите|нажм\w+|нажмите|кликн\w+|click|tap)\s+(по\s+)?(ссылк\w+|link|here|сюда)\s+(\w+\s+){0,2}(для|чтобы|to)\s+(подтвержд\w+|верифиц\w+|разблокир\w+|получ\w+|активир\w+|verify|confirm|unlock|claim|activate)"),
    ("phishing_link", WEAK, r"\b(bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|rb\.gy|clck\.ru|goo\.gl|shorturl\.at)/\w+"),
    ("phishing_link", MEDIUM, r"(верифик\w+|подтверд\w+|verify|confirm)\s+(\w+\s+){0,2}(личност\w+|аккаунт\w*|identity|account|карт\w+|card)\s+(\w+\s+){0,3}(по\s+ссылк\w+|by\s+clicking|via\s+(the\s+)?link)"),
    # ---------------- prizes / lotteries ----------------
    ("prize_scam", MEDIUM, r"(вы|ты)\s+(выиграл\w+|стали\s+победител\w+|победил\w*)|поздравляем[,!\s]+(вы|ты)\s+(выиграл\w+|победил\w*|стали)|you\s+(have\s+)?(won|been\s+selected)|congratulations[,!\s]+you|lottery\s+winner|розыгрыш\s+приз\w+"),
    ("prize_scam", STRONG, r"(для\s+получени\w+|чтобы\s+получить|to\s+(receive|claim|get))\s+(\w+\s+){0,2}(приз\w*|выигрыш\w*|бонус\w*|награду|prize|winnings?|reward)\s+(\w+\s+){0,3}(оплатите|заплатите|переведите|внесите|отправьте|pay|send|deposit)"),
    # ---------------- paid-task / easy-money ----------------
    ("task_scam", MEDIUM, r"(лайк\w*|просмотр\w*|подписк\w+|отзыв\w*|задани\w+|комментари\w+)[\s,.;:—-]+(\w+[\s,.;:—-]+){0,4}(оплат\w+|платим|заработ\w+|за\s+каждо\w+)|за\s+(каждый|каждое|каждую)\s+(лайк|просмотр|отзыв|заказ|задание|подписку)\s+\w*\s*\d+"),
    ("task_scam", MEDIUM, r"(like|subscribe|rate|review|watch)\w*\s+(\w+\s+){0,4}(get\s+paid|earn|\$\s?\d+)|work\s+from\s+(home|phone)\s+(and\s+)?earn|earn\s+money\s+(from|on)\s+(your\s+)?phone"),
    ("task_scam", MEDIUM, r"легк\w+\s+(деньги|заработок)|лёгк\w+\s+(деньги|заработок)|быстр\w+\s+деньги|зарабатывай\w*\s+(на\s+)?(телефон\w*|дома|онлайн|в\s+телеграм\w*)|easy\s+money|quick\s+cash"),
    # ---------------- pyramids / MLM ----------------
    ("pyramid", MEDIUM, r"финансов\w+\s+пирамид\w+|сетево\w+\s+маркетинг\w*|\bмлм\b|\bmlm\b|ponzi|pyramid\s+scheme|приводи\w*\s+(друзей|людей)\s+(и|—|-)\s*получ\w+|заработок\s+на\s+приглашени\w+"),
    ("pyramid", WEAK, r"реферальн\w+\s+(программ\w+|систем\w+|доход\w*|бонус\w*)|referral\s+(bonus|income|program)"),
    # ---------------- gambling ads ----------------
    ("gambling_ad", MEDIUM, r"1xbet|1хбет|мелбет|melbet|mostbet|мостбет|pin[\s-]?up|пин[\s-]?ап|vavada|вавада|казино|\bcasino\b|букмекер\w*|ставки\s+на\s+спорт|\bbetting\b|прогнозы\s+на\s+(спорт|матч\w*|ставки)"),
    ("gambling_ad", WEAK, r"промокод\w*|promo\s*code|бонус\s+за\s+регистраци\w+|фриспин\w*|free\s*spins?"),
    # ---------------- buying bank accounts / cards / passports ----------------
    ("account_buying", STRONG, r"(куплю|покупаю|скупаю|арендую|возьму\s+в\s+аренду|аренда|выкуп\w*)\s+(\w+\s+){0,2}(банковск\w+\s+(карт\w+|счет\w*|счёт\w*|аккаунт\w*)|паспорт\w*|электронн\w+\s+кошел\w+|доступ\w*\s+к\s+(банк\w*|личн\w+\s+кабинет\w*)|(карт\w+|счет\w*|счёт\w*)\s+(\w+\s+)?(банк\w+|мбанк|optima|оптима|демир|kicb|кикб))"),
    ("account_buying", MEDIUM, r"(куплю|покупаю|скупаю|арендую|аренда)\s+(\w+\s+){0,2}(сим[\s-]*карт\w*|симки|номера\s+(мегком|о!|beeline|билайн))|(buy|buying|rent)\s+(\w+\s+){0,2}(bank\s+accounts?|sim\s+cards?|verified\s+accounts?)"),
    # ---------------- local-language lines (first pass) ----------------
    ("kk_fin", MEDIUM, r"инвестиция\w*\s+(сал\w+|жаса\w+)|пассивті\s+табыс|ұтып\s+алдыңыз|банк\s+қызметкері|шотыңыз\s+бұғатталды|картаңыз\s+бұғатталды"),
    ("ky_fin", MEDIUM, r"инвестиция\s+салыңыз|пассивдүү\s+киреше|утуп\s+алдыңыз|банк\s+кызматкери|эсебиңиз\s+бөгөттөлдү|картаңыз\s+бөгөттөлдү"),
    ("uz_fin", MEDIUM, r"investitsiya\s+(kiriting|qiling)|passiv\s+daromad|yutib\s+oldingiz|bank\s+xodimi|hisobingiz\s+bloklandi|kartangiz\s+bloklandi"),
    ("tg_fin", MEDIUM, r"сармоягузорӣ\s+кунед|шумо\s+ғолиб\s+шудед|ҳисоби\s+шумо\s+банд\s+шуд|корти\s+шумо\s+банд\s+шуд|корманди\s+бонк"),
    ("tk_fin", MEDIUM, r"maýa\s+goýum\s+ediň|siz\s+ýeňdiňiz|hasabyňyz\s+petiklendi|kartyňyz\s+petiklendi|bankyň\s+işgäri"),
]
