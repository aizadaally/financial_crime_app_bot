"""Rules for Uzbek, Kazakh, Kyrgyz, Tajik and Turkmen spam.

Shared Russian loanwords (дроп, обнал, кардинг, ...) are already covered in
rules.py and also appear in Central Asian spam, so these rules only add the
local-language phrasing. They are a starting point: send real samples and the
patterns can be tightened. In Uzbek/Turkmen Latin text, apostrophe variants
are folded to ' by detector.normalize().
"""
from .rules import BAN, MEDIUM, STRONG, WEAK

A = r"['`]?"  # optional apostrophe (o'z, qo'sh, ...)

KEYWORD_RULES: list[tuple[str, int, str]] = [
    # ---------- Uzbek (Latin) ----------
    ("uz_dropper", STRONG, rf"\bdrop(lar|chi|ga|lar)?\s+(kerak|qidiramiz|izlaymiz)|\bobnal(\w*)?\b|\bkarta\s+(ijara|arenda)\w*"),
    ("uz_dropper", MEDIUM, rf"(bank\s+)?kart(a|ani|alar)\s+(sotiladi|sotib\s+olamiz|sotaman|olinadi)|hisob\s*raqam\w*\s+(sotiladi|ijara)"),
    ("uz_dropper", MEDIUM, rf"pul\s+(yechish|yechib\s+berish|chiqarish)\s+(xizmati|orqali)|naqdlashtirish"),
    ("uz_fraud", STRONG, rf"soxta\s+(hujjat|pasport|karta|diplom|spravka)|firibgar\w*\s+(sxema|usul)|fishing\s+(sayt|havola)"),
    ("uz_easy", MEDIUM, rf"(kafolatli|kafolatlangan)\s+(daromad|foyda)|tez\s+pul\s+(ishlash|topish)|investitsiya\s+(qo{A}ying|kiriting)\s+va\s+(\d+x|ikki\s+baravar)"),
    # ---------- Uzbek (Cyrillic) ----------
    ("uz_dropper", STRONG, r"дроп(лар)?\s+керак|карта\s+(ижара|сотилади|сотиб\s+оламиз)|нақдлаштириш"),
    ("uz_fraud", STRONG, r"сохта\s+(ҳужжат|паспорт|карта|диплом)|фирибгар\w*\s+(схема|усул)"),
    ("uz_easy", MEDIUM, r"кафолатли\s+(даромад|фойда)|тез\s+пул\s+(ишлаш|топиш)"),
    # ---------- Kazakh ----------
    ("kz_dropper", STRONG, r"дроп(тар)?\s+(керек|қажет|іздейміз)|карта(ны|лар)?\s+(жалға|жалдау|сатып\s+аламын|сатамын|сатып\s+аламыз)|қолма-?қол\s+ақша\s+шығару|ақша\s+шешу"),
    ("kz_fraud", STRONG, r"жалған\s+(құжат|паспорт|анықтама|диплом|карта)|фишинг\s+(сілтеме|сайт)|алаяқтық\s+(схема|тәсіл)"),
    ("kz_easy", MEDIUM, r"кепілдендірілген\s+(табыс|пайда)|жылдам\s+(табыс|ақша)|тез\s+ақша\s+табу|салымсыз\s+табыс"),
    # ---------- Kyrgyz ----------
    ("kg_dropper", STRONG, r"дроп(тор)?\s+(керек|издейбиз|алабыз)|карта(ны|лар)?\s+(ижарага|сатылат|сатып\s+алабыз|сатам)|акча\s+(чыгаруу|нактоо)\s+(кызмат|аркылуу)"),
    ("kg_fraud", STRONG, r"жасалма\s+(документ|паспорт|справка|диплом|карта)|фишинг\s+(шилтеме|сайт)|алдамчылык\s+(схема|ыкма)"),
    ("kg_easy", MEDIUM, r"кепилденген\s+(киреше|пайда)|тез\s+акча\s+(табуу|иштөө)|салымсыз\s+киреше"),
    # ---------- Tajik ----------
    ("tj_dropper", STRONG, r"дроп(ҳо)?\s+(лозим|даркор|меҷӯем)|корт(ро|ҳо)?\s+(ба\s+иҷора|мефурӯшам|мехарем|мехарам)|пули\s+нақд\s+(баровардан|кардан)|гирифтани\s+пул\s+аз\s+корт"),
    ("tj_fraud", STRONG, r"ҳуҷҷат(и|ҳои)?\s+қалбакӣ|шиноснома(и)?\s+қалбакӣ|фишинг\s+(пайванд|сайт)|қаллобӣ"),
    ("tj_easy", MEDIUM, r"даромади\s+кафолатнок|зуд\s+пул\s+(кор\s+кардан|ёфтан)|бе\s+сармоягузорӣ\s+даромад"),
    # ---------- Turkmen (Latin) ----------
    ("tm_dropper", STRONG, rf"\bdrop(lar)?\s+(gerek|gerekli|gözleýäris)|\bkart(y|lar|a)?\s+(kärendesine|kärende|satylýar|satyn\s+alýarys|satýaryn)|nagt\s+pul\s+(çykarmak|çykaryp\s+bermek)"),
    ("tm_fraud", STRONG, rf"galp\s+(resminama|pasport|diplom|kart)|fişing\s+(baglanyşyk|sahypa)|aldawçylyk\s+(shema|usuly)"),
    ("tm_easy", MEDIUM, rf"kepillikli\s+(girdeji|peýda)|çalt\s+pul\s+(gazanmak|tapmak)"),
]

JOIN_CTA_RULES: list[tuple[str, int, str]] = [
    # Uzbek
    ("join_cta", WEAK, rf"(kanalga|guruhga|chatga)\s+qo{A}shiling|qo{A}shiling|obuna\s+bo{A}ling|(lichkaga|lsga|shaxsiyga)\s+yozing|yopiq\s+(kanal|guruh|chat)"),
    ("join_cta", WEAK, r"қўшилинг|обуна\s+бўлинг|ёпиқ\s+(канал|гуруҳ|чат)"),
    # Kazakh
    ("join_cta", WEAK, r"(арнаға|топқа|чатқа)\s+қосыл|қосылыңыз|жазылыңыз|(жеке\s+хабарлама|лс)\w*\s+жаз|жабық\s+(арна|топ|чат)"),
    # Kyrgyz
    ("join_cta", WEAK, r"(каналга|топко|чатка)\s+кошул|кошулуңуз|жазылыңыз|(лс|жеке)\w*\s+жазыңыз|жабык\s+(канал|топ|чат)"),
    # Tajik
    ("join_cta", WEAK, r"ҳамроҳ\s+шавед|обуна\s+шавед|(ба\s+)?(шахсӣ|лс)\s+нависед|канали\s+пӯшида|гурӯҳи\s+пӯшида"),
    # Turkmen
    ("join_cta", WEAK, r"(kanala|topara|çata)\s+goşulyň|goşulyň|ýazylyň|(ls|şahsy)\w*\s+ýazyň|ýapyk\s+(kanal|topar|çat)"),
]

# ---- coverage added after a per-language test: selling drugs, buying cards/accounts, phishing links ----
KEYWORD_RULES += [
    # drugs for sale (an explicit offer bans on its own)
    ("drugs", BAN, r"(есірткі|марихуан\w*|героин\w*|кокаин\w*|гашиш\w*|мефедрон\w*)\s+(сатам\w*|сатамыз|бар\b|жеткізу)"),
    ("drugs", BAN, r"(баңги\s+зат|бангизат|героин\w*|кокаин\w*|гашиш\w*|мефедрон\w*)\w*\s+(сатам\w*|сатабыз|бар\b|жеткирип)"),
    ("drugs", BAN, r"(giyohvand\w*|geroin\w*|kokain\w*|geshish\w*|mefedron\w*|narkotik\w*)\s+(sotaman|sotamiz|sotiladi|bor\b|yetkazib)"),
    ("drugs", BAN, r"(маводи\s+мухаддир|героин\w*|кокаин\w*|гашиш\w*)\s+(мефурӯшам|мефурӯшем|фурӯхта\s+мешавад|ҳаст\b)"),
    ("drugs", BAN, r"(neşe|neshe|geroin\w*|kokain\w*|haşiş\w*|mefedron\w*)\s+(satýaryn|satýarys|satylýar|bar\b)"),
    ("drugs", STRONG, r"закладк\w*\s+(бар|бор)\b|zakladka\s+(bor|bar)\b"),
    # buying / renting bank cards and accounts
    ("account_buying", STRONG, r"(банк\s+картасын|карталарды|шотты|эсепти|аккаунт\w*)\s+сатып\s+ал\w+"),
    ("account_buying", STRONG, rf"(bank\s+kartasini|kartalarni|hisob\s+raqam\w*|akkaunt\w*)\s+(sotib\s+ola\w+|ijaraga\s+ola\w+)"),
    ("account_buying", STRONG, r"(корти\s+бонкӣ|кортҳо\w*|ҳисоб\w*)\s+(мехарем|мехарам|ба\s+иҷора\s+мегирем)"),
    ("account_buying", STRONG, r"(bank\s+kartyny|kartlary|hasaby|akkaunt\w*)\s+(satyn\s+alýar\w+|kärendesine\s+alýar\w+)"),
    ("fraud", STRONG, r"\b(fake|forged)\s+(documents?|passports?|ids?|diplomas?|certificates?)\s*(for\s+sale|available|made|service)?|(make|making|sell(?:ing)?)\s+(fake|forged)\s+(documents?|passports?|ids?|diplomas?)"),
    # "click the link" + account blocked (works with the *_fin rules in rules_financial.py)
    ("phishing_link", MEDIUM, r"(ссылканы|шилтемени)\s+бас\w*|сілтемені\s+бас\w*|havolani\s+bos\w*|истинодро\s+пахш\s+кун\w*|baglanyşygy\s+bas\w*"),
]
