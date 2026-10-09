"""Anti-evasion: produce alternative readings of a message so the rules still match when
someone disguises the words. Every function is pure, linear-time and bounded."""
from __future__ import annotations

import re
import unicodedata

_LETTER = r"[^\W\d_]"
# "п.р.о.д.а.ю", "п-р-о-д-а-ю", "п*р*о*д*а*ю" (separator between single letters, no spaces)
_PUNCT_RUN = re.compile(rf"(?<!{_LETTER})(?:{_LETTER}[.\-_*•·|/~^]){{2,}}{_LETTER}(?!{_LETTER})")
# "п р о д а ю" (single letters separated by one space; a double space marks a word break)
_SPACE_RUN = re.compile(rf"(?<!\S)(?:{_LETTER} ){{2,}}{_LETTER}(?!\S)")
# separator inside a word: "нар*коту", "про.дам"
_INNER_PUNCT = re.compile(rf"(?<={_LETTER})[*•·~^|_\-.](?={_LETTER})")
_REPEAT = re.compile(r"(.)\1{2,}")

_LEET_CYR = str.maketrans({"0": "о", "1": "и", "3": "е", "4": "а", "5": "с", "6": "б", "7": "т", "@": "а", "$": "с"})
_LEET_LAT = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "@": "a", "$": "s"})
_CYRILLIC = re.compile(r"[а-яёіїєґўқғҳҷӣӯ]")
_LATIN = re.compile(r"[a-z]")

# Latin-letter Russian ("Prodayu narkotu") -> Cyrillic. Longest sequences first.
_TRANSLIT_MULTI = [("shch", "щ"), ("sch", "щ"), ("yo", "ё"), ("yu", "ю"), ("ya", "я"), ("zh", "ж"),
                   ("kh", "х"), ("ts", "ц"), ("ch", "ч"), ("sh", "ш"), ("ye", "ые")]
_TRANSLIT_SINGLE = str.maketrans({
    "a": "а", "b": "б", "v": "в", "g": "г", "d": "д", "e": "е", "z": "з", "i": "и", "y": "ы", "k": "к",
    "l": "л", "m": "м", "n": "н", "o": "о", "p": "п", "r": "р", "s": "с", "t": "т", "u": "у", "f": "ф",
    "h": "х", "c": "к", "q": "к", "w": "в", "x": "кс", "j": "дж",
})
_TRANSLIT_RE = re.compile("|".join(src for src, _ in _TRANSLIT_MULTI))
_TRANSLIT_MAP = dict(_TRANSLIT_MULTI)

# Uzbek/Kazakh-style Cyrillic -> Latin, so the Latin-script rules also match Cyrillic Uzbek.
_CYR_TO_UZ_LATIN = str.maketrans({
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ж": "j", "з": "z", "и": "i", "й": "y",
    "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "x", "э": "e", "ў": "o'", "қ": "q", "ғ": "g'", "ҳ": "h", "ъ": "'", "ь": "", "ё": "yo",
    "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sh", "ю": "yu", "я": "ya", "ы": "i", "ү": "u", "ө": "o",
    "ң": "ng", "ә": "a", "і": "i",
})


def strip_symbols(text: str) -> str:
    """Replace emoji/pictographs (category So/Sk) with a space; keep $ € ₽ % + etc."""
    return "".join(" " if unicodedata.category(ch) in ("So", "Sk") else ch for ch in text)


def join_spaced(text: str) -> str:
    text = _PUNCT_RUN.sub(lambda m: re.sub(r"[.\-_*•·|/~^]", "", m.group()), text)
    text = _SPACE_RUN.sub(lambda m: m.group().replace(" ", ""), text)
    return text


def strip_inner_punct(text: str) -> str:
    return _INNER_PUNCT.sub("", text)


def collapse_repeats(text: str) -> str:
    return _REPEAT.sub(r"\1", text)


def deleet(text: str) -> str:
    """'нарк0ту' -> 'наркоту', 'Обн@л' -> 'Обнал'. Only touches words that mix letters with digits/@/$."""
    out = []
    for tok in text.split(" "):
        if (re.search(_LETTER, tok) and re.search(r"[0-9@$]", tok)
                and not re.search(r"\d{3,}", tok) and not re.search(r"[/:]|\.\w", tok)):
            tok = tok.translate(_LEET_CYR if _CYRILLIC.search(tok) else _LEET_LAT)
        out.append(tok)
    return " ".join(out)


def translit_latin_to_cyrillic(text: str) -> str | None:
    """Only for text that is mostly Latin letters. Returns None when not applicable."""
    letters = re.findall(_LETTER, text)
    if len(letters) < 4:
        return None
    latin = sum(1 for ch in letters if "a" <= ch <= "z")
    if latin / len(letters) < 0.8:
        return None
    text = _TRANSLIT_RE.sub(lambda m: _TRANSLIT_MAP[m.group()], text)
    return text.translate(_TRANSLIT_SINGLE)


def cyrillic_to_latin(text: str) -> str | None:
    if not _CYRILLIC.search(text):
        return None
    return text.translate(_CYR_TO_UZ_LATIN)
