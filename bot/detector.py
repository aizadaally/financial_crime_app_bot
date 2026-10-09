from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field

from . import obfuscation as obf
from . import rules

_APOSTROPHES = dict.fromkeys(map(ord, "ʻʼ’‘´ʹ"), "'")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


MAX_TEXT = 4096  # Telegram's own message limit; anything longer is cut, bounding regex work
MAX_URLS = 50
MAX_URL_LEN = 2048
MAX_EXTRA_RULES = 200
MAX_PATTERN_LEN = 300
MAX_RULES_FILE_BYTES = 100_000


# Categories whose subject is itself criminal (used by STRICT_MODE). Soft signals such as urgency,
# join-calls, referral programmes or single fake-job phrases are deliberately not in here.
CRIMINAL_CATEGORIES = {
    "carding", "dropper", "fraud", "illegal_goods", "drugs", "laundering", "card_phishing",
    "wallet_theft", "account_buying", "loan_scam", "impersonation",
}
_CRIMINAL_SUFFIXES = ("_dropper", "_fraud")

# Text that talks ABOUT crime (warnings, news, advice) rather than offering it.
WARNING_CONTEXT = re.compile(
    r"борьб\w+\s+с|новост|сообщил\w*\s+(?:полиц|мвд)|задержа\w+|арестова\w+|осужд\w+|приговорил|предупреж\w+|"
    r"осторожн|берегитесь|не\s+(?:сообщайте|говорите|давайте|переводите|делитесь|называйте)|никому\s+не|"
    r"мошенник\w*\s+(?:звон|просят|пишут|предлага|обманыва)|как\s+(?:защитить|не\s+попасть)|"
    r"\bbeware\b|\bwarning\b|never\s+share|do\s+not\s+share|scam\s+alert|police\s+(?:arrested|detained)|"
    r"абайлаңыз|сақ\s+болыңыз|сергек\s+болуңуз|абайлагыла|ehtiyot\s+bo['`]?ling|огоҳ\s+бошед|üns\s+beriň",
    re.I,
)


def is_warning_context(text: str) -> bool:
    return bool(WARNING_CONTEXT.search(normalize(text or "")))


@dataclass
class Verdict:
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)

    @property
    def criminal_hit(self) -> str | None:
        for c in sorted(self.categories):
            if c in CRIMINAL_CATEGORIES or c.endswith(_CRIMINAL_SUFFIXES):
                return c
        return None

    def is_spam(self, threshold: int) -> bool:
        return self.score >= threshold


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).lower()
    text = text.replace("\u0307", "")  # dotted İ -> i
    text = text.translate(_APOSTROPHES)
    # "д р о п" / "д.р.о.п" style spacing is collapsed by variants() below.
    return re.sub(r"\s+", " ", text)


def _family(category: str) -> str:
    """uz_dropper / kz_dropper / dropper are the same idea in different languages."""
    return re.sub(r"^(?:uz|kz|kg|tj|tm|kk|ky|tg|tk)_", "", category)


def variants(text: str) -> list[str]:
    """The message as written, plus de-obfuscated readings (spaced letters, leetspeak, emoji between
    letters, repeated letters, look-alike letters, Russian typed in Latin, Cyrillic Uzbek in Latin)."""
    base = normalize(text)
    # keep double spaces as word breaks while joining spaced-out letters ("п р о д а ю  н а р к о т у")
    spaced = re.sub(r"[ \t]{2,}", " \u00a6 ", unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).lower())
    clean = obf.join_spaced(obf.strip_symbols(spaced)).replace("\u00a6", " ")
    clean = re.sub(r"\s+", " ", clean).strip()
    out = [base, base.translate(rules.CYR_TO_LAT), base.translate(rules.LAT_TO_CYR)]
    if clean != base:
        out.append(clean)
    out.append(obf.collapse_repeats(obf.strip_inner_punct(clean)))
    deleeted = obf.deleet(obf.strip_inner_punct(clean))
    out.append(deleeted)
    out.append(deleeted.translate(rules.LAT_TO_CYR))
    for source in (clean, deleeted):
        for fn in (obf.translit_latin_to_cyrillic, obf.cyrillic_to_latin):
            v = fn(source)
            if v:
                out.append(v)
    return list(dict.fromkeys(out))


_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*}][^()]*\)\s*[+*{]")
_PROBE_CODE = (
    "import re,sys;rx=re.compile(sys.stdin.read(),re.I)\n"
    "for p in ('a'*3000+'!','a '*1500+'!','а'*3000+'!','.'*3000+'!','ab'*1500+'!'): rx.search(p)"
)


def _assert_regex_safe(pattern: str) -> None:
    """Reject user-supplied regexes that could stall the bot (catastrophic backtracking)."""
    re.compile(pattern)  # syntax check
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError(f"extra rule has a nested quantifier (ReDoS risk): {pattern[:60]}")
    try:  # run in a throwaway process so a runaway pattern cannot hang us
        subprocess.run([sys.executable, "-I", "-c", _PROBE_CODE], input=pattern, text=True, timeout=2, check=True, capture_output=True)
    except subprocess.TimeoutExpired:
        raise ValueError(f"extra rule is too slow (ReDoS risk): {pattern[:60]}") from None


class Detector:
    def __init__(self, allowed_domains: set[str] | None = None, extra_rules_file: str | None = None):
        self.allowed = {d.lower().lstrip("@") for d in (allowed_domains or set())}
        self.keyword_rules = [(c, w, re.compile(p, re.I)) for c, w, p in rules.KEYWORD_RULES]
        self.cta_rules = [(c, w, re.compile(p, re.I)) for c, w, p in rules.JOIN_CTA_RULES]
        self.invite_re = re.compile(rules.INVITE_LINK_RE, re.I)
        self.tme_re = re.compile(rules.TME_USERNAME_RE, re.I)
        if extra_rules_file:
            self._load_extra(extra_rules_file)

    def _load_extra(self, path: str) -> None:
        """JSON: {"keywords": [{"category": "x", "weight": 3, "pattern": "..."}]}"""
        if os.path.getsize(path) > MAX_RULES_FILE_BYTES:
            raise ValueError("extra rules file is too large")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("keywords", [])
        if len(items) > MAX_EXTRA_RULES:
            raise ValueError("too many extra rules")
        for r in items:
            pattern = str(r["pattern"])
            if len(pattern) > MAX_PATTERN_LEN:
                raise ValueError("extra rule pattern too long")
            weight = max(0, min(int(r.get("weight", 3)), 5))
            _assert_regex_safe(pattern)
            self.keyword_rules.append((str(r.get("category", "custom"))[:30], weight, re.compile(pattern, re.I)))

    def _is_allowed(self, name: str) -> bool:
        return name.lower() in self.allowed

    def analyze(self, text: str, link_urls: list[str] | None = None) -> Verdict:
        v = Verdict()
        if not text and not link_urls:
            return v
        blob = (text or "")[:MAX_TEXT]
        if link_urls:
            blob += "\n" + "\n".join(u[:MAX_URL_LEN] for u in link_urls[:MAX_URLS])
        blob = blob[: MAX_TEXT * 2]  # hard cap on total work per message

        seen: set[str] = set()
        keyword_hit = False
        for index, variant in enumerate(variants(blob)):
            # A disguised/transliterated reading may add NEW kinds of evidence but must not count an idea
            # a second time (the same word matched in two alphabets is still one word).
            already = {_family(c) for c in v.categories} if index else set()
            for cat, weight, rx in self.keyword_rules:
                if _family(cat) in already:
                    continue
                m = rx.search(variant)
                if m and (cat, rx.pattern) not in seen:
                    seen.add((cat, rx.pattern))
                    v.score += weight
                    v.reasons.append(f"{cat}:{m.group(0)[:40]}")
                    v.categories.add(cat)
                    keyword_hit = True

        invite_hit = False
        base = normalize(blob)
        for m in self.invite_re.finditer(base):
            invite_hit = True
            v.score += rules.INVITE_LINK_WEIGHT
            v.reasons.append("invite_link")
            break
        tme_names = [m.group("name") for m in self.tme_re.finditer(base)]
        tme_names = [n for n in tme_names if not self._is_allowed(n)]
        if tme_names:
            v.score += rules.TME_LINK_WEIGHT
            v.reasons.append(f"tme_link:{tme_names[0]}")

        # Join-call-to-action only amplifies another signal.
        if keyword_hit or invite_hit or tme_names:
            for variant in variants(blob)[:1]:
                for cat, weight, rx in self.cta_rules:
                    m = rx.search(variant)
                    if m:
                        v.score += weight
                        v.reasons.append(f"{cat}:{m.group(0)[:30]}")
                        break
        return v
