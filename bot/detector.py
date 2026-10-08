from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field

from . import rules

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


@dataclass
class Verdict:
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def is_spam(self, threshold: int) -> bool:
        return self.score >= threshold


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).lower()
    # "д р о п" / "д.р.о.п" style spacing is collapsed by variants() below.
    return re.sub(r"\s+", " ", text)


def variants(text: str) -> list[str]:
    base = normalize(text)
    out = [base, base.translate(rules.CYR_TO_LAT), base.translate(rules.LAT_TO_CYR)]
    # collapse single-letter separators: "к а р д и н г" -> "кардинг"
    out.append(re.sub(r"(?<=\b\w)[\s.\-_*]+(?=\w\b)", "", base))
    return list(dict.fromkeys(out))


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
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for r in data.get("keywords", []):
            self.keyword_rules.append((r.get("category", "custom"), int(r.get("weight", 3)), re.compile(r["pattern"], re.I)))

    def _is_allowed(self, name: str) -> bool:
        return name.lower() in self.allowed

    def analyze(self, text: str, link_urls: list[str] | None = None) -> Verdict:
        v = Verdict()
        if not text and not link_urls:
            return v
        blob = text or ""
        if link_urls:
            blob += "\n" + "\n".join(link_urls)

        seen: set[str] = set()
        keyword_hit = False
        for variant in variants(blob):
            for cat, weight, rx in self.keyword_rules:
                m = rx.search(variant)
                if m and (cat, rx.pattern) not in seen:
                    seen.add((cat, rx.pattern))
                    v.score += weight
                    v.reasons.append(f"{cat}:{m.group(0)[:40]}")
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
