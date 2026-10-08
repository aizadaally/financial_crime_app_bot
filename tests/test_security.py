import json
import time

import pytest

from bot.detector import Detector
from bot.main import defang

d = Detector()

ADVERSARIAL = [
    "a" * 100_000,
    "a " * 50_000,
    "д " * 50_000,
    "." * 100_000,
    "t.me/" * 20_000,
    "https://t.me/+" + "a" * 100_000,
    "к а р д и н г " * 10_000,
    "​" * 100_000,
    "дроп" * 30_000,
    "(" * 5000 + "a" * 5000,
]


@pytest.mark.parametrize("payload", ADVERSARIAL)
def test_adversarial_input_is_fast(payload):
    start = time.perf_counter()
    d.analyze(payload, [payload] * 100)
    assert time.perf_counter() - start < 1.0


def test_defang_makes_links_inert():
    out = defang("join https://t.me/+AbC and t.me/x www.evil.com tg://join?invite=1 @user")
    for bad in ("http://", "https://", "t.me", "tg://", "www.", "@"):
        assert bad not in out.lower()


def test_extra_rules_reject_redos(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"keywords": [{"pattern": "(a+)+$", "weight": 3}]}))
    with pytest.raises(ValueError):
        Detector(extra_rules_file=str(f))


def test_extra_rules_reject_bad_regex_and_huge_file(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"keywords": [{"pattern": "([", "weight": 3}]}))
    with pytest.raises(Exception):
        Detector(extra_rules_file=str(f))
    f.write_text(" " * 200_000)
    with pytest.raises(ValueError):
        Detector(extra_rules_file=str(f))


def test_extra_rules_valid_and_weight_capped(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"keywords": [{"pattern": "foobarspam", "weight": 999}]}))
    det = Detector(extra_rules_file=str(f))
    assert det.analyze("foobarspam").score == 5
