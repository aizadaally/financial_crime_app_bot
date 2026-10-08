# Financial-crime spam filter bot (Telegram)

Watches group/supergroup messages (including edits and captions), scores them
against keyword/regex/link rules, and **deletes the message and bans the
sender** when the score reaches `BAN_SCORE` (default 4). Chat admins and
whitelisted users are never touched.

## What it detects
- Carding, stolen data, dumps/CVV, sniffers
- Dropper / cash-out / money-mule recruitment
- Fraud tooling and services (phishing kits, "пробив", fake documents, KYC bypass)
- Illegal "easy money" schemes
- Invites to join other chats/channels (`t.me/+…`, `joinchat`, `t.me/name`, hidden
  text-link/button URLs) – a link alone scores low, a link plus criminal wording bans
- English, Russian, Uzbek (Latin+Cyrillic), Kazakh, Kyrgyz, Tajik and Turkmen phrasing (`bot/rules_regional.py`; first-pass wording, tune with real samples)
- Social-engineering scams in all 7 languages: fake "easy job" offers, requests for card details or SMS codes, urgent "lend me money, my card is not working" messages (`bot/rules_scams.py`)
- Light obfuscation: spaced letters, zero-width chars, Latin/Cyrillic look-alikes

Rules live in `bot/rules.py`. Add your own without code changes via
`EXTRA_RULES_FILE`:

```json
{"keywords": [{"category": "custom", "weight": 3, "pattern": "your regex"}]}
```

## Run
1. Create a bot with @BotFather, **disable privacy mode** (`/setprivacy` → Disable).
2. Add it to your group as admin with *Delete messages* and *Ban users* rights.
3. `cp .env.example .env`, fill in `BOT_TOKEN`, then:
```
pip install -r requirements.txt   # (requirements-dev.txt adds pytest)
python -m bot.main
```
Set `DRY_RUN=true` to only log and report (no deleting or banning) while testing.
See `GO_LIVE.md` (step-by-step launch) and `SECURITY.md` (threat model).
Tests: `pip install -r requirements-dev.txt && pytest`.

## Tuning
Weights: strong=3, medium=2, weak=1; invite link=2, t.me link=1. Raise
`BAN_SCORE` for fewer false positives. Use `ALLOWED_DOMAINS` for your own
groups' usernames.
