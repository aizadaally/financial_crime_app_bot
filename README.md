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
pip install -r requirements.txt
python -m bot.main
```
Tests: `pytest`.

## Tuning
Weights: strong=3, medium=2, weak=1; invite link=2, t.me link=1. Raise
`BAN_SCORE` for fewer false positives. Use `ALLOWED_DOMAINS` for your own
groups' usernames.
