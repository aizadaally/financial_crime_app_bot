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

## Smart AI layer (optional)
Rules are fast and free but can't know every scam wording. With `AI_ENABLED=true` and an
`ANTHROPIC_API_KEY`, messages that look suspicious (rules flagged them, or they contain a
link / @contact / phone number / money amount) are also checked by Claude, which understands meaning
in all 7 languages. Result: **high confidence → delete + ban**, **medium → delete only**, low/not a scam → nothing.
If the AI is down, slow, rate-capped or answers badly, the bot silently falls back to rules only.
Privacy: only the message text is sent (never names or ids); tell your members. See `SECURITY.md`.

## Strict mode
`STRICT_MODE=true` bans any message whose subject is criminal (one signal is enough), but spares text that reads like a warning, news or advice ("будьте осторожны", "полиция задержала…").

## Ban, mute or temporary
`PUNISHMENT=ban` (default) removes the sender; `PUNISHMENT=mute` keeps them in the group but unable to write.
`PUNISH_MINUTES=60` makes either one lift automatically after an hour. Once a person has been banned, Telegram
may stop admins re-adding them (they must rejoin via an invite link and, if "Approve New Members" is on, be approved).
Mute avoids this: an admin just lifts the restriction in the group's member list.

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
