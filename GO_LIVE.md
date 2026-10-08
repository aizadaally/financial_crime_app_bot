# Going live – step by step (no experience needed)

## Part A – Test on your own computer (free, 15 minutes)
1. Install Python 3.11+ (python.org) and Git.
2. In Telegram talk to **@BotFather** → `/newbot` → follow the questions → copy the **token**.
   Then `/setprivacy` → your bot → **Disable**. Also send `/setjoingroups` → your bot → **Enable**.
3. Create a **new empty test group** in Telegram and add your bot. Make the bot an admin and tick only
   **Delete messages** and **Ban users**.
4. In a terminal:
   ```
   git clone https://github.com/aizadaally/financial_crime_app_bot
   cd financial_crime_app_bot
   git checkout claude/telegram-spam-filter-bot-jchk6l
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -r requirements-dev.txt
   pytest -q                        # all tests must pass
   cp .env.example .env             # Windows: copy .env.example .env
   ```
5. Open `.env` in a text editor and set `BOT_TOKEN=` to your token. Leave `DRY_RUN=true`.
6. Run: `python -m bot.main`. Leave the window open.
7. From a **second, non-admin Telegram account** post this in the test group:
   `Ищем дропов, обнал! Пиши в лс https://t.me/+AbCdEf123`
   In the terminal you should see `[DRY RUN] spam from ...`. The message stays (dry run).
8. Set `DRY_RUN=false` in `.env`, restart the bot (Ctrl+C, run again) and post it again:
   the message is deleted and that second account is banned. (Unban it in group settings → Administrators → Removed users.)

## Part B – Run it 24/7
Your computer must stay on, so use a small server (VPS, ~US$4–6/month, e.g. Hetzner, DigitalOcean, Vultr).
1. Create an Ubuntu server, log in with SSH (use SSH keys, not a password) and install Docker:
   `curl -fsSL https://get.docker.com | sh`
2. Get the code and your settings onto the server:
   ```
   git clone https://github.com/aizadaally/financial_crime_app_bot && cd financial_crime_app_bot
   git checkout claude/telegram-spam-filter-bot-jchk6l
   cp .env.example .env && nano .env      # paste token, set ALLOWED_CHAT_IDS, LOG_CHAT_ID
   ```
3. Start: `docker compose up -d --build`
   Watch logs: `docker compose logs -f` · Stop: `docker compose down` · Update: `git pull && docker compose up -d --build`
4. Server safety: `ufw allow OpenSSH && ufw enable` (the bot needs no open ports – it only calls out to Telegram),
   disable SSH password login, and keep the server updated (`apt update && apt upgrade`).

## Part C – Roll out safely
1. Week 1: `DRY_RUN=true` in your real groups, with `LOG_CHAT_ID` set (a private group only you/admins are in).
   Read every "WOULD BAN" report. If any are innocent, raise `BAN_SCORE` or tell me the message and I'll fix the rule.
2. Then `DRY_RUN=false`.
3. Set `ALLOWED_CHAT_IDS` to your real group ids so nobody can use your bot elsewhere.
   To find an id: put `ALLOWED_CHAT_IDS` empty, add the bot, watch logs, or temporarily add @RawDataBot.
   Group ids look like `-1001234567890`.

## Golden rules
- Never share or screenshot the token. If leaked → BotFather → `/revoke`.
- Never click links in the criminal chats/spam you collect. Copy the **text** only.
- Give the bot only Delete + Ban rights.
