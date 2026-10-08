# Security design

| Risk | Mitigation |
|---|---|
| Token theft | Token only in `.env` (git-ignored, docker-ignored); format checked at start; never logged; revoke with `/revoke` in BotFather |
| Clicking criminal links | Bot never opens, fetches or resolves any URL. Reports sent to `LOG_CHAT_ID` are defanged (`hxxp://`, `t[.]me`, no `@`) with link previews off |
| Regex DoS / huge messages | Input capped to 8 KB; custom rules limited in size/count, checked for nested quantifiers and probed in a throwaway process with a 2 s timeout |
| Bot added to strangers' chats | `ALLOWED_CHAT_IDS`: bot ignores and leaves any other chat |
| Banning the wrong person | Admins, bots, channel posts and `WHITELIST_USER_IDS` are skipped; if admin status can't be verified the bot does nothing; `DRY_RUN` mode |
| Data privacy | No database, no message storage. Console log has user id, score and rule names only |
| Supply chain | Two pinned dependencies, `pip-audit` clean, run in CI |
| Server compromise | Docker: non-root user, read-only filesystem, all capabilities dropped, memory limit |
| Least privilege | Give the bot only *Delete messages* and *Ban users* |
| AI layer: prompt injection | Message is untrusted data inside tags (tags neutralised); the model has no tools and can only return a fixed JSON schema; a fooled AI can at worst say "not a scam", the rules still apply, and only the sender can ever be acted on |
| AI layer: privacy & cost | Off by default; only suspicious messages; text only (no names/ids); text cut to 1500 chars; results cached; per-minute call cap; API key only in `.env` |
| AI layer: failures | Timeout / error / refusal / invalid output / cap reached -> no verdict -> rules only. Admins are checked before any AI call |
