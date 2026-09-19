# Installation

```bash
cd ~/Code/precog
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# edit .env — at least LLM key and/or Telegram

precog doctor
precog plan-run "passive recon example.com" --target example.com --yes
```

Docker:

```bash
cp .env.example .env
docker compose --profile kali up --build
```

Telegram:

```bash
# set TELEGRAM_BOT_TOKEN + TELEGRAM_ALLOWED_CHAT_IDS
precog telegram
```
