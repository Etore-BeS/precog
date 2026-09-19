# Precog Fatia 1 Implementation Plan

> **For agentic workers:** Implement task-by-task. **1-hour prototype bias: smallest working vertical slice first.**

**Goal:** Working Precog prototype: Firegod-adapted agent + Telegram e2e + OpenAI/OpenRouter + authorized-recon gating + minimal Kali Docker + Brazil OSINT pack.

**Architecture:** New Origin repo. Start from Firegod AI concepts/structure (https://github.com/Firegod1991/firegod-ai) — inspect license & layout first; do not blindly copy. Prefer Python + Docker Compose. Harden with scope/confirm/audit. Add Telegram + cloud LLM providers. Minimal Kali sidecar for tools.

**Tech Stack:** Python 3.11+, Docker Compose, python-telegram-bot (or httpx long-poll), openai SDK / OpenRouter-compatible API, pytest.

## Global Constraints
- Default `AGENT_MODE=authorized-recon`
- No secrets in repo; `.env.example` only
- Tests offline, no real targets
- No `--privileged`; non-root when possible
- Ship > polish; skip ISO/VM build
- Credit Unishka for BR source map; no illegal scrapers

---

## Task 1: Scaffold repo from Firegod reference
- [ ] Inspect Firegod repo structure, license, entrypoints
- [ ] Create Precog skeleton (README, LICENSE notes, .env.example, .gitignore, .dockerignore)
- [ ] docs/IMPLEMENTATION_PLAN.md + link design
- [ ] Commit

## Task 2: Core agent + providers + policies
- [ ] agent/core plan/run loop
- [ ] Providers: OpenAI, OpenRouter (Ollama stub optional)
- [ ] Policies: scope file validation, confirm gate, mode
- [ ] Audit JSON logger + report MD/JSON
- [ ] CLI: doctor, plan, run, tools list, audit list
- [ ] Unit tests (mocks)
- [ ] Commit

## Task 3: Telegram e2e
- [ ] Long-polling bot; allowlist chat ids
- [ ] Plan → inline approve/reject → run → send summary + files
- [ ] Env: TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHAT_IDS
- [ ] Commit

## Task 4: Kali Docker + compose
- [ ] kali/Dockerfile minimal + essential packages
- [ ] docker-compose.yml with profiles kali, ollama
- [ ] Wire agent to tools via docker exec or HTTP sidecar — document choice
- [ ] Healthcheck
- [ ] Commit

## Task 5: Brazil OSINT pack
- [ ] osint/brazil/sources.yaml
- [ ] Skills: empresa, pessoa-publica, transparencia, geo-ambiental
- [ ] CNPJ wrapper + CPF guardrail
- [ ] docs/OSINT_BRAZIL.md
- [ ] Tests with mocks
- [ ] Commit

## Task 6: Docs + doctor + smoke
- [ ] README quickstart (1-hour path)
- [ ] docs/INSTALLATION.md, SECURITY.md, vm/README stub
- [ ] doctor validates env
- [ ] pytest offline green
- [ ] Final summary: how to run, env vars, known limits

## Done when
User can set .env (Telegram + OpenAI or OpenRouter), docker compose --profile kali up --build, message the bot, approve a plan against scoped target, get a report.
