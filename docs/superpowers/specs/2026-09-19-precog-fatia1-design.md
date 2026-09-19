# Precog Fatia 1 — Design (congelado 2026-09-19)

## Objetivo
Protótipo out-of-box de plataforma OSINT/recon defensiva **Precog**: fork/adaptação do [Firegod AI](https://github.com/Firegod1991/firegod-ai) + tools estilo Trace Labs Kali + Telegram e2e + OpenAI/OpenRouter + pacote OSINT Brasil. Repo novo no **Cursor Origin**. Pasta local do usuário: `~/Code/precog` (hoje vazia).

## Decisões
- Abordagem **B**: fork/adaptar Firegod (não greenfield puro).
- Default mode: **`authorized-recon`** (não `safe`).
- Ainda obrigatório: `authorized-scope` + confirmação explícita + audit para ações intrusivas.
- Manter **mais** do Firegod ligado (OSINT + suite recon/pentest), atrás do portão de modo/escopo/confirmação.
- Telegram **e2e** no dia 1 (long-polling); allowlist `TELEGRAM_ALLOWED_CHAT_IDS`.
- Providers dia 1: **OpenAI e OpenRouter** (`LLM_PROVIDER=openai|openrouter`); Ollama opcional (profile).
- Docker Compose: `agent` + profile `kali` (imagem mínima) + profile `ollama` opcional.
- **BR OSINT pesado** no dia 1: `osint/brazil/sources.yaml`, skills, wrapper CNPJ, guardrail CPF, `docs/OSINT_BRAZIL.md`.
- ISO/VM Trace Labs: **fora** (só stub `vm/` + doc).
- Meta: protótipo **funcionando em ~1 hora** — ship > polish.

## Arquitetura
```
agent/          # core, providers (openai/openrouter/ollama), telegram, cli, policies, audit
osint/brazil/   # sources.yaml, skills, wrappers
kali/           # Dockerfile mínimo + packages
docker/         # compose (+ profiles)
config/         # authorized-scope.example.txt
docs/           # INSTALLATION, SECURITY, OSINT_BRAZIL, IMPLEMENTATION_PLAN, vm stub
tests/          # offline/mocks only
```

## Aceite fatia 1
1. `docker compose --profile kali up --build` sobe agent (+ kali).
2. Telegram: mensagem → plan → aprovar/rejeitar → run → resumo + report.
3. LLM via OpenAI **ou** OpenRouter.
4. Default `authorized-recon`; escopo + confirmação + audit.
5. Tools Firegod principais preservadas atrás do portão.
6. BR: catálogo + skills + CNPJ wrapper + docs.
7. `agent doctor` + testes offline.
8. Stub `vm/` documentado.

## Fora de escopo (fatia 1)
ISO Trace Labs, Ollama obrigatório, polish translate/CVE, deploy produção.

## Legal
Somente OSINT passivo / lab / ativos autorizados. Sem secrets no git. `.env.example` apenas.
