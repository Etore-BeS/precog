# Precog

Authorized OSINT / recon defensive agent — **fatia-1 prototype**.

Inspired by [Firegod AI](https://github.com/Firegod1991/firegod-ai) (clean-room; not a vendor copy).

## Quick start (~1 hour path)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # add OPENAI_API_KEY or OPENROUTER_API_KEY; Telegram optional

# ensure example.com (or your lab host) is in config/authorized-scope.example.txt
precog doctor
precog tools
precog plan-run "passive recon on example.com" --target example.com --yes
precog telegram   # long-poll: plan → approve/reject → run → report
```

Docker + Kali sidecar (no `--privileged`):

```bash
docker compose --profile kali up --build
```

## CLI

`precog doctor | plan | plan-run | tools | audit | report | telegram`

## Defaults

- `AGENT_MODE=authorized-recon`
- Scope file + confirm gate + JSONL audit
- LLM: OpenAI or OpenRouter (`LLM_PROVIDER`)
- Ollama: compose profile only
- Brazil pack: `osint/brazil/` + `docs/OSINT_BRAZIL.md`

## Legal

Only against assets you own or have explicit written authorization to test. No CPF fishing. No secrets in git.
