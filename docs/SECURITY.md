# Security & authorization

- Default mode: `authorized-recon`
- Every target must appear in `AUTHORIZED_SCOPE_FILE`
- Confirm gate (`REQUIRE_CONFIRM=true`) before execution
- Append-only JSONL audit under `audit_logs/`
- No secrets in git — `.env` only locally
- Kali container runs **without** `--privileged`
- CPF lookups are hard-blocked (LGPD)
- Use only on assets you own or have written authorization to test

Inspired by [Firegod AI](https://github.com/Firegod1991/firegod-ai) — clean-room reimplementation, not a vendor copy.
