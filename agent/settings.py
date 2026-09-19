from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    agent_mode: Literal["authorized-recon", "safe"] = "authorized-recon"
    authorized_scope_file: Path = Path("config/authorized-scope.example.txt")
    require_confirm: bool = True

    llm_provider: Literal["openai", "openrouter", "ollama"] = "openai"
    llm_model: str = "gpt-4o-mini"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "openai/gpt-4o-mini"
    ollama_base_url: str = "http://host.docker.internal:11434/v1"
    ollama_model: str = "qwen2.5:7b-instruct"

    telegram_bot_token: str = ""
    telegram_allowed_chat_ids: str = ""

    kali_container: str = "precog-kali"
    kali_enabled: bool = True

    audit_dir: Path = Path("audit_logs")
    report_dir: Path = Path("reports")

    @property
    def allowed_chat_ids(self) -> set[int]:
        raw = self.telegram_allowed_chat_ids.strip()
        if not raw:
            return set()
        return {int(p.strip()) for p in raw.replace(";", ",").split(",") if p.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
