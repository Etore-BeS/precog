from __future__ import annotations

from typing import Any

import httpx

from agent.settings import Settings


class OpenAICompatProvider:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        extra_headers: dict[str, str] | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.extra_headers = extra_headers or {}

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        body = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.2),
        }
        with httpx.Client(timeout=60.0) as client:
            r = client.post(f"{self.base_url}/chat/completions", headers=headers, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]


def build_provider(settings: Settings) -> OpenAICompatProvider:
    if settings.llm_provider == "openrouter":
        return OpenAICompatProvider(
            settings.openrouter_api_key,
            settings.openrouter_base_url,
            settings.openrouter_model or settings.llm_model,
            {"HTTP-Referer": "https://github.com/Etore-BeS/precog", "X-Title": "Precog"},
        )
    if settings.llm_provider == "ollama":
        return OpenAICompatProvider(
            settings.openai_api_key or "ollama",
            settings.ollama_base_url,
            settings.ollama_model,
        )
    return OpenAICompatProvider(
        settings.openai_api_key,
        settings.openai_base_url,
        settings.llm_model,
    )
