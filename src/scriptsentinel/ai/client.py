"""Unified Multi-Provider AI Client for ScriptSentinel.

Provides zero-dependency access to leading frontier models and custom endpoints:
- Anthropic (Claude 3.5 Sonnet, Claude 3.7 Sonnet, Haiku, Opus)
- OpenAI (GPT-4o, o1, o3-mini)
- OpenRouter (DeepSeek, Llama, Mistral, all hosted models)
- Custom / Local OpenAI-Compatible APIs (vLLM, Ollama, LM Studio, custom base URLs)

Auto-detects credentials from CLI arguments or environment variables:
- ANTHROPIC_API_KEY
- OPENAI_API_KEY
- OPENROUTER_API_KEY
- AI_API_KEY / AI_API_BASE
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class AIConfig:
    """Configuration for the AI engine."""
    provider: str
    api_key: str | None
    api_base: str | None
    model: str
    temperature: float = 0.2
    timeout_seconds: float = 45.0

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key) or bool(self.api_base and "localhost" in self.api_base)


class AIClient:
    """Unified client for invoking AI reasoning engines."""

    def __init__(
        self,
        config: AIConfig | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.config = config or self.auto_detect()
        self._provided_client = http_client
        self._owned_client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._provided_client is not None:
            return self._provided_client
        if self._owned_client is None:
            self._owned_client = httpx.Client(timeout=self.config.timeout_seconds)
        return self._owned_client

    def close(self) -> None:
        if self._owned_client is not None:
            self._owned_client.close()
            self._owned_client = None

    def __enter__(self) -> AIClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    @property
    def is_available(self) -> bool:
        return self.config.is_configured

    @classmethod
    def auto_detect(
        cls,
        api_key: str | None = None,
        api_base: str | None = None,
        provider: str | None = None,
        model: str | None = None,
    ) -> AIConfig:
        """Auto-detects the best available AI provider and configuration."""
        key = api_key or os.environ.get("AI_API_KEY")
        base = api_base or os.environ.get("AI_API_BASE")
        prov = provider or os.environ.get("AI_PROVIDER")
        mdl = model or os.environ.get("AI_MODEL")

        # 1. Anthropic check
        if not key:
            anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
            if anthropic_key:
                key = anthropic_key
                prov = prov or "anthropic"
                mdl = mdl or "claude-3-5-sonnet-20241022"

        # 2. OpenAI check
        if not key:
            openai_key = os.environ.get("OPENAI_API_KEY")
            if openai_key:
                key = openai_key
                prov = prov or "openai"
                mdl = mdl or "gpt-4o"

        # 3. OpenRouter check
        if not key:
            openrouter_key = os.environ.get("OPENROUTER_API_KEY")
            if openrouter_key:
                key = openrouter_key
                prov = prov or "openrouter"
                mdl = mdl or "anthropic/claude-3.5-sonnet"

        # 4. Custom endpoint fallback (e.g. Ollama localhost)
        if not prov:
            if base:
                prov = "custom"
                mdl = mdl or "default"
            else:
                prov = "none"
                mdl = mdl or "none"

        return AIConfig(
            provider=prov.lower(),
            api_key=key,
            api_base=base,
            model=mdl or "default",
        )

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generates a text completion across any configured provider."""
        if not self.is_available:
            raise RuntimeError(
                "AI engine is not configured. Supply --api-key or set ANTHROPIC_API_KEY, "
                "OPENAI_API_KEY, OPENROUTER_API_KEY, or AI_API_KEY environment variable."
            )

        if self.config.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)

        return self._call_openai_compatible(system_prompt, user_prompt)

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.config.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.config.model if self.config.model != "default" else "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": self.config.temperature,
        }

        resp = self._get_client().post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return str(data["content"][0]["text"])

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> str:
        if self.config.provider == "openrouter":
            base = "https://openrouter.ai/api/v1"
            model = self.config.model if self.config.model != "default" else "anthropic/claude-3.5-sonnet"
        elif self.config.provider == "openai":
            base = "https://api.openai.com/v1"
            model = self.config.model if self.config.model != "default" else "gpt-4o"
        else:
            base = (self.config.api_base or "http://localhost:11434/v1").rstrip("/")
            model = self.config.model

        url = f"{base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key or 'anonymous'}",
            "content-type": "application/json",
        }
        if self.config.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/Monar-HQ/scriptsentinel"
            headers["X-Title"] = "ScriptSentinel"

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.config.temperature,
        }

        resp = self._get_client().post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return str(data["choices"][0]["message"]["content"])
