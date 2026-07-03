"""Model construction without embedding provider credentials in source."""
from __future__ import annotations

import os
import httpx

from langchain_openai import ChatOpenAI


def _build_http_clients() -> dict:
    """Build httpx clients with optional TLS bypass for proxy environments.

    Local firewalls/proxies may inject self-signed certificates that break
    certifi-based verification. Set DEEPSEEK_VERIFY_TLS=false to bypass.
    """
    verify_tls = os.getenv("DEEPSEEK_VERIFY_TLS", "true").lower() != "false"
    if verify_tls:
        return {}
    return {
        "http_client": httpx.Client(verify=False),
        "http_async_client": httpx.AsyncClient(verify=False),
    }


def build_model() -> ChatOpenAI:
    """Build the configured tool-calling chat model.

    DeepSeek is accessed through its OpenAI-compatible API. OpenAI-compatible
    providers can also be selected by setting TRACE_AGENT_MODEL_PROVIDER=openai.
    """
    provider = os.getenv("TRACE_AGENT_MODEL_PROVIDER", "deepseek").lower()
    http_kwargs = _build_http_clients()

    if provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY is required. Start through "
                "scripts/start_deep_agent_backend.ps1 or set it explicitly."
            )
        return ChatOpenAI(
            api_key=api_key,
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            temperature=0,
            timeout=float(os.getenv("DEEPSEEK_TIMEOUT", "120")),
            max_retries=2,
            **http_kwargs,
            profile={
                "max_input_tokens": int(
                    os.getenv("TRACE_AGENT_CONTEXT_WINDOW", "64000")
                ),
                "max_output_tokens": int(
                    os.getenv("TRACE_AGENT_MAX_OUTPUT_TOKENS", "8192")
                ),
                "tool_calling": True,
                "tool_choice": True,
                "structured_output": True,
            },
        )

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for the OpenAI provider.")
        return ChatOpenAI(
            api_key=api_key,
            model=os.getenv("OPENAI_MODEL", "gpt-4.1"),
            temperature=0,
            timeout=float(os.getenv("OPENAI_TIMEOUT", "120")),
            max_retries=2,
            **http_kwargs,
        )

    raise RuntimeError(
        f"Unsupported TRACE_AGENT_MODEL_PROVIDER={provider!r}; "
        "supported providers: deepseek, openai"
    )

