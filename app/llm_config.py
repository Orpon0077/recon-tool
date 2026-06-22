# ── LLM Configuration ──────────────────────────────────────
# This file stores all LLM settings like API keys, model names, etc.

import os
from typing import Optional

# ── Which LLM provider to use ──
# Options: "deepseek", "openai", "claude", "local"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek")

# ── API Keys (get from environment variables) ──
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ── Local LLM (Ollama) settings ──
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")

# ── Model specific configurations ──
MODEL_CONFIG = {
    "deepseek": {
        "model": "deepseek-chat",
        "max_tokens": 4096,
        "temperature": 0.7,
    },
    "openai": {
        "model": "gpt-4o-mini",
        "max_tokens": 4096,
        "temperature": 0.7,
    },
    "claude": {
        "model": "claude-3-haiku-20240307",
        "max_tokens": 4096,
        "temperature": 0.7,
    },
    "local": {
        "model": OLLAMA_MODEL,
        "max_tokens": 4096,
        "temperature": 0.7,
    }
}

def get_config() -> dict:
    """Get current LLM configuration"""
    return {
        "provider": LLM_PROVIDER,
        "config": MODEL_CONFIG.get(LLM_PROVIDER, MODEL_CONFIG["deepseek"]),
        "api_key": {
            "deepseek": DEEPSEEK_API_KEY,
            "openai": OPENAI_API_KEY,
            "claude": ANTHROPIC_API_KEY,
        }.get(LLM_PROVIDER, ""),
        "ollama_url": OLLAMA_URL,
    }
