#!/bin/bash
echo "🧹 Cleaning up old files..."

# ── Delete old LLM files ──
rm -f app/llm_config.py app/llm_memory.py app/llm_provider.py
rm -f app/llm_reasoning.py app/llm_system_prompt.py app/llm_tools.py

# ── Delete old routers ──
rm -f app/routers/llm.py app/routers/subdomain.py

# ── Delete old database ──
rm -f app/database.py

# ── Delete old automation ──
rm -f app/automation.py app/scheduler.py

# ── Delete old port_scanner ──
rm -f app/port_scanner.py

# ── Delete old modules ──
rm -rf app/modules/
rm -f app/modules.py

echo "✅ Cleanup complete!"
