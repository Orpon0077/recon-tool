# ── LLM Provider (Optimized) ──
import aiohttp
import os
import json
import asyncio
from typing import List, Dict

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"

class LLMProvider:
    def __init__(self):
        self.api_url = os.getenv("LLM_API_URL", "http://192.168.125.170:1234/api/v1/chat")
        self.model = os.getenv("LLM_MODEL", "google/gemma-4-12b")
        print(f"[LLM] Using API: {self.api_url}")
        print(f"[LLM] Model: {self.model}")
    
    async def chat(self, messages: List[Dict]) -> str:
        # ── Extract user message ──
        user_message = ""
        for msg in messages:
            if msg["role"] == "user":
                user_message = msg["content"]
        
        if not user_message:
            return "Please provide a message."
        
        # ── Check if it's a simple greeting ──
        if user_message.lower() in ["hello", "hi", "hey", "how are you"]:
            return "Hello! I am Recon Assistant. I can help you scan websites for security, technology, and infrastructure. Try 'Help' for more information."
        
        # ── Try LLM with short timeout ──
        try:
            result = await self._call_llm(messages)
            if result and not result.startswith("❌"):
                return result
        except Exception as e:
            print(f"[LLM] LLM call failed: {e}")
        
        # ── Fallback: Quick response ──
        return "I am Recon Assistant. Please tell me what you want to scan. Example: 'Full scan axiler.com' or 'Firewall of axiler.com' or type 'Help' for more options."
    
    async def _call_llm(self, messages: List[Dict]) -> str:
        """Call LLM API"""
        user_message = ""
        system_prompt = ""
        
        for msg in messages:
            if msg["role"] == "user":
                user_message = msg["content"]
            elif msg["role"] == "system":
                system_prompt = msg["content"]
        
        if not user_message:
            return ""
        
        payload = {
            "model": self.model,
            "system_prompt": system_prompt or "You are a helpful assistant. Be very brief and concise.",
            "input": user_message
        }
        
        print(f"[LLM] Sending: {user_message[:30]}...")
        
        timeout = aiohttp.ClientTimeout(total=30, connect=5)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(
                    self.api_url,
                    json=payload,
                ) as response:
                    text = await response.text()
                    
                    if response.status != 200:
                        print(f"[LLM] API Error: {response.status}")
                        return ""
                    
                    try:
                        data = json.loads(text)
                    except:
                        return text[:200]
                    
                    if "output" in data and isinstance(data["output"], list):
                        for item in data["output"]:
                            if isinstance(item, dict) and item.get("type") == "message":
                                return item.get("content", "")
                        if len(data["output"]) > 0:
                            first = data["output"][0]
                            if isinstance(first, dict):
                                return first.get("content", str(first))
                            return str(first)
                    
                    if "response" in data:
                        return data["response"]
                    if "message" in data:
                        if isinstance(data["message"], dict):
                            return data["message"].get("content", str(data["message"]))
                        return str(data["message"])
                    if "content" in data:
                        return data["content"]
                    
                    return json.dumps(data, indent=2)
            except asyncio.TimeoutError:
                print("[LLM] ⏰ Timeout")
                return ""
            except Exception as e:
                print(f"[LLM] Error: {e}")
                return ""

llm_provider = LLMProvider()
