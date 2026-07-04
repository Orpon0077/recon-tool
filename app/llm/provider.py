# ── LLM Provider ──
import aiohttp
import os
import json
import asyncio
from typing import List, Dict

class LLMProvider:
    def __init__(self):
        self.api_url = os.getenv("LLM_API_URL", "http://192.168.125.170:1234/api/v1/chat")
        self.model = os.getenv("LLM_MODEL", "google/gemma-4-12b")
        print(f"[LLM] Using API: {self.api_url}")
        print(f"[LLM] Model: {self.model}")
    
    async def chat(self, messages: List[Dict]) -> str:
        """
        messages: [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
        Returns: Response string from LLM
        """
        # ── Extract system prompt and user message ──
        system_prompt = ""
        user_message = ""
        
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            elif msg["role"] == "user":
                user_message = msg["content"]
        
        if not user_message:
            return "Please provide a message."
        
        # ── Combine system prompt with user message ──
        if system_prompt:
            combined_prompt = f"{system_prompt}\n\n---\n\nUser Query: {user_message}\n\n---\n\nPlease respond as Recon Assistant based on your role and the instructions above."
        else:
            combined_prompt = user_message
        
        # ── Try LLM ──
        try:
            result = await self._call_llm(combined_prompt)
            if result:
                return result
        except Exception as e:
            print(f"[LLM] LLM call failed: {e}")
        
        # ── NO FALLBACK! Just return what we got or empty ──
        return "I couldn't process that request. Please try again."
    
    async def _call_llm(self, prompt: str) -> str:
        """Call LLM API with combined prompt"""
        if not prompt:
            return ""
        
        payload = {
            "model": self.model,
            "input": prompt
        }
        
        print(f"[LLM] Sending: {prompt[:80]}...")
        
        timeout = aiohttp.ClientTimeout(total=60, connect=10)
        
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
                        return text[:500]
                    
                    # ── Parse response ──
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
                print("[LLM] ⏰ Timeout after 60s")
                return ""
            except Exception as e:
                print(f"[LLM] Error: {e}")
                return ""

llm_provider = LLMProvider()