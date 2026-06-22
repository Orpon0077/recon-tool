# ── LLM Provider ───────────────────────────────────────────
# This file handles the actual API calls to different LLM providers

import json
import aiohttp
from typing import List, Dict, Optional
from app.llm_config import get_config
from app.llm_tools import TOOLS

class LLMProvider:
    """
    LLMProvider handles API calls to different LLM services.
    It supports: DeepSeek, OpenAI, Claude, and Local LLM (Ollama)
    """
    
    def __init__(self):
        self.config = get_config()
        self.provider = self.config["provider"]
        self.model = self.config["config"]["model"]
        self.api_key = self.config.get("api_key", "")
        self.tools = TOOLS
    
    async def chat(self, messages: List[Dict], tools: Optional[List] = None) -> Dict:
        """
        Main chat function - sends messages to LLM and returns response
        
        How it works:
        1. Checks which provider is selected
        2. Calls the appropriate provider's API
        3. Returns the response
        """
        if self.provider == "deepseek":
            return await self._chat_deepseek(messages, tools)
        elif self.provider == "openai":
            return await self._chat_openai(messages, tools)
        elif self.provider == "claude":
            return await self._chat_claude(messages, tools)
        elif self.provider == "local":
            return await self._chat_local(messages, tools)
        else:
            return {"error": f"Unknown provider: {self.provider}"}
    
    async def _chat_deepseek(self, messages: List[Dict], tools: Optional[List] = None) -> Dict:
        """
        DeepSeek API call
        
        How it works:
        1. Creates HTTP request with headers (Authorization: Bearer API_KEY)
        2. Sends messages to https://api.deepseek.com/v1/chat/completions
        3. Gets response and returns it
        """
        if not self.api_key:
            return {"error": "DEEPSEEK_API_KEY not set"}
        
        try:
            url = "https://api.deepseek.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.config["config"]["max_tokens"],
                "temperature": self.config["config"]["temperature"],
            }
            
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers, timeout=60) as response:
                    data = await response.json()
                    if response.status == 200:
                        return data
                    return {"error": f"DeepSeek API error: {data}"}
        except Exception as e:
            return {"error": f"DeepSeek error: {e}"}
    
    async def _chat_openai(self, messages: List[Dict], tools: Optional[List] = None) -> Dict:
        """OpenAI API call"""
        if not self.api_key:
            return {"error": "OPENAI_API_KEY not set"}
        
        try:
            import openai
            client = openai.AsyncOpenAI(api_key=self.api_key)
            
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=self.config["config"]["max_tokens"],
                temperature=self.config["config"]["temperature"],
                tools=tools,
                tool_choice="auto" if tools else None
            )
            return {"choices": [{"message": response.choices[0].message.model_dump()}]}
        except Exception as e:
            return {"error": f"OpenAI error: {e}"}
    
    async def _chat_claude(self, messages: List[Dict], tools: Optional[List] = None) -> Dict:
        """Claude API call"""
        if not self.api_key:
            return {"error": "ANTHROPIC_API_KEY not set"}
        
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            
            system_prompt = ""
            user_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_prompt = msg["content"]
                else:
                    user_messages.append(msg)
            
            response = await client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=user_messages,
                max_tokens=self.config["config"]["max_tokens"],
                temperature=self.config["config"]["temperature"],
                tools=tools,
            )
            return {"choices": [{"message": {"content": response.content[0].text}}]}
        except Exception as e:
            return {"error": f"Claude error: {e}"}
    
    async def _chat_local(self, messages: List[Dict], tools: Optional[List] = None) -> Dict:
        """Local LLM via Ollama"""
        try:
            url = f"{self.config['ollama_url']}/api/chat"
            
            ollama_messages = []
            for msg in messages:
                ollama_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
            
            payload = {
                "model": self.model,
                "messages": ollama_messages,
                "stream": False,
                "options": {
                    "temperature": self.config["config"]["temperature"],
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=120) as response:
                    data = await response.json()
                    return {"choices": [{"message": {"content": data.get("message", {}).get("content", "")}}]}
        except Exception as e:
            return {"error": f"Local LLM error: {e}"}

# ── Global instance ──
llm_provider = LLMProvider()
