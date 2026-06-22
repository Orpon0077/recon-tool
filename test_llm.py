#!/usr/bin/env python3
# ── Test LLM Connection ──

import asyncio
import os
from dotenv import load_dotenv

# Load .env
load_dotenv()

async def test_deepseek():
    """Test DeepSeek API connection"""
    
    api_key = os.getenv("DEEPSEEK_API_KEY")
    
    if not api_key:
        print("❌ DEEPSEEK_API_KEY not found in .env file")
        print("📝 Please add: DEEPSEEK_API_KEY=your_key_here")
        return False
    
    print("🔍 Testing DeepSeek API...")
    
    import aiohttp
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "user", "content": "Say 'Hello, I am DeepSeek!' in one sentence"}
        ],
        "max_tokens": 100,
        "temperature": 0.7
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=30) as response:
                data = await response.json()
                if response.status == 200:
                    message = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    print(f"✅ DeepSeek response: {message}")
                    return True
                else:
                    print(f"❌ API Error: {data}")
                    return False
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_deepseek())
    if result:
        print("\n✅ LLM Integration Ready!")
    else:
        print("\n❌ LLM Integration Failed. Check your API key.")
