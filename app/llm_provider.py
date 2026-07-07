import os
import asyncio
import aiohttp
import json


class LLMProvider:
    def __init__(self):
        self.api_url = os.getenv("LLM_API_URL", "http://192.168.125.170:1234/api/v1/chat")
        self.model = os.getenv("LLM_MODEL", "google/gemma-4-12b")
        print(f"[LLM_PROVIDER] Initialized: {self.api_url}")

    async def chat(self, messages: list) -> dict:
        print("[LLM_PROVIDER] chat() called")

        system_prompt = ""
        user_message = ""

        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            elif msg.get("role") == "user":
                user_message = msg.get("content", "")

        if not user_message:
            return {"error": "No user message", "provider": "local"}

        if system_prompt:
            print(f"[LLM_PROVIDER] System prompt merged (length: {len(system_prompt)})")

        payload = {
            "model": self.model,
            "system_prompt": system_prompt,
            "input": user_message,
        }

        print("[LLM_PROVIDER] Calling Local LLM...")
        print(f"[LLM_PROVIDER] Sending request to {self.api_url}")

        try:
            timeout = aiohttp.ClientTimeout(total=300, connect=10)
            connector = aiohttp.TCPConnector(ssl=False)

            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            ) as session:
                async with session.post(self.api_url, json=payload) as response:
                    status = response.status
                    print(f"[LLM_PROVIDER] Status: {status}")
                    data = await response.json(content_type=None)

                    if status == 200:
                        # --- Check 'output' array (gemma-4-12b format) ---
                        outputs = data.get("output", [])
                        if outputs:
                            # 1. Find first item with type "message"
                            for item in outputs:
                                if item.get("type") == "message":
                                    text = item.get("content", "")
                                    if text.strip():
                                        print(f"[LLM_PROVIDER] Response received (length: {len(text)})")
                                        return {
                                            "success": True,
                                            "response": text.strip(),
                                            "provider": "local",
                                        }
                            # 2. If no message, take first output's content
                            first = outputs[0]
                            if isinstance(first, dict):
                                content = first.get("content", "")
                                if content.strip():
                                    return {
                                        "success": True,
                                        "response": content.strip(),
                                        "provider": "local",
                                    }
                            # 3. If all outputs are strings, join them
                            if all(isinstance(o, str) for o in outputs):
                                return {
                                    "success": True,
                                    "response": "\n".join(outputs).strip(),
                                    "provider": "local",
                                }

                        # --- Check 'response' field ---
                        if "response" in data:
                            return {
                                "success": True,
                                "response": data["response"],
                                "provider": "local",
                            }

                        # --- Check OpenAI-style 'choices' ---
                        choices = data.get("choices", [])
                        if choices:
                            content = choices[0].get("message", {}).get("content", "")
                            if content:
                                return {
                                    "success": True,
                                    "response": content,
                                    "provider": "local",
                                }

                        # --- Fallback: return the whole data as string ---
                        # This prevents "Unknown format" errors
                        return {
                            "success": True,
                            "response": json.dumps(data, indent=2),
                            "provider": "local",
                        }
                    else:
                        text = await response.text()
                        return {"error": f"HTTP {status}: {text[:200]}", "provider": "local"}

        except aiohttp.ClientConnectionError as e:
            print(f"[LLM_PROVIDER] Connection Error: {e}")
            return {"error": f"Cannot connect to LLM server: {str(e)}", "provider": "local"}
        except asyncio.TimeoutError:
            return {"error": "LLM server timed out", "provider": "local"}
        except Exception as e:
            print(f"[LLM_PROVIDER] Exception: {e}")
            return {"error": str(e), "provider": "local"}


llm_provider = LLMProvider()