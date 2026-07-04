import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

class LLMProvider:
    def __init__(self):
        self.api_url = "http://192.168.125.170:1234/api/v1/chat"
        self.model = "google/gemma-4-12b"
        print(f"[LLM_PROVIDER] ✅ Using REAL LLM at: {self.api_url}")
    
    def chat(self, messages):
        print("[LLM_PROVIDER] chat() called")
        
        try:
            user_message = ""
            for msg in messages:
                if msg.get("role") == "user":
                    user_message = msg.get("content", "")
            
            if not user_message:
                return {"error": "No user message", "provider": "local"}
            
            headers = {"Content-Type": "application/json"}
            payload = {
                "model": self.model,
                "system_prompt": "You are a helpful AI assistant. Provide clear, concise answers.",
                "input": user_message
            }
            
            print("[LLM_PROVIDER] ⏳ Calling Local LLM...")
            start = time.time()
            
            # ── Timeout 600 seconds (10 minutes) ──
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=600)
            data = response.json()
            
            elapsed = time.time() - start
            print(f"[LLM_PROVIDER] Response received in {elapsed:.2f}s")
            
            if response.status_code == 200:
                outputs = data.get("output", [])
                for item in outputs:
                    if item.get("type") == "message":
                        text = item.get("content", "")
                        if text and len(text.strip()) > 0:
                            return {
                                "success": True,
                                "response": text.strip()[:500],
                                "provider": "local"
                            }
                
                if outputs and len(outputs) > 0:
                    text = outputs[0].get("content", "")
                    if text and len(text.strip()) > 0:
                        return {
                            "success": True,
                            "response": text.strip()[:500],
                            "provider": "local"
                        }
            
            print(f"[LLM_PROVIDER] API Error: {data}")
            return {"error": str(data), "provider": "local"}
            
        except requests.exceptions.Timeout:
            print("[LLM_PROVIDER] ⏰ Timeout (600s)")
            return {"error": "Local LLM timeout (600s)", "provider": "local"}
        except Exception as e:
            print(f"[LLM_PROVIDER] Error: {e}")
            return {"error": str(e), "provider": "local"}

llm_provider = LLMProvider()
