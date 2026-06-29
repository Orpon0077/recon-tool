# ── Conversation Memory ──
from typing import List, Dict
from datetime import datetime
import json
import os

class ConversationMemory:
    def __init__(self):
        self.sessions: Dict[str, List[Dict]] = {}
        self.max_history = 20
    
    def get_session(self, session_id: str) -> List[Dict]:
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        return self.sessions[session_id]
    
    def add_message(self, session_id: str, role: str, content: str):
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        
        self.sessions[session_id].append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if len(self.sessions[session_id]) > self.max_history:
            self.sessions[session_id] = self.sessions[session_id][-self.max_history:]
    
    def get_context(self, session_id: str, max_messages: int = 10) -> List[Dict]:
        history = self.get_session(session_id)
        return history[-max_messages:]
    
    def clear_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

conversation_memory = ConversationMemory()
