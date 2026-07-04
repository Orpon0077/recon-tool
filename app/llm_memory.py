# ── Conversation Memory ────────────────────────────────────
from typing import List, Dict

class ConversationMemory:
    def __init__(self):
        self.sessions: Dict[str, List[Dict]] = {}
    
    def add_message(self, session_id: str, role: str, content: str):
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        self.sessions[session_id].append({"role": role, "content": content})
    
    def get_context(self, session_id: str, max_messages: int = 10):
        if session_id not in self.sessions:
            return []
        return self.sessions[session_id][-max_messages:]
    
    def clear_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

conversation_memory = ConversationMemory()
