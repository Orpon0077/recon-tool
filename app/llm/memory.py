# ── Conversation Memory ────────────────────────────────────
from typing import List, Dict
from datetime import datetime
import json
import os
from app.database.chat_history import save_conversation, get_conversation

class ConversationMemory:
    def __init__(self):
        self.sessions: Dict[str, List[Dict]] = {}
        self.max_history = 50
    
    def get_session(self, session_id: str) -> List[Dict]:
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        return self.sessions[session_id]
    
    async def add_message(self, session_id: str, role: str, content: str):
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.sessions[session_id].append(message)
        
        # ── Trim history ──
        if len(self.sessions[session_id]) > self.max_history:
            self.sessions[session_id] = self.sessions[session_id][-self.max_history:]
        
        # ── Save to database ──
        await save_conversation(session_id, self.sessions[session_id])
    
    async def get_context(self, session_id: str, max_messages: int = 10) -> List[Dict]:
        # ── Try to load from database first ──
        if session_id not in self.sessions:
            db_messages = await get_conversation(session_id)
            if db_messages:
                self.sessions[session_id] = db_messages
        
        history = self.get_session(session_id)
        return history[-max_messages:]
    
    async def load_from_db(self, session_id: str):
        """Load conversation from database"""
        db_messages = await get_conversation(session_id)
        if db_messages:
            self.sessions[session_id] = db_messages
            return True
        return False
    
    def clear_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    async def get_all_sessions(self) -> list:
        """Get all sessions from database"""
        from app.database.chat_history import get_all_conversations
        return await get_all_conversations()

conversation_memory = ConversationMemory()
