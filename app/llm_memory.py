# ── Conversation Memory ────────────────────────────────────
# This file stores and manages conversation history

from typing import List, Dict, Optional
from datetime import datetime
import json
import os

class ConversationMemory:
    """
    ConversationMemory stores chat history for each session.
    
    How it works:
    1. Each user gets a unique session_id
    2. All messages are stored in memory (dictionary)
    3. When user asks something, we send previous messages as context
    4. This makes the AI remember what was discussed earlier
    """
    
    def __init__(self):
        self.sessions: Dict[str, List[Dict]] = {}
        self.max_history = 20  # Keep last 20 messages per session
    
    def get_session(self, session_id: str) -> List[Dict]:
        """Get or create a session"""
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        return self.sessions[session_id]
    
    def add_message(self, session_id: str, role: str, content: str):
        """Add a message to conversation history"""
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        
        self.sessions[session_id].append({
            "role": role,          # "user" or "assistant"
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Trim history to keep memory manageable
        if len(self.sessions[session_id]) > self.max_history:
            self.sessions[session_id] = self.sessions[session_id][-self.max_history:]
    
    def get_context(self, session_id: str, max_messages: int = 10) -> List[Dict]:
        """Get last N messages for context"""
        history = self.get_session(session_id)
        return history[-max_messages:]
    
    def clear_session(self, session_id: str):
        """Clear conversation history"""
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def save_to_file(self, session_id: str, filepath: str):
        """Save conversation to file (optional)"""
        if session_id in self.sessions:
            with open(filepath, 'w') as f:
                json.dump(self.sessions[session_id], f, indent=2)
    
    def load_from_file(self, session_id: str, filepath: str):
        """Load conversation from file (optional)"""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                self.sessions[session_id] = json.load(f)

# ── Global instance ──
conversation_memory = ConversationMemory()
