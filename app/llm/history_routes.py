from fastapi import APIRouter
from app.database.chat_history import get_all_conversations, get_conversation

router = APIRouter(prefix="/api/llm", tags=["llm"])

@router.get("/history")
async def get_chat_history():
    """Get all chat conversations"""
    conversations = await get_all_conversations(limit=50)
    
    result = []
    for conv in conversations:
        # Get first message as preview
        messages = await get_conversation(conv.get("session_id", ""))
        preview = "New conversation"
        if messages and len(messages) > 0:
            first_msg = messages[0]
            if first_msg.get("role") == "user":
                preview = first_msg.get("content", "New conversation")[:50]
                if len(preview) >= 50:
                    preview += "..."
        
        result.append({
            "session_id": conv.get("session_id"),
            "created_at": conv.get("created_at", "Unknown"),
            "message_count": conv.get("message_count", 0),
            "preview": preview
        })
    
    return {"conversations": result}

@router.get("/history/{session_id}")
async def get_chat_conversation(session_id: str):
    """Get a specific conversation"""
    messages = await get_conversation(session_id)
    return {"session_id": session_id, "messages": messages}
