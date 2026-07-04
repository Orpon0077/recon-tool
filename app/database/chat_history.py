# ── Chat History Database ──────────────────────────────────
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "recon_tool"
COLLECTION_NAME = "chat_history"

try:
    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print("[ChatHistory] Connected to MongoDB")
except Exception as e:
    print(f"[ChatHistory] Connection error: {e}")
    collection = None

async def save_conversation(session_id: str, messages: list) -> str:
    """Save conversation history to MongoDB"""
    if collection is None:
        return "error-no-db"
    
    try:
        doc = {
            "session_id": session_id,
            "messages": messages,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        result = await collection.update_one(
            {"session_id": session_id},
            {"$set": doc},
            upsert=True
        )
        return str(result.upserted_id) if result.upserted_id else session_id
    except Exception as e:
        print(f"[ChatHistory] Save error: {e}")
        return "error-save-failed"

async def get_conversation(session_id: str) -> list:
    """Get conversation history by session_id"""
    if collection is None:
        return []
    
    try:
        doc = await collection.find_one({"session_id": session_id})
        if doc:
            return doc.get("messages", [])
        return []
    except Exception as e:
        print(f"[ChatHistory] Get error: {e}")
        return []

async def get_all_conversations(limit: int = 50) -> list:
    """Get all conversations (latest first)"""
    if collection is None:
        return []
    
    try:
        cursor = collection.find({}, {"session_id": 1, "created_at": 1, "messages": 1}).sort("updated_at", -1).limit(limit)
        conversations = []
        async for doc in cursor:
            conversations.append({
                "session_id": doc.get("session_id"),
                "created_at": doc.get("created_at").strftime("%Y-%m-%d %H:%M") if doc.get("created_at") else "Unknown",
                "message_count": len(doc.get("messages", []))
            })
        return conversations
    except Exception as e:
        print(f"[ChatHistory] Get all error: {e}")
        return []

async def delete_conversation(session_id: str) -> bool:
    """Delete a conversation by session_id"""
    if collection is None:
        return False
    
    try:
        result = await collection.delete_one({"session_id": session_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"[ChatHistory] Delete error: {e}")
        return False
