from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "recon_tool"

try:
    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    collection = db["scans"]
    print("[Database] Connected to MongoDB")
except Exception as e:
    print(f"[Database] Connection error: {e}")
    collection = None

async def save_scan(url: str, results: dict) -> str:
    if collection is None:
        return "error-no-db"
    try:
        doc = {"url": url, "timestamp": datetime.utcnow(), "results": results}
        result = await collection.insert_one(doc)
        return str(result.inserted_id)
    except Exception as e:
        print(f"[Database] Save error: {e}")
        return "error-save-failed"

async def get_all_scans() -> list:
    if collection is None:
        return []
    try:
        cursor = collection.find({}, {"url": 1, "timestamp": 1}).sort("timestamp", -1)
        scans = []
        async for doc in cursor:
            scans.append({
                "id": str(doc["_id"]),
                "url": doc.get("url", "Unknown"),
                "timestamp": doc.get("timestamp", datetime.utcnow()).strftime("%Y-%m-%d %H:%M")
            })
        return scans
    except Exception as e:
        print(f"[Database] Get error: {e}")
        return []

async def get_scan_by_id(scan_id: str) -> dict:
    if collection is None:
        return None
    try:
        from bson import ObjectId
        if not ObjectId.is_valid(scan_id):
            return None
        doc = await collection.find_one({"_id": ObjectId(scan_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
            if doc.get("timestamp"):
                doc["timestamp"] = doc["timestamp"].strftime("%Y-%m-%d %H:%M")
            return doc
        return None
    except Exception as e:
        print(f"[Database] Get by ID error: {e}")
        return None
