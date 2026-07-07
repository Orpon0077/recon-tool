from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from bson import ObjectId

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

async def save_scan(url: str, results: dict, scan_id: str = None) -> str:
    """
    Save scan results. If scan_id is provided, use it as the document _id.
    Returns the scan_id (or ObjectId if not provided).
    """
    if collection is None:
        return "error-no-db"
    try:
        doc = {
            "url": url,
            "timestamp": datetime.utcnow(),
            "results": results,
        }
        if scan_id:
            # Use the provided UUID as _id
            doc["_id"] = scan_id
        result = await collection.insert_one(doc)
        # If we used custom _id, that is the inserted id; else use ObjectId
        inserted_id = scan_id if scan_id else str(result.inserted_id)
        return inserted_id
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
                "id": str(doc["_id"]),  # now _id can be ObjectId or string UUID
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
        # Try to find by string _id (UUID) first
        doc = await collection.find_one({"_id": scan_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            if doc.get("timestamp"):
                doc["timestamp"] = doc["timestamp"].strftime("%Y-%m-%d %H:%M")
            return doc

        # If not found, try as ObjectId
        if ObjectId.is_valid(scan_id):
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