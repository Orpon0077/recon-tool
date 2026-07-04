# ── Database Module ────────────────────────────────────────
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

MONGO_URL = "mongodb://localhost:27017"
DB_NAME = "recon_tool"
COLLECTION_NAME = "scans"

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

async def save_scan(url: str, results: dict) -> str:
    document = {
        "url": url,
        "timestamp": datetime.utcnow(),
        "results": results,
    }
    result = await collection.insert_one(document)
    return str(result.inserted_id)

async def get_all_scans() -> list:
    cursor = collection.find({}, {"url": 1, "timestamp": 1}).sort("timestamp", -1)
    scans = []
    async for doc in cursor:
        scans.append({
            "id": str(doc["_id"]),
            "url": doc["url"],
            "timestamp": doc["timestamp"].strftime("%Y-%m-%d %H:%M"),
        })
    return scans

async def get_scan_by_id(scan_id: str) -> dict:
    from bson import ObjectId
    doc = await collection.find_one({"_id": ObjectId(scan_id)})
    if doc:
        doc["_id"] = str(doc["_id"])
        doc["timestamp"] = doc["timestamp"].strftime("%Y-%m-%d %H:%M")
    return doc
