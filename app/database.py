# ── Database Module ────────────────────────────────────────
# MongoDB connection এবং data save/load করার কাজ এখানে

from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

# MongoDB connection settings
MONGO_URL = "mongodb://localhost:27017"
DB_NAME = "recon_tool"
COLLECTION_NAME = "scans"

# MongoDB client তৈরি করো
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]


async def save_scan(url: str, results: dict) -> str:
    """
    Scan এর result MongoDB তে save করে।
    Save হওয়ার পর document এর ID return করে।
    """
    document = {
        "url": url,
        "timestamp": datetime.utcnow(),
        "results": results,
    }
    result = await collection.insert_one(document)
    return str(result.inserted_id)


async def get_all_scans() -> list:
    """
    সব scan এর history বের করে।
    শুধু URL আর timestamp দেখায় — details না।
    """
    cursor = collection.find(
        {},  # সব documents
        {"url": 1, "timestamp": 1}  # শুধু এই fields নাও
    ).sort("timestamp", -1)  # নতুন থেকে পুরনো

    scans = []
    async for document in cursor:
        scans.append({
            "id": str(document["_id"]),
            "url": document["url"],
            "timestamp": document["timestamp"].strftime("%Y-%m-%d %H:%M"),
        })
    return scans


async def get_scan_by_id(scan_id: str) -> dict:
    """
    ID দিয়ে একটা specific scan এর পুরো result বের করে।
    """
    from bson import ObjectId
    document = await collection.find_one({"_id": ObjectId(scan_id)})
    if document:
        document["_id"] = str(document["_id"])
        document["timestamp"] = document["timestamp"].strftime("%Y-%m-%d %H:%M")
    return document