# ── Database Module ────────────────────────────────────────
# MongoDB connection and data save/load

from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

# MongoDB connection settings
MONGO_URL = "mongodb://localhost:27017"
DB_NAME = "recon_tool"
COLLECTION_NAME = "scans"

# MongoDB client and collection setup
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]


async def save_scan(url: str, results: dict) -> str:
    """
    Save the scan result in MongoDB.
    Returns the ID of the saved document.
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
    Get the history of all scans.
    Shows only the URL and timestamp — not the details.
    """
    cursor = collection.find(
        {},  # all documents
        {"url": 1, "timestamp": 1}  # only include these fields
    ).sort("timestamp", -1)  # newest first

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
    Get a specific scan by its ID.
    """
    from bson import ObjectId
    document = await collection.find_one({"_id": ObjectId(scan_id)})
    if document:
        document["_id"] = str(document["_id"])
        document["timestamp"] = document["timestamp"].strftime("%Y-%m-%d %H:%M")
    return document