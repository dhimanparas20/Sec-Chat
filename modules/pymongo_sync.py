"""
MongoDB Utility Module

Production-ready MongoDB utility class using PyMongo.
Requirements: pymongo==4.6.0, passlib
pip3 install pymongo, passlib
"""

from typing import Any, Dict, List, Optional, Union
from bson import ObjectId
import pymongo
import random
import string
from passlib.hash import pbkdf2_sha256

DEFAULT_STRING = "mongodb://localhost:27017/"

class MongoDB:
    """
    MongoDB utility class for database and collection operations.
    """

    def __init__(self, db_name: str, collection_name: str, connection_str: str = DEFAULT_STRING) -> None:
        """
        Initialize MongoDB client and select database and collection.

        Args:
            db_name (str): Name of the database.
            collection_name (str): Name of the collection.
            connection_str (str): MongoDB connection string.

        Raises:
            Exception: If connection fails.
        """
        self.client = pymongo.MongoClient(connection_str)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    @staticmethod
    def hashit(data: str) -> str:
        """
        Hash a string using pbkdf2_sha256.

        Args:
            data (str): Data to hash.

        Returns:
            str: Hashed string.
        """
        return pbkdf2_sha256.hash(data)

    @staticmethod
    def verify_hash(password: str, hashed_password: str) -> bool:
        """
        Verify a password against a hash.

        Args:
            password (str): Plain password.
            hashed_password (str): Hashed password.

        Returns:
            bool: True if verified, False otherwise.
        """
        return pbkdf2_sha256.verify(password, hashed_password)

    @staticmethod
    def gen_string(length: int = 15) -> str:
        """
        Generate a random alphanumeric string.

        Args:
            length (int): Length of the string.

        Returns:
            str: Random string.
        """
        characters = string.ascii_letters + string.digits
        return ''.join(random.choices(characters, k=length))

    def add_db(self, db_name: str, collection_name: str) -> None:
        """
        Switch to a different database and collection.

        Args:
            db_name (str): Database name.
            collection_name (str): Collection name.
        """
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def get_all_db(self) -> List[str]:
        """
        List all database names.

        Returns:
            List[str]: List of database names.
        """
        return self.client.list_database_names()

    def get_all_collections(self, db_name: Optional[str] = None) -> List[str]:
        """
        List all collection names in a database.

        Args:
            db_name (Optional[str]): Database name. If None, uses current db.

        Returns:
            List[str]: List of collection names.
        """
        db = self.client[db_name] if db_name else self.db
        return db.list_collection_names()

    def insert(self, data: Dict[str, Any], *args, **kwargs) -> str:
        """
        Insert a single document.

        Args:
            data (Dict[str, Any]): Document to insert.

        Returns:
            str: Inserted document ID.
        """
        result = self.collection.insert_one(data, *args, **kwargs)
        return str(result.inserted_id)

    def insert_unique(self, filter: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """
        Insert a document only if no document matches the unique filter.

        Args:
            filter (Dict[str, Any]): Query filter to check uniqueness.
            data (Dict[str, Any]): Document to insert.

        Returns:
            bool: True if inserted, False if already exists.

        Raises:
            Exception: If document already exists.
        """
        if self.count(filter) > 0:
            # Already exists
            return False
        self.insert(data)
        return True

    def insert_many(self, data: List[Dict[str, Any]], *args, **kwargs) -> List[str]:
        """
        Insert multiple documents.

        Args:
            data (List[Dict[str, Any]]): List of documents.

        Returns:
            List[str]: List of inserted document IDs.
        """
        result = self.collection.insert_many(data, *args, **kwargs)
        return [str(_id) for _id in result.inserted_ids]

    def filter(self, filter: Optional[Dict[str, Any]] = None, show_id: bool = False, *args, **kwargs) -> List[
        Dict[str, Any]]:
        """
        Filter documents from the collection.

        Args:
            filter (Optional[Dict[str, Any]]): Query filter.
            show_id (bool): Whether to include '_id' in results.

        Returns:
            List[Dict[str, Any]]: List of documents.
        """
        projection = None if show_id else {"_id": 0}
        cursor = self.collection.find(filter or {}, projection, *args, **kwargs)
        result = []
        if show_id:
            result = [{**item, "_id": str(item["_id"])} if "_id" in item else item for item in cursor]
        else:
            result = list(cursor)
        return result

    def get(self, filter: Optional[Dict[str, Any]] = None, show_id: bool = False, *args, **kwargs) -> Optional[
        Dict[str, Any]]:
        """
        Get a single document matching the filter.

        Args:
            filter (Optional[Dict[str, Any]]): Query filter.
            show_id (bool): Whether to include '_id' in result.

        Returns:
            Optional[Dict[str, Any]]: The first matching document, or None if not found.

        Raises:
            Exception: If an error occurs during retrieval.
        """
        projection = None if show_id else {"_id": 0}
        try:
            doc = self.collection.find_one(filter or {}, projection, *args, **kwargs)
            if doc and show_id and "_id" in doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception as e:
            raise Exception(f"Error in get: {e}")

    def count(self, filter: Optional[Dict[str, Any]] = None, *args, **kwargs) -> int:
        """
        Count documents matching a filter.

        Args:
            filter (Optional[Dict[str, Any]]): Query filter.

        Returns:
            int: Number of documents.
        """
        return self.collection.count_documents(filter or {}, *args, **kwargs)

    def update(self, filter: Dict[str, Any], update_data: Dict[str, Any], *args, **kwargs) -> int:
        """
        Update documents matching a filter.

        Args:
            filter (Dict[str, Any]): Query filter.
            update_data (Dict[str, Any]): Full MongoDB update dict, e.g., {"$push": {...}}.

        Returns:
            int: Number of documents modified.
        """
        if "_id" in filter and isinstance(filter["_id"], str):
            filter["_id"] = ObjectId(filter["_id"])
        result = self.collection.update_many(filter, update_data, *args, **kwargs)
        return result.modified_count

    def delete(self, filter: Dict[str, Any], *args, **kwargs) -> int:
        """
        Delete documents matching a filter.

        Args:
            filter (Dict[str, Any]): Query filter.

        Returns:
            int: Number of documents deleted.
        """
        if "_id" in filter and isinstance(filter["_id"], str):
            filter["_id"] = ObjectId(filter["_id"])
        result = self.collection.delete_many(filter, *args, **kwargs)
        return result.deleted_count

    def drop_db(self, db_name: Optional[str] = None) -> None:
        """
        Drop a database.

        Args:
            db_name (Optional[str]): Database name. If None, drops current db.
        """
        db_to_drop = db_name or self.db.name
        self.client.drop_database(db_to_drop)

    def drop_collection(self, collection_name: Optional[str] = None, db_name: Optional[str] = None) -> None:
        """
        Drop a collection.

        Args:
            collection_name (Optional[str]): Collection name. If None, uses current collection.
            db_name (Optional[str]): Database name. If None, uses current db.
        """
        db = self.client[db_name] if db_name else self.db
        coll = collection_name or self.collection.name
        db.drop_collection(coll)

    def get_keys(self, exclude_id: bool = True) -> List[str]:
        """
        Get list of keys in the first document of the collection.

        Args:
            exclude_id (bool): Whether to exclude '_id'.

        Returns:
            List[str]: List of keys.
        """
        doc = self.collection.find_one()
        if not doc:
            return []
        keys = list(doc.keys())
        if exclude_id and '_id' in keys:
            keys.remove('_id')
        return keys

    def close(self) -> None:
        """
        Close the MongoDB client connection.
        """
        self.client.close()

    # Extra utility: get a document by ID
    def get_by_id(self, _id: Union[str, ObjectId]) -> Optional[Dict[str, Any]]:
        """
        Get a document by its ObjectId.

        Args:
            _id (Union[str, ObjectId]): Document ID.

        Returns:
            Optional[Dict[str, Any]]: The document, or None if not found.
        """
        if isinstance(_id, str):
            _id = ObjectId(_id)
        return self.collection.find_one({"_id": _id})

    def update_or_create(self, filter: Dict[str, Any], data: Dict[str, Any]) -> (Dict[str, Any], bool):
        """
        Update a document matching the filter, or create it if it doesn't exist.

        Args:
            filter (Dict[str, Any]): Query filter.
            data (Dict[str, Any]): Data to update or insert.

        Returns:
            Tuple[Dict[str, Any], bool]: (The document, created True if inserted, False if updated)
        """
        try:
            result = self.collection.update_one(filter, {"$set": data}, upsert=True)
            if result.upserted_id is not None:
                # Created new
                doc = self.collection.find_one({"_id": result.upserted_id})
                if doc:
                    doc["_id"] = str(doc["_id"])
                return doc, True
            else:
                # Updated existing
                doc = self.collection.find_one(filter)
                if doc:
                    doc["_id"] = str(doc["_id"])
                return doc, False
        except Exception as e:
            raise Exception(f"Error in update_or_create: {e}")

    def get_or_create(self, filter: Dict[str, Any], data: Optional[Dict[str, Any]] = None) -> (Dict[str, Any], bool):
        """
        Fetch a document matching the filter, or create it if it doesn't exist.

        Args:
            filter (Dict[str, Any]): Query filter.
            data (Optional[Dict[str, Any]]): Data to insert if not found.

        Returns:
            Tuple[Dict[str, Any], bool]: (The document, created True if inserted, False if fetched)
        """
        try:
            doc = self.collection.find_one(filter)
            if doc:
                doc["_id"] = str(doc["_id"])
                return doc, False
            # Merge filter and data for creation
            new_doc = {**filter}
            if data:
                new_doc.update(data)
            inserted_id = self.collection.insert_one(new_doc).inserted_id
            new_doc["_id"] = str(inserted_id)
            return new_doc, True
        except Exception as e:
            raise Exception(f"Error in fetch_or_create: {e}")


# Usage Example:
# mydb = MongoDB("AutomationBOT", "bot