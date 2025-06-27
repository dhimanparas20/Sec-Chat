"""
Secure Chat Application - Production Backend
============================================

A production-ready Flask-RESTful application for secure real-time chat with end-to-end encryption.

Features:
- End-to-end encryption using RSA
- Real-time messaging with Socket.IO
- User presence and typing indicators
- Message delivery and read receipts
- Vanish mode for temporary messages
- Profile management with avatar uploads
- Share/invite functionality
- Complete data cleanup on account deletion

Author: Your Name
Version: 2.0.0
License: MIT
"""

# Standard library imports
import os
import uuid
import base64
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from werkzeug.utils import secure_filename

# Third-party imports
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_restful import Api, Resource
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv

# Local imports
from modules.pymongo_sync import MongoDB
from modules.enc_dec import (
    generate_key_pair,
    save_public_key,
    fetch_public_key,
    encrypt_message,
    decrypt_message
)

# Load environment variables
load_dotenv()

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chat_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Application Configuration
class Config:
    """Application configuration class."""

    # Flask settings
    SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"

    # File upload settings
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "static/uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(3 * 1024 * 1024)))  # 3MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # Database settings
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "CHAT")

    # Server settings
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    # CORS settings - Fixed to allow localhost
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # Security settings
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Flask-RESTful API
api = Api(app)

# Initialize SocketIO with proper CORS configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Allow all origins for development
    logger=False,  # Disable SocketIO logging to reduce noise
    engineio_logger=False,
    async_mode='threading'
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize MongoDB Collections
try:
    users_db = MongoDB(Config.DATABASE_NAME, "users", Config.MONGODB_URI)
    messages_db = MongoDB(Config.DATABASE_NAME, "messages", Config.MONGODB_URI)
    presence_db = MongoDB(Config.DATABASE_NAME, "presence", Config.MONGODB_URI)
    online_users_db = MongoDB(Config.DATABASE_NAME, "online_users", Config.MONGODB_URI)
    typing_users_db = MongoDB(Config.DATABASE_NAME, "typing_users", Config.MONGODB_URI)

    logger.info("Successfully connected to MongoDB collections")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

# Initialize TTL indexes for automatic cleanup
try:
    presence_db.collection.create_index("last_seen", expireAfterSeconds=86400)  # 24 hours
    online_users_db.collection.create_index("last_activity", expireAfterSeconds=300)  # 5 minutes
    typing_users_db.collection.create_index("timestamp", expireAfterSeconds=30)  # 30 seconds
    logger.info("TTL indexes created successfully")
except Exception as e:
    logger.warning(f"Failed to create TTL indexes: {e}")

# Utility Functions
def allowed_file(filename: str) -> bool:
    """
    Check if uploaded file has an allowed extension.

    Args:
        filename (str): Name of the uploaded file

    Returns:
        bool: True if file extension is allowed, False otherwise
    """
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS)

def get_file_size(file) -> int:
    """
    Get file size in bytes without affecting file pointer.

    Args:
        file: File object from request.files

    Returns:
        int: File size in bytes
    """
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning
    return size

def generate_avatar_filename(username: str, original_filename: str) -> str:
    """
    Generate a unique avatar filename with username prefix.

    Args:
        username (str): Username of the user
        original_filename (str): Original filename of uploaded file

    Returns:
        str: Generated filename in format: username_<uuid>.<extension>
    """
    if '.' in original_filename:
        extension = original_filename.rsplit('.', 1)[1].lower()
        return f"{username}_{uuid.uuid4().hex}.{extension}"
    return f"{username}_{uuid.uuid4().hex}"

def cleanup_user_files(username: str) -> bool:
    """
    Clean up all files associated with a user.

    Args:
        username (str): Username whose files to clean up

    Returns:
        bool: True if cleanup successful, False otherwise
    """
    try:
        # Get user's current avatar path
        user = users_db.get({"username": username})
        if user and user.get("avatar"):
            avatar_path = user["avatar"].lstrip("/")  # Remove leading slash
            full_path = os.path.join(os.getcwd(), avatar_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                logger.info(f"Deleted avatar file: {full_path}")

        # Clean up any other files that might start with username
        upload_dir = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_dir):
            for filename in os.listdir(upload_dir):
                if filename.startswith(f"{username}_"):
                    file_path = os.path.join(upload_dir, filename)
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted user file: {file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete file {file_path}: {e}")

        # Clean up encryption keys
        keys_dir = "keys"
        if os.path.exists(keys_dir):
            for key_file in [f"{username}_priv.pem", f"{username}_pub.pem"]:
                key_path = os.path.join(keys_dir, key_file)
                if os.path.exists(key_path):
                    try:
                        os.remove(key_path)
                        logger.info(f"Deleted key file: {key_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete key file {key_path}: {e}")

        return True
    except Exception as e:
        logger.error(f"Error during file cleanup for user {username}: {e}")
        return False

# MongoDB-based Presence Management Functions
def add_online_user(username: str, socket_id: str) -> None:
    """
    Add user to online users collection with socket tracking.

    Args:
        username (str): Username to mark as online
        socket_id (str): Socket ID for the connection
    """
    try:
        current_time = datetime.now(timezone.utc).isoformat()
        online_users_db.update(
            {"username": username},
            {
                "$addToSet": {"socket_ids": socket_id},
                "$set": {
                    "last_activity": current_time,
                    "status": "online"
                }
            },
            upsert=True
        )
        logger.debug(f"User {username} marked as online with socket {socket_id}")
    except Exception as e:
        logger.error(f"Failed to add online user {username}: {e}")

def remove_online_user(username: str, socket_id: str) -> bool:
    """
    Remove user from online users collection and check if they went offline.

    Args:
        username (str): Username to potentially mark as offline
        socket_id (str): Socket ID that disconnected

    Returns:
        bool: True if user went completely offline, False if still has connections
    """
    try:
        current_time = datetime.now(timezone.utc).isoformat()

        # Remove socket ID from array
        online_users_db.update(
            {"username": username},
            {
                "$pull": {"socket_ids": socket_id},
                "$set": {"last_activity": current_time}
            }
        )

        # Check if user has any remaining socket connections
        user_doc = online_users_db.get({"username": username})
        if user_doc and (not user_doc.get("socket_ids") or len(user_doc.get("socket_ids", [])) == 0):
            # No more connections, mark as offline
            online_users_db.update(
                {"username": username},
                {"$set": {"status": "offline", "last_activity": current_time}}
            )
            logger.debug(f"User {username} went offline")
            return True  # User went offline

        logger.debug(f"User {username} still has active connections")
        return False  # User still has connections
    except Exception as e:
        logger.error(f"Failed to remove online user {username}: {e}")
        return False

def get_online_users() -> List[str]:
    """
    Get list of currently online users.

    Returns:
        List[str]: List of usernames that are currently online
    """
    try:
        online_docs = online_users_db.filter({
            "status": "online",
            "socket_ids": {"$exists": True, "$ne": []}
        })
        return [doc["username"] for doc in online_docs]
    except Exception as e:
        logger.error(f"Failed to get online users: {e}")
        return []

def is_user_online(username: str) -> bool:
    """
    Check if a specific user is currently online.

    Args:
        username (str): Username to check

    Returns:
        bool: True if user is online, False otherwise
    """
    try:
        user_doc = online_users_db.get({"username": username, "status": "online"})
        return (user_doc is not None and
                user_doc.get("socket_ids") and
                len(user_doc.get("socket_ids", [])) > 0)
    except Exception as e:
        logger.error(f"Failed to check if user {username} is online: {e}")
        return False

def add_typing_user(username: str, typing_to: str) -> None:
    """
    Add user to typing users collection.

    Args:
        username (str): Username who is typing
        typing_to (str): Username they are typing to
    """
    try:
        current_time = datetime.now(timezone.utc).isoformat()
        typing_users_db.update(
            {"username": username},
            {
                "$set": {
                    "typing_to": typing_to,
                    "timestamp": current_time
                }
            },
            upsert=True
        )
        logger.debug(f"User {username} is typing to {typing_to}")
    except Exception as e:
        logger.error(f"Failed to add typing user {username}: {e}")

def remove_typing_user(username: str) -> None:
    """
    Remove user from typing users collection.

    Args:
        username (str): Username to remove from typing
    """
    try:
        typing_users_db.delete({"username": username})
        logger.debug(f"Removed {username} from typing users")
    except Exception as e:
        logger.error(f"Failed to remove typing user {username}: {e}")

def get_typing_users() -> Dict[str, str]:
    """
    Get dictionary of users currently typing.

    Returns:
        Dict[str, str]: Dictionary mapping username to who they're typing to
    """
    try:
        typing_docs = typing_users_db.filter({})
        return {doc["username"]: doc["typing_to"] for doc in typing_docs}
    except Exception as e:
        logger.error(f"Failed to get typing users: {e}")
        return {}

# Authentication Decorator
def require_auth(f):
    """
    Decorator to require authentication for API endpoints.

    Args:
        f: Function to wrap

    Returns:
        Wrapped function that checks authentication
    """
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Flask-RESTful Resource Classes
class RegisterResource(Resource):
    """Handle user registration."""

    def post(self):
        """
        Register a new user account.

        Expected JSON payload:
        {
            "username": "string",
            "password": "string",
            "full_name": "string",
            "email": "string",
            "age": integer
        }

        Returns:
            JSON response with success/error message
        """
        try:
            data = request.get_json()
            if not data:
                return {"error": "Invalid JSON data"}, 400

            # Extract and validate required fields
            username = data.get("username", "").strip()
            password = data.get("password", "")
            full_name = data.get("full_name", "").strip()
            email = data.get("email", "").strip().lower()
            age = data.get("age")

            # Input validation
            if not username or not password:
                return {"error": "Username and password are required"}, 400

            if not full_name or not email or age is None:
                return {"error": "Full name, email, and age are required"}, 400

            if len(username) < 3:
                return {"error": "Username must be at least 3 characters long"}, 400

            if len(password) < 6:
                return {"error": "Password must be at least 6 characters long"}, 400

            if not isinstance(age, int) or age < 13 or age > 120:
                return {"error": "Age must be between 13 and 120"}, 400

            # Check for existing username
            if users_db.count({"username": username}) > 0:
                return {"error": "Username already exists. Please choose a different username."}, 409

            # Check for existing email
            if users_db.count({"email": email}) > 0:
                return {"error": "Email already exists. Please use a different email address."}, 409

            # Hash password and generate encryption keys
            hashed_password = users_db.hashit(password)
            private_pem, public_pem = generate_key_pair(
                initials=username,
                password=password.encode(),
                save_to_files=True
            )
            save_public_key(username, public_pem)

            # Create user document
            user_doc = {
                "username": username,
                "password": hashed_password,
                "full_name": full_name,
                "email": email,
                "age": age,
                "status": "auto",
                "avatar": None,
                "notification_sound": True,
                "created_at": datetime.now(timezone.utc).isoformat()
            }

            users_db.insert(user_doc)
            logger.info(f"New user registered: {username}")

            return {
                "success": True,
                "message": "Account created successfully! You can now login."
            }, 201

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"error": "Registration failed. Please try again."}, 500

class LoginResource(Resource):
    """Handle user login."""

    def post(self):
        """
        Authenticate user login.

        Expected JSON payload:
        {
            "username": "string",
            "password": "string"
        }

        Returns:
            JSON response with success/error message
        """
        try:
            data = request.get_json()
            if not data:
                return {"error": "Invalid JSON data"}, 400

            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                return {"error": "Username and password are required"}, 400

            # Verify user credentials
            user = users_db.get({"username": username})
            if not user or not users_db.verify_hash(password, user["password"]):
                return {"error": "Invalid username or password"}, 401

            # Set session
            session["username"] = username
            logger.info(f"User logged in: {username}")

            return {"success": True, "message": "Login successful"}, 200

        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"error": "Login failed. Please try again."}, 500

class ForgotPasswordResource(Resource):
    """Handle password reset."""

    def post(self):
        """
        Reset user password.

        Expected JSON payload:
        {
            "username": "string",
            "new_password": "string"
        }

        Returns:
            JSON response with success/error message
        """
        try:
            data = request.get_json()
            if not data:
                return {"error": "Invalid JSON data"}, 400

            username = data.get("username", "").strip()
            new_password = data.get("new_password", "")

            if not username or not new_password:
                return {"error": "Username and new password are required"}, 400

            if len(new_password) < 6:
                return {"error": "Password must be at least 6 characters long"}, 400

            # Check if user exists
            user = users_db.get({"username": username})
            if not user:
                return {"error": "User not found"}, 404

            # Update password
            hashed_password = users_db.hashit(new_password)
            users_db.update(
                {"username": username},
                {"$set": {"password": hashed_password}}
            )

            logger.info(f"Password reset for user: {username}")
            return {"success": True, "message": "Password updated successfully"}, 200

        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return {"error": "Password reset failed. Please try again."}, 500

class ProfileResource(Resource):
    """Handle user profile operations."""

    @require_auth
    def get(self):
        """
        Get current user's profile information.

        Returns:
            JSON response with user profile data
        """
        try:
            username = session["username"]
            user = users_db.get({"username": username})

            if not user:
                return {"error": "User not found"}, 404

            return {
                "user": {
                    "username": user["username"],
                    "full_name": user.get("full_name", ""),
                    "email": user.get("email", ""),
                    "status": user.get("status", "auto"),
                    "avatar": user.get("avatar"),
                    "notification_sound": user.get("notification_sound", True)
                }
            }, 200

        except Exception as e:
            logger.error(f"Profile get error: {e}")
            return {"error": "Failed to retrieve profile"}, 500

    @require_auth
    def post(self):
        """
        Update user profile information.

        Accepts form data with optional fields:
        - full_name: string
        - email: string
        - status: string
        - notification_sound: boolean
        - password: string
        - avatar: file upload

        Returns:
            JSON response with success/error message
        """
        try:
            username = session["username"]
            update_data = {}

            # Handle text fields
            if 'full_name' in request.form:
                update_data['full_name'] = request.form['full_name'].strip()

            if 'email' in request.form:
                email = request.form['email'].strip().lower()
                # Check if email is already taken by another user
                existing_user = users_db.get({
                    "email": email,
                    "username": {"$ne": username}
                })
                if existing_user:
                    return {"error": "Email already taken"}, 409
                update_data['email'] = email

            if 'status' in request.form:
                update_data['status'] = request.form['status']

            if 'notification_sound' in request.form:
                update_data['notification_sound'] = (
                    request.form['notification_sound'].lower() == 'true'
                )

            if 'password' in request.form and request.form['password']:
                new_password = request.form['password']
                if len(new_password) < 6:
                    return {"error": "Password must be at least 6 characters long"}, 400
                update_data['password'] = users_db.hashit(new_password)

            # Handle avatar upload with improved naming
            if 'avatar' in request.files:
                file = request.files['avatar']
                if file and file.filename:
                    # Validate file type
                    if not allowed_file(file.filename):
                        return {
                            "error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WEBP are allowed."
                        }, 400

                    # Validate file size
                    file_size = get_file_size(file)
                    if file_size > app.config['MAX_CONTENT_LENGTH']:
                        return {
                            "error": f"File size too large. Maximum {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB allowed."
                        }, 400

                    # Delete old avatar if exists
                    current_user = users_db.get({"username": username})
                    if current_user and current_user.get("avatar"):
                        old_avatar_path = current_user["avatar"].lstrip("/")
                        full_old_path = os.path.join(os.getcwd(), old_avatar_path)
                        if os.path.exists(full_old_path):
                            try:
                                os.remove(full_old_path)
                                logger.info(f"Deleted old avatar: {full_old_path}")
                            except Exception as e:
                                logger.warning(f"Failed to delete old avatar: {e}")

                    # Generate new filename with username prefix
                    filename = generate_avatar_filename(username, file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                    try:
                        file.save(filepath)
                        update_data['avatar'] = f'/static/uploads/{filename}'
                        logger.info(f"Avatar saved for user {username}: {filename}")
                    except Exception as e:
                        logger.error(f"Failed to save avatar for {username}: {e}")
                        return {"error": "Failed to save avatar"}, 500

            # Update user profile
            if update_data:
                users_db.update({"username": username}, {"$set": update_data})
                logger.info(f"Profile updated for user: {username}")

            return {
                "success": True,
                "message": "Profile updated successfully!"
            }, 200

        except Exception as e:
            logger.error(f"Profile update error: {e}")
            return {"error": "Failed to update profile"}, 500

class StatusResource(Resource):
    """Handle user status updates."""

    @require_auth
    def post(self):
        """
        Update user online status.

        Expected JSON payload:
        {
            "status": "string"  // "online", "away", "busy", "offline", "auto"
        }

        Returns:
            JSON response with success/error message
        """
        try:
            data = request.get_json()
            if not data:
                return {"error": "Invalid JSON data"}, 400

            status = data.get('status', 'auto')
            username = session["username"]

            users_db.update(
                {"username": username},
                {"$set": {"status": status}}
            )

            logger.info(f"Status updated for user {username}: {status}")
            return {"success": True}, 200

        except Exception as e:
            logger.error(f"Status update error: {e}")
            return {"error": "Failed to update status"}, 500

class KeysResource(Resource):
    """Handle encryption key operations."""

    @require_auth
    def post(self):
        """
        Regenerate user's encryption keys.

        Returns:
            JSON response with success/error message
        """
        try:
            username = session["username"]
            user = users_db.get({"username": username})

            if not user:
                return {"error": "User not found"}, 404

            # Generate new key pair
            private_pem, public_pem = generate_key_pair(
                initials=username,
                password=b"newkeys",
                save_to_files=True
            )
            save_public_key(username, public_pem)

            logger.info(f"Keys regenerated for user: {username}")
            return {"success": True, "message": "Keys regenerated successfully"}, 200

        except Exception as e:
            logger.error(f"Key regeneration error: {e}")
            return {"error": "Failed to regenerate keys"}, 500

class AccountResource(Resource):
    """Handle account deletion."""

    @require_auth
    def delete(self):
        """
        Delete user account and all associated data.

        This includes:
        - User profile and settings
        - All messages (sent and received)
        - Presence and online status data
        - Typing status data
        - Profile pictures and uploaded files
        - Encryption keys (public and private)

        Returns:
            JSON response with success/error message
        """
        try:
            username = session["username"]
            logger.info(f"Starting account deletion for user: {username}")

            # 1. Clean up all files associated with the user
            file_cleanup_success = cleanup_user_files(username)
            if not file_cleanup_success:
                logger.warning(f"File cleanup had issues for user: {username}")

            # 2. Delete all messages where user is sender or receiver
            messages_deleted = messages_db.delete({
                "$or": [
                    {"sender": username},
                    {"receiver": username}
                ]
            })
            logger.info(f"Deleted {messages_deleted} message documents for user: {username}")

            # 3. Delete user account from users collection
            users_deleted = users_db.delete({"username": username})
            logger.info(f"Deleted {users_deleted} user documents for user: {username}")

            # 4. Clean up presence data from all collections
            presence_deleted = presence_db.delete({"username": username})
            online_deleted = online_users_db.delete({"username": username})
            typing_deleted = typing_users_db.delete({"username": username})

            logger.info(f"Cleaned up presence data for user {username}: "
                       f"presence={presence_deleted}, online={online_deleted}, typing={typing_deleted}")

            # 5. Delete public key from keys collection
            try:
                from modules.enc_dec import db as keys_db
                keys_deleted = keys_db.delete({"username": username})
                logger.info(f"Deleted {keys_deleted} key documents for user: {username}")
            except Exception as e:
                logger.warning(f"Failed to delete keys from database for user {username}: {e}")

            # 6. Clear session
            session.pop("username", None)
            session.pop("redirect_to_chat", None)

            logger.info(f"Account deletion completed successfully for user: {username}")
            return {
                "success": True,
                "message": "Account and all associated data deleted successfully"
            }, 200

        except Exception as e:
            logger.error(f"Account deletion error for user {session.get('username', 'unknown')}: {e}")
            return {"error": "Failed to delete account. Please try again."}, 500

class ChatResource(Resource):
    """Handle chat-related operations."""

    @require_auth
    def delete(self):
        """
        Delete chat history with a specific user.

        Expected JSON payload:
        {
            "target_user": "string",
            "include_vanish": boolean (optional)
        }

        Returns:
            JSON response with deletion results
        """
        try:
            data = request.get_json()
            if not data:
                return {"error": "Invalid JSON data"}, 400

            username = session["username"]
            target_user = data.get('target_user', '').strip()
            include_vanish = data.get('include_vanish', False)

            if not target_user:
                return {"error": "Target user required"}, 400

            # Build delete filter
            delete_filter = {
                "$or": [
                    {"sender": username, "receiver": target_user},
                    {"sender": target_user, "receiver": username}
                ]
            }

            if not include_vanish:
                delete_filter["vanish_mode"] = {"$ne": True}

            # Delete messages
            result = messages_db.collection.delete_many(delete_filter)

            # Check if there are any remaining messages with this user
            remaining_messages = messages_db.count({
                "$or": [
                    {"sender": username, "receiver": target_user},
                    {"sender": target_user, "receiver": username}
                ],
                "vanish_mode": {"$ne": True}
            })

            logger.info(f"Chat deletion: {username} <-> {target_user}, "
                       f"deleted: {result.deleted_count}, remaining: {remaining_messages}")

            return {
                "success": True,
                "removed_from_contacts": remaining_messages == 0,
                "deleted_count": result.deleted_count
            }, 200

        except Exception as e:
            logger.error(f"Chat deletion error: {e}")
            return {"error": f"Failed to delete chat: {str(e)}"}, 500

class SearchResource(Resource):
    """Handle user search operations."""

    @require_auth
    def get(self, query):
        """
        Search for users by username or full name.

        Args:
            query (str): Search query string

        Returns:
            JSON response with matching users
        """
        try:
            if not query or len(query.strip()) < 2:
                return {"users": []}, 200

            current_user = session["username"]
            query = query.strip()

            # Search by username or full name (case insensitive)
            search_filter = {
                "$or": [
                    {"username": {"$regex": query, "$options": "i"}},
                    {"full_name": {"$regex": query, "$options": "i"}}
                ],
                "username": {"$ne": current_user}  # Exclude current user
            }

            users = users_db.filter(search_filter)

            user_list = []
            for user in users[:10]:  # Limit to 10 results
                user_list.append({
                    "username": user["username"],
                    "full_name": user.get("full_name", user["username"]),
                    "avatar": user.get("avatar")
                })

            return {"users": user_list}, 200

        except Exception as e:
            logger.error(f"User search error: {e}")
            return {"users": []}, 500

class UserInfoResource(Resource):
    """Handle user information retrieval."""

    @require_auth
    def get(self, username):
        """
        Get user information by username.

        Args:
            username (str): Username to get info for

        Returns:
            JSON response with user information
        """
        try:
            user = users_db.get({"username": username})
            if not user:
                return {"error": "User not found"}, 404

            return {
                "user": {
                    "username": user["username"],
                    "full_name": user.get("full_name", user["username"]),
                    "avatar": user.get("avatar")
                }
            }, 200

        except Exception as e:
            logger.error(f"User info retrieval error: {e}")
            return {"error": "Failed to retrieve user information"}, 500

class ShareLinkResource(Resource):
    """Handle share link generation."""

    @require_auth
    def post(self):
        """
        Generate a shareable chat link for the current user.

        Returns:
            JSON response with share URL
        """
        try:
            username = session["username"]

            # Generate the share URL
            share_url = request.url_root + f"chat/{username}"

            logger.info(f"Share link generated for user: {username}")
            return {
                "success": True,
                "share_url": share_url,
                "username": username
            }, 200

        except Exception as e:
            logger.error(f"Share link generation error: {e}")
            return {"error": "Failed to generate share link"}, 500

class PublicKeyResource(Resource):
    """Handle public key retrieval."""

    def get(self, username):
        """
        Get user's public key for encryption.

        Args:
            username (str): Username whose public key to retrieve

        Returns:
            JSON response with base64-encoded public key
        """
        try:
            key = fetch_public_key(username)
            if not key:
                return {"error": "No public key found"}, 404

            return {"public_key": base64.b64encode(key).decode()}, 200

        except Exception as e:
            logger.error(f"Public key retrieval error: {e}")
            return {"error": "Failed to retrieve public key"}, 500

class ContactsResource(Resource):
    """Handle contacts retrieval."""

    @require_auth
    def get(self):
        """
        Get user's contacts and chat history metadata.

        Returns:
            JSON response with contacts information
        """
        try:
            username = session["username"]

            # Find all users this user has chatted with (exclude vanish mode only conversations)
            docs = messages_db.filter({
                "$or": [
                    {"sender": username},
                    {"receiver": username}
                ],
                "vanish_mode": {"$ne": True}
            })

            users = set()
            last_message_times = {}

            for doc in docs:
                users.add(doc["sender"])
                users.add(doc["receiver"])

                # Find the latest message time for each conversation
                if doc.get("messages"):
                    latest_msg = max(doc["messages"], key=lambda x: x.get("time", ""))
                    other_user = doc["receiver"] if doc["sender"] == username else doc["sender"]

                    if (other_user not in last_message_times or
                        latest_msg.get("time", "") > last_message_times.get(other_user, "")):
                        last_message_times[other_user] = latest_msg.get("time", "")

            users.discard(username)

            # Get full user information for contacts
            contacts_data = {}
            for user in users:
                user_info = users_db.get({"username": user})
                if user_info:
                    contacts_data[user] = {
                        "username": user,
                        "full_name": user_info.get("full_name", user),
                        "avatar": user_info.get("avatar")
                    }
                else:
                    contacts_data[user] = {
                        "username": user,
                        "full_name": user,
                        "avatar": None
                    }

            return {
                "contacts": list(users),
                "contacts_data": contacts_data,
                "last_message_times": last_message_times
            }, 200

        except Exception as e:
            logger.error(f"Contacts retrieval error: {e}")
            return {
                "contacts": [],
                "contacts_data": {},
                "last_message_times": {}
            }, 500

# Register API Resources
api.add_resource(RegisterResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(ForgotPasswordResource, '/forgot')
api.add_resource(ProfileResource, '/profile', '/update_profile')
api.add_resource(StatusResource, '/update_status')
api.add_resource(KeysResource, '/regenerate_keys')
api.add_resource(AccountResource, '/delete_account')
api.add_resource(ChatResource, '/delete_chat')
api.add_resource(SearchResource, '/search_users/<string:query>')
api.add_resource(UserInfoResource, '/user_info/<string:username>')
api.add_resource(ShareLinkResource, '/generate_share_link')
api.add_resource(PublicKeyResource, '/public_key/<string:username>')
api.add_resource(ContactsResource, '/contacts')

# Traditional Flask Routes (for rendering templates)
@app.route('/')
def index():
    """
    Main chat application route.

    Returns:
        Rendered chat template or redirect to auth
    """
    if "username" not in session:
        return redirect(url_for('auth_page'))

    # Check if there's a pending chat redirect
    start_chat_with = session.pop("redirect_to_chat", None)
    target_user_info = None

    if start_chat_with:
        target_user = users_db.get({"username": start_chat_with})
        if target_user:
            target_user_info = {
                "username": target_user["username"],
                "full_name": target_user.get("full_name", target_user["username"]),
                "avatar": target_user.get("avatar")
            }

    return render_template('chat.html',
                         username=session["username"],
                         start_chat_with=start_chat_with,
                         target_user_info=target_user_info)

@app.route('/chat/<target_username>')
def share_chat_redirect(target_username):
    """
    Handle shared chat links - redirect to chat with target user.

    Args:
        target_username (str): Username to start chat with

    Returns:
        Rendered template or redirect
    """
    try:
        # Check if target user exists
        target_user = users_db.get({"username": target_username})
        if not target_user:
            return render_template('auth.html',
                                 error_message=f"User '{target_username}' not found.")

        # Check if current user is logged in
        if "username" not in session:
            # Store the target username in session to redirect after login
            session["redirect_to_chat"] = target_username
            return render_template('auth.html',
                                 info_message=f"Please login or register to chat with {target_user.get('full_name', target_username)} (@{target_username})")

        # User is logged in, check if trying to chat with themselves
        if session["username"] == target_username:
            return redirect(url_for('index'))

        # Redirect to main chat with target user parameter
        return render_template('chat.html',
                             username=session["username"],
                             start_chat_with=target_username,
                             target_user_info={
                                 "username": target_user["username"],
                                 "full_name": target_user.get("full_name", target_user["username"]),
                                 "avatar": target_user.get("avatar")
                             })

    except Exception as e:
        logger.error(f"Share chat redirect error: {e}")
        return render_template('auth.html',
                             error_message="An error occurred. Please try again.")

@app.route('/logout')
def logout():
    """
    Handle user logout and cleanup.

    Returns:
        Redirect to auth page
    """
    username = session.get("username")
    if username:
        try:
            # Clean up all presence data
            online_users_db.delete({"username": username})
            typing_users_db.delete({"username": username})
            presence_db.update(
                {"username": username},
                {"$set": {"status": "offline", "last_seen": datetime.now(timezone.utc).isoformat()}}
            )

            # Notify other users via SocketIO
            socketio.emit('user_offline', {'username': username})
            logger.info(f"User logged out: {username}")

        except Exception as e:
            logger.error(f"Logout cleanup error for {username}: {e}")

    # Clear session
    session.pop("username", None)
    session.pop("redirect_to_chat", None)
    return redirect(url_for('auth_page'))

@app.route('/auth')
def auth_page():
    """
    Render authentication page.

    Returns:
        Rendered auth template
    """
    return render_template('auth.html')

@app.route('/profile_page')
def profile_page():
    """
    Render profile management page.

    Returns:
        Rendered profile template or redirect to auth
    """
    if "username" not in session:
        return redirect(url_for('auth_page'))
    return render_template('profile.html')

# Socket.IO Event Handlers
@socketio.on('join')
def on_join(data):
    """
    Handle user joining the chat application.

    Args:
        data (dict): Socket data (currently unused)
    """
    username = session.get("username")
    if not username:
        logger.warning("Join attempt without authentication")
        return

    try:
        # Remove from any existing rooms
        for room in session.get("rooms", []):
            leave_room(room)

        # Join the user's personal room
        join_room(username)
        session["rooms"] = [username]

        # Add to online users using MongoDB
        add_online_user(username, request.sid)

        # Update user's presence in MongoDB
        current_time = datetime.now(timezone.utc).isoformat()
        presence_db.update(
            {"username": username},
            {
                "$set": {
                    "socket_id": request.sid,
                    "status": "online",
                    "last_seen": current_time,
                    "last_activity": current_time
                },
                "$setOnInsert": {"username": username}
            },
            upsert=True
        )

        # Notify others that this user is online
        emit('user_online', {"username": username}, broadcast=True, include_self=False)

        # Get list of all online users from MongoDB
        online_usernames = get_online_users()

        # Send the list of online users to the newly connected user
        emit('online_users', {"users": online_usernames})

        # Update user's last seen in users collection
        users_db.update(
            {"username": username},
            {"$set": {"last_seen": current_time}}
        )

        logger.debug(f"User joined: {username}")

    except Exception as e:
        logger.error(f"Join error for user {username}: {e}")

@socketio.on('status_change')
def handle_status_change(data):
    """
    Handle user status changes (online, away, busy, etc.).

    Args:
        data (dict): Contains 'status' field
    """
    username = session.get("username")
    status = data.get('status') if data else None

    if not username or not status:
        logger.warning(f"Invalid status change request: username={username}, status={status}")
        return

    try:
        current_time = datetime.now(timezone.utc).isoformat()

        if status == 'offline':
            # Remove from online users
            online_users_db.update(
                {"username": username},
                {"$set": {"status": "offline", "last_activity": current_time}}
            )
            emit('user_offline', {'username': username}, broadcast=True, include_self=False)
        else:
            # Update status in online users
            online_users_db.update(
                {"username": username},
                {"$set": {"status": status, "last_activity": current_time}},
                upsert=True
            )
            emit('user_online', {'username': username, 'status': status}, broadcast=True, include_self=False)

        logger.debug(f"Status changed for {username}: {status}")

    except Exception as e:
        logger.error(f"Status change error for user {username}: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    """
    Handle user starting to type.

    Args:
        data (dict): Contains 'to' field with recipient username
    """
    username = session.get("username")
    to_user = data.get("to") if data else None

    if not username or not to_user:
        logger.warning(f"Invalid typing start: username={username}, to_user={to_user}")
        return

    try:
        # Track typing status in MongoDB
        add_typing_user(username, to_user)

        # Update presence with typing info
        current_time = datetime.now(timezone.utc).isoformat()
        presence_db.update(
            {"username": username},
            {
                "$set": {
                    "typing_to": to_user,
                    "typing_timestamp": current_time,
                    "last_activity": current_time
                }
            },
            upsert=True
        )

        # Notify the recipient
        emit('user_typing', {"from": username}, room=to_user)
        logger.debug(f"Typing started: {username} -> {to_user}")

    except Exception as e:
        logger.error(f"Typing start error: {e}")

@socketio.on('typing_stop')
def handle_typing_stop(data):
    """
    Handle user stopping typing.

    Args:
        data (dict): Contains 'to' field with recipient username
    """
    username = session.get("username")
    to_user = data.get("to") if data else None

    if not username:
        logger.warning("Typing stop without username")
        return

    try:
        # Remove from typing users in MongoDB
        remove_typing_user(username)

        # Remove typing status from presence
        presence_db.update(
            {"username": username},
            {"$unset": {"typing_to": "", "typing_timestamp": ""}}
        )

        # Notify the recipient
        if to_user:
            emit('user_stopped_typing', {"from": username}, room=to_user)

        logger.debug(f"Typing stopped: {username}")

    except Exception as e:
        logger.error(f"Typing stop error: {e}")

@socketio.on('messages_seen')
def handle_messages_seen(data):
    """
    Handle marking messages as seen/read.

    Args:
        data (dict): Contains 'sender' field
    """
    username = session.get("username")
    sender = data.get("sender") if data else None

    if not username or not sender:
        logger.warning(f"Invalid messages seen: username={username}, sender={sender}")
        return

    try:
        current_time = datetime.now(timezone.utc).isoformat()

        # Mark messages as seen in database - update individual message status
        result = messages_db.collection.update_many(
            {
                "sender": sender,
                "receiver": username,
                "messages.seen": {"$ne": True}
            },
            {
                "$set": {
                    "messages.$[elem].seen": True,
                    "messages.$[elem].seen_at": current_time
                }
            },
            array_filters=[{"elem.seen": {"$ne": True}}]
        )

        # Update last activity
        presence_db.update(
            {"username": username},
            {"$set": {"last_activity": current_time}},
            upsert=True
        )

        # Notify the sender that their messages were seen
        emit('messages_seen', {"by": username, "timestamp": current_time}, room=sender)

        logger.debug(f"Messages marked as seen: {sender} -> {username}, count: {result.modified_count}")

    except Exception as e:
        logger.error(f"Messages seen error: {e}")

@socketio.on('message_delivered')
def handle_message_delivered(data):
    """
    Handle message delivery confirmation.

    Args:
        data (dict): Contains 'message_id' and 'sender' fields
    """
    username = session.get("username")
    message_id = data.get("message_id") if data else None
    sender = data.get("sender") if data else None

    if not username or not message_id or not sender:
        logger.warning(f"Invalid message delivered: username={username}, message_id={message_id}, sender={sender}")
        return

    try:
        current_time = datetime.now(timezone.utc).isoformat()

        # Mark specific message as delivered
        result = messages_db.collection.update_one(
            {
                "sender": sender,
                "receiver": username,
                "messages._id": message_id
            },
            {
                "$set": {
                    "messages.$.delivered": True,
                    "messages.$.delivered_at": current_time
                }
            }
        )

        # Notify sender
        emit('message_delivered', {
            "message_id": message_id,
            "delivered_to": username,
            "timestamp": current_time
        }, room=sender)

        logger.debug(f"Message delivered: {message_id} from {sender} to {username}")

    except Exception as e:
        logger.error(f"Message delivered error: {e}")

@socketio.on('disconnect')
def on_disconnect():
    """Handle user disconnection and cleanup."""
    username = session.get("username")
    if not username:
        return

    try:
        # Remove socket ID from user's online status
        went_offline = remove_online_user(username, request.sid)

        if went_offline:
            # Update presence status to offline
            presence_db.update(
                {"username": username},
                {"$set": {"status": "offline", "last_seen": datetime.now(timezone.utc).isoformat()}}
            )

            # Remove from typing users
            remove_typing_user(username)

            # Notify other users
            emit('user_offline', {'username': username}, broadcast=True)

        logger.debug(f"User disconnected: {username}, went_offline: {went_offline}")

    except Exception as e:
        logger.error(f"Disconnect error for user {username}: {e}")

@socketio.on('fetch_history')
def handle_fetch_history(data):
    """
    Handle fetching chat history between two users.

    Args:
        data (dict): Contains user1/sender and user2/receiver fields
    """
    # Accept both possible key names for compatibility
    user1 = data.get('user1') or data.get('sender') if data else None
    user2 = data.get('user2') or data.get('receiver') if data else None

    if not user1 or not user2:
        logger.warning(f"Invalid fetch history request: user1={user1}, user2={user2}")
        emit('chat_history', [])
        return

    try:
        # Fetch both directions (exclude vanish mode messages)
        docs = messages_db.filter({
            "$or": [
                {"sender": user1, "receiver": user2},
                {"sender": user2, "receiver": user1}
            ],
            "vanish_mode": {"$ne": True}
        })

        all_msgs = []
        for doc in docs:
            for msg in doc.get("messages", []):
                all_msgs.append({
                    "sender": doc["sender"],
                    "receiver": doc["receiver"],
                    "message": msg["message"],
                    "time": msg.get("time", ""),
                    "message_id": msg.get("_id", ""),
                    "delivered": msg.get("delivered", False),
                    "seen": msg.get("seen", False),
                    "delivered_at": msg.get("delivered_at", ""),
                    "seen_at": msg.get("seen_at", "")
                })

        # Sort by time
        all_msgs.sort(key=lambda x: x["time"])
        emit('chat_history', all_msgs)

        logger.debug(f"Chat history fetched: {user1} <-> {user2}, messages: {len(all_msgs)}")

    except Exception as e:
        logger.error(f"Fetch history error: {e}")
        emit('chat_history', [])

@socketio.on('send_message')
def handle_send_message(data):
    """
    Handle sending regular messages.

    Args:
        data (dict): Contains sender, receiver, message, time, and vanish_mode fields
    """
    if not data:
        logger.warning("Empty message data received")
        return

    sender = data.get('sender')
    receiver = data.get('receiver')
    encrypted_message = data.get('message')  # Should be already encrypted on client
    vanish_mode = data.get('vanish_mode', False)
    message_id = str(uuid.uuid4())

    if not sender or not receiver or not encrypted_message:
        logger.warning(f"Invalid message data: sender={sender}, receiver={receiver}, message_present={bool(encrypted_message)}")
        return

    try:
        # Create message object with proper status tracking
        msg_obj = {
            "_id": message_id,
            "time": data.get("time"),
            "message": encrypted_message,
            "delivered": False,
            "seen": False,
            "delivered_at": None,
            "seen_at": None
        }

        # Only store in database if not in vanish mode
        if not vanish_mode:
            filter_query = {"sender": sender, "receiver": receiver}
            if messages_db.count(filter_query) == 0:
                messages_db.insert({**filter_query, "messages": [msg_obj], "vanish_mode": False})
            else:
                messages_db.update(filter_query, {"$push": {"messages": msg_obj}})

        # Send to receiver with message ID
        emit('receive_message', {
            "sender": sender,
            "message": encrypted_message,
            "time": msg_obj["time"],
            "message_id": message_id
        }, room=receiver)

        # Mark as delivered if receiver is online
        if is_user_online(receiver):
            current_time = datetime.now(timezone.utc).isoformat()

            # Update message status in database
            if not vanish_mode:
                messages_db.collection.update_one(
                    {
                        "sender": sender,
                        "receiver": receiver,
                        "messages._id": message_id
                    },
                    {
                        "$set": {
                            "messages.$.delivered": True,
                            "messages.$.delivered_at": current_time
                        }
                    }
                )

            # Notify sender
            emit('message_delivered', {
                "message_id": message_id,
                "delivered_to": receiver,
                "timestamp": current_time
            }, room=sender)

        logger.debug(f"Message sent: {sender} -> {receiver}, vanish: {vanish_mode}")

    except Exception as e:
        logger.error(f"Send message error: {e}")

@socketio.on('send_vanish_message')
def handle_send_vanish_message(data):
    """
    Handle sending vanish mode messages (not stored in database).

    Args:
        data (dict): Contains sender, receiver, message, and time fields
    """
    if not data:
        logger.warning("Empty vanish message data received")
        return

    sender = data.get('sender')
    receiver = data.get('receiver')
    encrypted_message = data.get('message')
    message_id = str(uuid.uuid4())

    if not sender or not receiver or not encrypted_message:
        logger.warning(f"Invalid vanish message data: sender={sender}, receiver={receiver}, message_present={bool(encrypted_message)}")
        return

    try:
        # Only emit to receiver, don't store in database
        emit('receive_vanish_message', {
            "sender": sender,
            "message": encrypted_message,
            "time": data.get("time"),
            "message_id": message_id
        }, room=receiver)

        logger.debug(f"Vanish message sent: {sender} -> {receiver}")

    except Exception as e:
        logger.error(f"Send vanish message error: {e}")

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(413)
def too_large(error):
    """Handle file too large errors."""
    return jsonify({"error": "File too large"}), 413

# Application Entry Point
if __name__ == '__main__':
    try:
        logger.info(f"Starting Secure Chat Application on {Config.HOST}:{Config.PORT}")
        logger.info(f"Debug mode: {Config.DEBUG}")
        logger.info(f"Upload folder: {Config.UPLOAD_FOLDER}")
        logger.info(f"Max file size: {Config.MAX_CONTENT_LENGTH / (1024*1024):.1f}MB")

        socketio.run(
            app,
            debug=Config.DEBUG,
            port=Config.PORT,
            host=Config.HOST,
            use_reloader=False  # Disable reloader in production
        )
    except Exception as e:
        logger.critical(f"Failed to start application: {e}")
        raise
