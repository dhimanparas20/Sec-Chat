from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from modules.pymongo_sync import MongoDB
from modules.enc_dec import generate_key_pair, save_public_key, fetch_public_key, encrypt_message, decrypt_message
import base64
import os
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024  # 3MB max file size
socketio = SocketIO(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

users_db = MongoDB("CHAT", "users")
messages_db = MongoDB("CHAT", "messages")
presence_db = MongoDB("CHAT", "presence")  # New collection for tracking presence and status

# Initialize TTL index for presence collection (documents auto-delete after 1 day)
presence_db.collection.create_index("last_seen", expireAfterSeconds=86400)  # 24 hours

# Allowed file extensions for avatars
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_size(file):
    """Get file size in bytes"""
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning
    return size


# --- RESTful endpoints ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    full_name = data.get("full_name")
    email = data.get("email")
    age = data.get("age")

    # Validation
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if not full_name or not email or not age:
        return jsonify({"error": "Full name, email, and age are required"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    if not isinstance(age, int) or age < 13 or age > 120:
        return jsonify({"error": "Age must be between 13 and 120"}), 400

    # Check if username already exists
    if users_db.count({"username": username}) > 0:
        return jsonify({"error": "Username already exists"}), 409

    # Check if email already exists
    if users_db.count({"email": email}) > 0:
        return jsonify({"error": "Email already exists"}), 409

    # Hash password and generate keys
    hashed = users_db.hashit(password)
    private_pem, public_pem = generate_key_pair(initials=username, password=password.encode(), save_to_files=True)
    save_public_key(username, public_pem)

    # Insert user with additional fields
    users_db.insert({
        "username": username,
        "password": hashed,
        "full_name": full_name,
        "email": email,
        "age": age,
        "status": "auto",
        "avatar": None,
        "notification_sound": True,  # Default notification sound on
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    return jsonify({"success": True})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = users_db.get({"username": username})
    if not user or not users_db.verify_hash(password, user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    session["username"] = username
    return jsonify({"success": True})


@app.route('/forgot', methods=['POST'])
def forgot():
    data = request.json
    username = data.get("username")
    new_password = data.get("new_password")
    user = users_db.get({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404
    hashed = users_db.hashit(new_password)
    users_db.update({"username": username}, {"$set": {"password": hashed}})
    return jsonify({"success": True})


@app.route('/profile')
def get_profile():
    """Get current user's profile"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = users_db.get({"username": session["username"]})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": {
            "username": user["username"],
            "full_name": user.get("full_name", ""),
            "email": user.get("email", ""),
            "status": user.get("status", "auto"),
            "avatar": user.get("avatar"),
            "notification_sound": user.get("notification_sound", True)
        }
    })


@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update user profile"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    username = session["username"]
    update_data = {}

    # Handle text fields
    if 'full_name' in request.form:
        update_data['full_name'] = request.form['full_name']

    if 'email' in request.form:
        email = request.form['email']
        # Check if email is already taken by another user
        existing_user = users_db.get({"email": email, "username": {"$ne": username}})
        if existing_user:
            return jsonify({"error": "Email already taken"}), 409
        update_data['email'] = email

    if 'status' in request.form:
        update_data['status'] = request.form['status']

    if 'notification_sound' in request.form:
        update_data['notification_sound'] = request.form['notification_sound'].lower() == 'true'

    if 'password' in request.form and request.form['password']:
        update_data['password'] = users_db.hashit(request.form['password'])

    # Handle avatar upload with validation
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            # Check file type
            if not allowed_file(file.filename):
                return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WEBP are allowed."}), 400

            # Check file size (3MB limit)
            file_size = get_file_size(file)
            if file_size > 3 * 1024 * 1024:  # 3MB
                return jsonify({"error": "File size too large. Maximum 3MB allowed."}), 400

            # Generate unique filename
            filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                update_data['avatar'] = f'/static/uploads/{filename}'
            except Exception as e:
                return jsonify({"error": "Failed to save avatar"}), 500

    # Update user
    try:
        users_db.update({"username": username}, {"$set": update_data})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed to update profile"}), 500


@app.route('/update_status', methods=['POST'])
def update_status():
    """Update user online status"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    status = data.get('status', 'auto')

    try:
        users_db.update(
            {"username": session["username"]},
            {"$set": {"status": status}}
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed to update status"}), 500


@app.route('/regenerate_keys', methods=['POST'])
def regenerate_keys():
    """Regenerate user's encryption keys"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    username = session["username"]
    user = users_db.get({"username": username})

    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        # Generate new key pair
        private_pem, public_pem = generate_key_pair(
            initials=username,
            password=b"newkeys",
            save_to_files=True
        )
        save_public_key(username, public_pem)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed to regenerate keys"}), 500


@app.route('/delete_account', methods=['POST'])
def delete_account():
    """Delete user account and all associated data"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    username = session["username"]

    try:
        # Delete all messages where user is sender or receiver
        messages_db.delete({
            "$or": [
                {"sender": username},
                {"receiver": username}
            ]
        })

        # Delete user account
        users_db.delete({"username": username})

        # Clear session
        session.pop("username", None)

        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to delete account"}), 500


@app.route('/delete_chat', methods=['POST'])
def delete_chat():
    """Delete chat history with a specific user"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    username = session["username"]
    target_user = data.get('target_user')
    include_vanish = data.get('include_vanish', False)

    if not target_user:
        return jsonify({"error": "Target user required"}), 400

    try:
        # Delete messages between the two users using proper MongoDB delete method
        delete_filter = {
            "$or": [
                {"sender": username, "receiver": target_user},
                {"sender": target_user, "receiver": username}
            ]
        }

        if not include_vanish:
            delete_filter["vanish_mode"] = {"$ne": True}

        # Use the correct delete method
        result = messages_db.collection.delete_many(delete_filter)

        # Check if there are any remaining messages with this user
        remaining_messages = messages_db.count({
            "$or": [
                {"sender": username, "receiver": target_user},
                {"sender": target_user, "receiver": username}
            ],
            "vanish_mode": {"$ne": True}
        })

        return jsonify({
            "success": True,
            "removed_from_contacts": remaining_messages == 0,
            "deleted_count": result.deleted_count
        })
    except Exception as e:
        print(f"Delete chat error: {e}")  # Debug logging
        return jsonify({"error": f"Failed to delete chat: {str(e)}"}), 500


@app.route('/search_users/<query>')
def search_users(query):
    """Search for users by username or full name"""
    if "username" not in session:
        return jsonify({"users": []})

    current_user = session["username"]

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
    for user in users:
        user_list.append({
            "username": user["username"],
            "full_name": user.get("full_name", user["username"]),
            "avatar": user.get("avatar")
        })

    return jsonify({"users": user_list[:10]})  # Limit to 10 results


@app.route('/user_info/<username>')
def get_user_info(username):
    """Get user information by username"""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = users_db.get({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": {
            "username": user["username"],
            "full_name": user.get("full_name", user["username"]),
            "avatar": user.get("avatar")
        }
    })


@app.route('/public_key/<username>')
def get_public_key(username):
    key = fetch_public_key(username)
    if not key:
        return jsonify({"error": "No public key found"}), 404
    return jsonify({"public_key": base64.b64encode(key).decode()})


@app.route('/')
def index():
    if "username" not in session:
        return redirect(url_for('auth_page'))
    return render_template('chat.html', username=session["username"])


@app.route('/logout')
def logout():
    username = session.get("username")
    if username and username in online_users:
        del online_users[username]
        socketio.emit('user_offline', {'username': username})

    session.pop("username", None)
    return redirect(url_for('auth_page'))


@app.route('/auth')
def auth_page():
    return render_template('auth.html')


@app.route('/profile_page')
def profile_page():
    if "username" not in session:
        return redirect(url_for('auth_page'))
    return render_template('profile.html')


@socketio.on('join')
def on_join(data):
    username = session.get("username")
    if not username:
        return
    
    # Remove from any existing rooms
    for room in session.get("rooms", []):
        leave_room(room)
    
    # Join the user's personal room
    join_room(username)
    session["rooms"] = [username]
    
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
    
    # Get list of all online users
    online_users = [user["username"] for user in presence_db.find({"status": "online"})]
    
    # Send the list of online users to the newly connected user
    emit('online_users', {"users": online_users})
    
    # Update user's last seen in users collection
    users_db.update(
        {"username": username},
        {"$set": {"last_seen": current_time}}
    )


@socketio.on('status_change')
def handle_status_change(data):
    username = session.get("username")
    status = data.get('status')
    
    if not username or not status:
        return
    
    current_time = datetime.now(timezone.utc).isoformat()
    
    if status == 'offline':
        # Update all sessions for this user to offline
        presence_db.update_many(
            {"username": username, "status": "online"},
            {"$set": {"status": "offline", "last_seen": current_time}}
        )
        emit('user_offline', {'username': username}, broadcast=True, include_self=False)
    else:
        # Update status for all sessions
        presence_db.update_many(
            {"username": username, "status": {"$ne": "offline"}},
            {"$set": {"status": status, "last_activity": current_time}}
        )
        emit('user_online', {'username': username, 'status': status}, broadcast=True, include_self=False)


@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get("username")
    to_user = data.get("to")
    
    if not username or not to_user:
        return
    
    # Update typing status in MongoDB
    presence_db.update(
        {"username": username},
        {
            "$set": {
                "typing": to_user, 
                "last_activity": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Notify the recipient
    emit('user_typing', {"from": username}, room=to_user)
    
    # Set a timeout to automatically stop typing after 3 seconds
    def stop_typing():
        typing_user = presence_db.get({"username": username, "typing": to_user})
        if typing_user:
            presence_db.update(
                {"username": username, "typing": to_user},
                {"$unset": {"typing": ""}}
            )
            emit('user_stopped_typing', {"username": username}, room=to_user)
    
    socketio.start_background_task(
        lambda: socketio.sleep(3) and stop_typing()
    )


@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get("username")
    to_user = data.get("to")
    
    if not username or not to_user:
        return
    
    # Remove typing status from MongoDB
    result = presence_db.update(
        {"username": username, "typing": to_user},
        {"$unset": {"typing": ""}}
    )
    
    # Only emit if the user was actually typing
    if result.modified_count > 0:
        emit('user_stopped_typing', {"username": username}, room=to_user)


@socketio.on('messages_seen')
def handle_messages_seen(data):
    username = session.get("username")
    message_ids = data.get("message_ids", [])
    
    if not username or not message_ids:
        return
    
    # Mark messages as seen
    messages_db.update(
        {"_id": {"$in": message_ids}, "receiver": username},
        {"$set": {"seen": True, "seen_at": datetime.now(timezone.utc).isoformat()}},
        multi=True
    )
    
    # Update last activity
    presence_db.update(
        {"username": username},
        {"$set": {"last_activity": datetime.now(timezone.utc).isoformat()}}
    )
    
    # Notify the sender that their messages were seen
    messages = messages_db.find({"_id": {"$in": message_ids}})
    senders = {msg["sender"] for msg in messages if msg["sender"] != username}
    
    for sender in senders:
        emit('messages_seen', {"by": username, "message_ids": message_ids}, room=sender)


@socketio.on('disconnect')
def on_disconnect():
    # Find and remove user from online users
    username_to_remove = None
    for user in presence_db.find({"socket_id": request.sid}):
        username_to_remove = user["username"]
        break

    if username_to_remove:
        # Update presence status to offline
        presence_db.update(
            {"username": username_to_remove, "socket_id": request.sid},
            {"$set": {"status": "offline", "last_seen": datetime.now(timezone.utc).isoformat()}}
        )
        
        # Check if user has any other active sessions
        active_sessions = presence_db.count({"username": username_to_remove, "status": "online"})
        
        if active_sessions == 0:
            # No more active sessions, notify other users
            emit('user_offline', {'username': username_to_remove}, broadcast=True)


@socketio.on('fetch_history')
def handle_fetch_history(data):
    # Accept both possible key names for compatibility
    user1 = data.get('user1') or data.get('sender')
    user2 = data.get('user2') or data.get('receiver')
    if not user1 or not user2:
        emit('chat_history', [])
        return

    # Fetch both directions (exclude vanish mode messages)
    docs = messages_db.filter({
        "$or": [
            {"sender": user1, "receiver": user2},
            {"sender": user2, "receiver": user1}
        ],
        "vanish_mode": {"$ne": True}  # Exclude vanish mode messages
    })

    all_msgs = []
    for doc in docs:
        for msg in doc.get("messages", []):
            all_msgs.append({
                "sender": doc["sender"],
                "receiver": doc["receiver"],
                "message": msg["message"],
                "time": msg.get("time", "")
            })

    # Sort by time (if your time format is sortable)
    all_msgs.sort(key=lambda x: x["time"])
    emit('chat_history', all_msgs)


@app.route('/contacts')
def contacts():
    if "username" not in session:
        return jsonify({"contacts": [], "contacts_data": {}, "last_message_times": {}})

    username = session["username"]

    # Find all users this user has chatted with (either as sender or receiver)
    # Exclude vanish mode only conversations
    docs = messages_db.filter({
        "$or": [
            {"sender": username},
            {"receiver": username}
        ],
        "vanish_mode": {"$ne": True}  # Exclude vanish mode messages
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

            if other_user not in last_message_times or latest_msg.get("time", "") > last_message_times.get(other_user,
                                                                                                           ""):
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

    return jsonify({
        "contacts": list(users),
        "contacts_data": contacts_data,
        "last_message_times": last_message_times
    })


@socketio.on('send_message')
def handle_send_message(data):
    sender = data['sender']
    receiver = data['receiver']
    encrypted_message = data['message']  # Should be already encrypted on client
    vanish_mode = data.get('vanish_mode', False)

    msg_obj = {
        "time": data.get("time"),
        "message": encrypted_message
    }

    # Only store in database if not in vanish mode
    if not vanish_mode:
        filter_query = {"sender": sender, "receiver": receiver}
        if messages_db.count(filter_query) == 0:
            messages_db.insert({**filter_query, "messages": [msg_obj], "vanish_mode": False})
        else:
            messages_db.update(filter_query, {"$push": {"messages": msg_obj}})

    # Send to receiver
    emit('receive_message', {
        "sender": sender,
        "message": encrypted_message,
        "time": msg_obj["time"]
    }, room=receiver)


@socketio.on('send_vanish_message')
def handle_send_vanish_message(data):
    """Handle vanish mode messages - don't store in database"""
    sender = data['sender']
    receiver = data['receiver']
    encrypted_message = data['message']

    # Only emit to receiver, don't store in database
    emit('receive_vanish_message', {
        "sender": sender,
        "message": encrypted_message,
        "time": data.get("time")
    }, room=receiver)


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
