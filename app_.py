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

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

users_db = MongoDB("CHAT", "users")
messages_db = MongoDB("CHAT", "messages")
online_users_db = MongoDB("CHAT", "online_users")
typing_users_db = MongoDB("CHAT", "typing_users")
user_sessions_db = MongoDB("CHAT", "user_sessions")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_size(file):
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    full_name = data.get("full_name")
    email = data.get("email")
    age = data.get("age")
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
    if users_db.count({"username": username}) > 0:
        return jsonify({"error": "Username already exists"}), 409
    if users_db.count({"email": email}) > 0:
        return jsonify({"error": "Email already exists"}), 409
    hashed = users_db.hashit(password)
    private_pem, public_pem = generate_key_pair(initials=username, password=password.encode(), save_to_files=True)
    save_public_key(username, public_pem)
    users_db.insert({
        "username": username,
        "password": hashed,
        "full_name": full_name,
        "email": email,
        "age": age,
        "status": "auto",
        "avatar": None,
        "notification_sound": True,
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
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    username = session["username"]
    update_data = {}
    if 'full_name' in request.form:
        update_data['full_name'] = request.form['full_name']
    if 'email' in request.form:
        email = request.form['email']
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
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            if not allowed_file(file.filename):
                return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WEBP are allowed."}), 400
            file_size = get_file_size(file)
            if file_size > 3 * 1024 * 1024:
                return jsonify({"error": "File size too large. Maximum 3MB allowed."}), 400
            filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(filepath)
                update_data['avatar'] = f'/static/uploads/{filename}'
            except Exception as e:
                return jsonify({"error": "Failed to save avatar"}), 500
    try:
        users_db.update({"username": username}, {"$set": update_data})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed to update profile"}), 500


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
    if username:
        online_users_db.delete({"username": username})
        user_sessions_db.delete({"username": username})
        typing_users_db.delete({"receiver": username})
    session.pop("username", None)
    return redirect(url_for('auth_page'))


@app.route('/auth')
def auth_page():
    return render_template('auth.html')


# --- Socket.IO events ---

@socketio.on('join')
def on_join(data):
    username = data['username']
    join_room(username)
    online_users_db.update_or_create(
        {"username": username},
        {"username": username, "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(),
         "session_id": request.sid}
    )
    user_sessions_db.update_or_create(
        {"username": username},
        {"username": username, "session_id": request.sid}
    )
    emit('user_online', {'username': username}, broadcast=True, include_self=False)
    online_list = [u["username"] for u in online_users_db.filter()]
    emit('users_online', online_list)


@socketio.on('status_change')
def handle_status_change(data):
    username = data['username']
    status = data['status']
    if status == 'offline':
        online_users_db.delete({"username": username})
        user_sessions_db.delete({"username": username})
        typing_users_db.delete({"receiver": username})
        emit('user_offline', {'username': username}, broadcast=True, include_self=False)
    else:
        online_users_db.update_or_create(
            {"username": username},
            {"username": username, "status": status, "last_seen": datetime.now(timezone.utc).isoformat(),
             "session_id": request.sid}
        )
        user_sessions_db.update_or_create(
            {"username": username},
            {"username": username, "session_id": request.sid}
        )
        emit('user_online', {'username': username}, broadcast=True, include_self=False)

@socketio.on('typing_start')
def handle_typing_start(data):
    sender = data['sender']
    receiver = data['receiver']
    # Add sender to receiver's typing set in DB
    typing_users_db.update(
        {"receiver": receiver},
        {"$addToSet": {"senders": sender}}
    )
    emit('user_typing_start', {'sender': sender, 'receiver': receiver}, room=receiver)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    sender = data['sender']
    receiver = data['receiver']
    # Remove sender from receiver's typing set in DB
    typing_users_db.update(
        {"receiver": receiver},
        {"$pull": {"senders": sender}}
    )
    emit('user_typing_stop', {'sender': sender, 'receiver': receiver}, room=receiver)

@socketio.on('messages_seen')
def handle_messages_seen(data):
    sender = data['sender']
    receiver = data['receiver']
    emit('messages_seen', {
        'sender': sender,
        'receiver': receiver,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=receiver)

@socketio.on('disconnect')
def on_disconnect():
    # Find user by session_id
    sid = request.sid
    doc = online_users_db.get({"session_id": sid})
    if doc:
        username = doc["username"]
        online_users_db.delete({"username": username})
        user_sessions_db.delete({"username": username})
        typing_users_db.delete({"receiver": username})
        emit('user_offline', {'username': username}, broadcast=True)

@socketio.on('fetch_history')
def handle_fetch_history(data):
    user1 = data.get('user1') or data.get('sender')
    user2 = data.get('user2') or data.get('receiver')
    if not user1 or not user2:
        emit('chat_history', [])
        return
    docs = messages_db.filter({
        "$or": [
            {"sender": user1, "receiver": user2},
            {"sender": user2, "receiver": user1}
        ]
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
    all_msgs.sort(key=lambda x: x["time"])
    emit('chat_history', all_msgs)

@app.route('/contacts')
def contacts():
    if "username" not in session:
        return jsonify({"contacts": []})
    username = session["username"]
    docs = messages_db.filter({
        "$or": [
            {"sender": username},
            {"receiver": username}
        ]
    })
    users = set()
    for doc in docs:
        users.add(doc["sender"])
        users.add(doc["receiver"])
    users.discard(username)
    return jsonify({"contacts": list(users)})

@socketio.on('send_message')
def handle_send_message(data):
    sender = data['sender']
    receiver = data['receiver']
    encrypted_message = data['message']
    msg_obj = {
        "time": data.get("time"),
        "message": encrypted_message
    }
    filter = {"sender": sender, "receiver": receiver}
    if messages_db.count(filter) == 0:
        messages_db.insert({**filter, "messages": [msg_obj]})
    else:
        messages_db.update(filter, {"$push": {"messages": msg_obj}})
    emit('receive_message', {
        "sender": sender,
        "message": encrypted_message,
        "time": msg_obj["time"]
    }, room=receiver)

@socketio.on('send_vanish_message')
def handle_send_vanish_message(data):
    sender = data['sender']
    receiver = data['receiver']
    encrypted_message = data['message']
    emit('receive_vanish_message', {
        "sender": sender,
        "message": encrypted_message,
        "time": data.get("time")
    }, room=receiver)

if __name__ == '__main__':
    socketio.run(app, debug=True,port=5001)


