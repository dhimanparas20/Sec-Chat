from modules.enc_dec import *
from modules.pymongo_sync import MongoDB
import datetime

chat_db = MongoDB("CHAT", "messages")

def main():
    print("---------------------------------")
    sender_username = input("Enter username: ")
    receiver_username = input("Enter receiver username: ")
    if sender_username == receiver_username or not sender_username or not receiver_username:
        print("Usernames cant be same or empty.")
        return
    sender_key,receiver_key = fetch_public_key(sender_username), fetch_public_key(receiver_username)
    if not sender_key:
        print("Creating new key for sender.")
        private_pem, public_pem = generate_key_pair(initials=sender_username, password=b"Mst@2069", save_to_files=True)
        print("New key inserted: ",save_public_key(sender_username, public_key=public_pem))
    if not receiver_key:
        print("Receiver not found.Enter correct username.")
        return
    print("------------------------------")
    message = input("Enter message: ")
    encrypted_message = encrypt_message(message, receiver_key)
    filter = {"sender": sender_username, "receiver": receiver_username}
    msg_obj = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": encrypted_message
    }

    if chat_db.count(filter) == 0:
        # First message: create new conversation
        data = {**filter, "messages": [msg_obj]}
        print(chat_db.insert(data))
    else:
        # Conversation exists: append message
        count = chat_db.update(filter, {"$push": {"messages": msg_obj}})
        print(count,"messages updated.")



if __name__ == "__main__":
    main()