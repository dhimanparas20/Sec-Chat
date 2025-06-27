from modules.enc_dec import *
from modules.pymongo_sync import mongoDB

chat_db = mongoDB("CHAT", "messages")

def main():
    print("---------------------------------")
    sender_username = input("Enter username: ")
    receiver_username = input("Enter receiver username: ")
    if sender_username == receiver_username or not sender_username or not receiver_username:
        print("Usernames cant be same or empty.")
        return
    sender,receiver = db.get({"username": sender_username}), db.get({"username": receiver_username})
    if not sender:
        print("Creating new key for sender.")
        private_pem, public_pem = generate_key_pair(initials=sender_username, password=b"Mst@2069", save_to_files=True)
        print("New key inserted: ",save_public_key(sender_username, public_key=public_pem))
    if not receiver:
        print("Receiver not found.Enter correct username.")
        return
    print("------------------------------")
    message = input("Enter message: ")
    encrypted_message = encrypt_message(message, receiver["public_key"])

    data = {
        "sender": sender_username,
        "receiver": receiver_username,
        "message": encrypted_message}
    chat_db.insert_unique({"sender": sender_username, "receiver": receiver_username}, data)

    decrypted_message = decrypt_message(encrypted_message, sender["private_key"])
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()