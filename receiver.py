from modules.enc_dec import *
from modules.pymongo_sync import MongoDB
import datetime

chat_db = MongoDB("CHAT", "messages")

def main():
    print("---------------------------------")
    sender_username = input("Enter username: ")
    my_username = input("Enter receiver username: ")
    if sender_username == my_username or not sender_username or not my_username:
        print("Usernames cant be same or empty.")
        return
    sender_key,receiver_key = fetch_public_key(sender_username), fetch_public_key(my_username)
    if not sender_key:
        print("No Such Sender Found")
        private_pem, public_pem = generate_key_pair(initials=sender_username, password=b"Mst@2069", save_to_files=True)
        print("New key inserted: ",save_public_key(sender_username, public_key=public_pem))
    if not receiver_key:
        print("Receiver not found.Enter correct username.")
        return




if __name__ == "__main__":
    main()