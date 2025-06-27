from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature, InvalidKey
from .pymongo_sync import MongoDB
from typing import Tuple,Optional,Union
import base64
import os
# os.system("clear")

db: MongoDB  =  MongoDB("CHAT", "keys")

# Custom Exceptions
class CryptoError(Exception):
    """Custom exception for cryptographic errors."""
    pass

# Key Generation
def generate_key_pair(initials: str = None, password: bytes = None, save_to_files: bool = False, directory: str = "keys") -> Tuple[bytes, bytes]:
    """
    Generates an RSA public/private key pair.

    Args:
        initials (str, optional): Initials or prefix for key filenames.
        password (bytes, optional): Password to encrypt the private key. If None, private key is unencrypted.
        save_to_files (bool, optional): If True, saves the keys as files in the specified directory.
        directory (str, optional): Directory to save the key files. Defaults to 'keys'.

    Returns:
        Tuple[bytes, bytes]: (private_key_pem, public_key_pem)

    Raises:
        CryptoError: If key generation or file saving fails.
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        encryption_algo = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if save_to_files:
            os.makedirs(directory, exist_ok=True)
            if initials:
                priv_path = os.path.join(directory, f"{initials}_priv.pem")
                pub_path = os.path.join(directory, f"{initials}_pub.pem")
            else:
                priv_path = os.path.join(directory, "priv.pem")
                pub_path = os.path.join(directory, "pub.pem")
            with open(priv_path, "wb") as priv_file:
                priv_file.write(private_pem)
            with open(pub_path, "wb") as pub_file:
                pub_file.write(public_pem)

        return private_pem, public_pem
    except Exception as e:
        raise CryptoError(f"Key generation failed: {e}")

# Message Encryption
def encrypt_message(message: str, public_key: bytes or str, keys_dir: str = "keys") -> bytes:
    """
    Encrypts a message using the provided public key (as bytes or filename).

    Args:
        message (str): The plaintext message to encrypt.
        public_key (bytes or str): The public key in PEM format, or the filename in keys_dir.
        keys_dir (str): Directory to look for key files if public_key is a filename.

    Returns:
        bytes: The encrypted message (ciphertext).

    Raises:
        CryptoError: If encryption fails or input is invalid.
    """
    if not isinstance(message, str) or not message:
        raise CryptoError("Message must be a non-empty string.")

    # Load key from file if a filename is provided
    if isinstance(public_key, str):
        key_path = os.path.join(keys_dir, public_key)
        if not os.path.isfile(key_path):
            raise CryptoError(f"Public key file '{key_path}' does not exist.")
        with open(key_path, "rb") as f:
            public_key_pem = f.read()
    elif isinstance(public_key, bytes):
        public_key_pem = public_key
    else:
        raise CryptoError("Public key must be bytes (PEM format) or a filename (str).")

    try:
        public_key_obj = serialization.load_pem_public_key(public_key_pem)
        ciphertext = public_key_obj.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}")

# Message Decryption
def decrypt_message(ciphertext: bytes, private_key: bytes or str, password: bytes = None, keys_dir: str = "keys") -> str:
    """
    Decrypts a ciphertext using the provided private key (as bytes or filename).

    Args:
        ciphertext (bytes): The encrypted message.
        private_key (bytes or str): The private key in PEM format, or the filename in keys_dir.
        password (bytes, optional): Password for the private key, if encrypted.
        keys_dir (str): Directory to look for key files if private_key is a filename.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        CryptoError: If decryption fails or input is invalid.
    """
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise CryptoError("Ciphertext must be non-empty bytes.")

    # Load key from file if a filename is provided
    if isinstance(private_key, str):
        key_path = os.path.join(keys_dir, private_key)
        if not os.path.isfile(key_path):
            raise CryptoError(f"Private key file '{key_path}' does not exist.")
        with open(key_path, "rb") as f:
            private_key_pem = f.read()
    elif isinstance(private_key, bytes):
        private_key_pem = private_key
    else:
        raise CryptoError("Private key must be bytes (PEM format) or a filename (str).")

    try:
        private_key_obj = serialization.load_pem_private_key(
            private_key_pem,
            password=password
        )
        plaintext = private_key_obj.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}")

# Save Public Key to MongoDB
def save_public_key(username: str, public_key: Union[bytes, str] = None, db: MongoDB = db):
    """
    Save a user's public key to MongoDB. If public_key_pem is not provided, reads from public_key_file.
    """
    if isinstance(public_key, str):
        with open(public_key, "rb") as f:
            public_key = f.read()
    # Always use base64 for binary data
    public_key_b64 = base64.b64encode(public_key).decode('utf-8')
    return db.insert_unique({"username": username}, {"username": username, "public_key": public_key_b64})

# Fetch Public Key form a file or MongoDB
def fetch_public_key(username: str, db: MongoDB = db, public_key_file: str = None) -> Optional[bytes]:
    """
    Fetch a user's public key from MongoDB, or from a file if public_key_file is provided.
    """
    if public_key_file:
        with open(public_key_file, "rb") as f:
            return f.read()
    doc = db.get({"username": username})
    if not doc or "public_key" not in doc:
        return None
    # Always decode from base64
    return base64.b64decode(doc["public_key"])


# Generate keys with initials
# private_pem, public_pem = generate_key_pair(initials="alice", password=b"mysecret", save_to_files=True)

# Save public key to MongoDB (from variable)
# print("New key inserted: ",save_public_key("alice", public_key_pem=public_pem))

# Save public key to MongoDB (from file)
# save_public_key("bob", public_key_file="keys/bob_pub.pem")

# Fetch public key from MongoDB
# alice_pubkey = fetch_public_key("alice")
# # print(alice_pubkey.decode('utf-8'))
#
# # Using key variables (as before)
# ciphertext = encrypt_message("Hello, secure world!", alice_pubkey)
# print("-------------------------------------")
# plaintext = decrypt_message(ciphertext, "alice_priv.pem", password=b"mysecret")
# print("-------------------------------------")
# print(plaintext)
#
# # Using key files (after saving with generate_key_pair(..., save_to_files=True))
# ciphertext = encrypt_message("Hello, secure world!", "alice_pub.pem")
# plaintext = decrypt_message(ciphertext, "alice_priv.pem", password=b"mysecret")
# print(plaintext)