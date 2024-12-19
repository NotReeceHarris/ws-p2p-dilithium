from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import math
import string
import random

def generate_rsa_keys():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    # Get the public key from the private key
    public_key = private_key.public_key()
    
    # Serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def generate_aes_keys():
    # Generate a random 256-bit key
    key = os.urandom(32)
    
    # Generate a random 128-bit IV
    iv = os.urandom(16)
    
    return key, iv

def encrypt_with_rsa(public_key_pem, plaintext):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    
    # Encrypt the data
    cipher_text = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return cipher_text

def decrypt_with_rsa(private_key_pem, cipher_text):
    # Load the private key
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    
    # Decrypt the data
    decrypted = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

def aes_encrypt(key, iv, data):
    """
    Encrypts the provided data using AES in CBC mode.

    :param key: The encryption key (bytes, 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively)
    :param iv: Initialization Vector (bytes, must be 16 bytes for AES-CBC)
    :param data: The data to encrypt (string)
    :return: Hex encoded encrypted data (string)
    """
    # Convert string data to bytes using UTF-8 encoding
    data_bytes = data.encode('utf-8')
    
    # Create the cipher object using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the data to be a multiple of the block size (16 bytes for AES)
    padded_data = pad(data_bytes, AES.block_size)
    
    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    # Convert to Hex for easy transmission or storage
    return encrypted_data.hex()

def aes_decrypt(key, iv, encrypted_data):
    """
    Decrypts the provided data using AES in CBC mode.

    :param key: The decryption key (bytes, must match the length used for encryption)
    :param iv: Initialization Vector used during encryption (bytes)
    :param encrypted_data: Hex encoded encrypted data (string)
    :return: Decrypted original data (string)
    """
    # Convert back from hex to bytes
    encrypted_data_bytes = bytes.fromhex(encrypted_data)
    
    # Create the cipher object using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the data
    decrypted_padded_data = cipher.decrypt(encrypted_data_bytes)
    
    # Unpad the data to remove any padding added during encryption
    original_data = unpad(decrypted_padded_data, AES.block_size)
    
    # Convert bytes back to string using UTF-8 decoding
    return original_data.decode('utf-8')

def verify_public_rsa_key(public_key_pem):
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        if isinstance(key, rsa.RSAPublicKey):
            return True
        return False
    except ValueError:
        return False

def verify_aes_key(key, iv):
    """
    Validates if the provided key and IV are suitable for AES encryption.

    :param key: The encryption key (bytes)
    :param iv: Initialization Vector (bytes)
    :return: Boolean indicating if the key and IV are valid, and a message string
    """
    # Check key size
    valid_key_sizes = [16, 24, 32]  # AES-128, AES-192, AES-256
    if len(key) not in valid_key_sizes:
        return False, f"Invalid key size. Must be one of {valid_key_sizes} bytes."

    # Check IV size
    if len(iv) != 16:
        return False, "Invalid IV size. Must be 16 bytes for AES-CBC."

    return True, "Key and IV are valid for AES encryption."

def generate_random_string(length):
    """
    Generate a string of random characters with the given length, excluding hyphens.
    
    :param length: Integer, number of characters in the string
    :return: String of random characters without hyphens
    """
    # Define the possible characters, excluding hyphen
    characters = string.ascii_letters + string.digits + ''.join(c for c in string.punctuation if c != '-')
    # Generate the random string
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# ---------------------------- SEND / RECV ----------------------------

targets_rsa_public_key = None
our_rsa_private_key = None
our_rsa_public_key = None

target_aes_key = None
target_aes_iv = None
our_aes_key = None
our_aes_iv = None

payload_size = 1 * 1024 * 1024 # 1 MB

# Encrypt our messages with the target's public key and decrypt the target's messages with our private key.

def disconnected():
    global targets_rsa_public_key, our_rsa_private_key, our_rsa_public_key, target_aes_key, target_aes_iv, our_aes_key, our_aes_iv
    
    targets_rsa_public_key = None
    our_rsa_private_key = None
    our_rsa_public_key = None

    target_aes_key = None
    target_aes_iv = None
    our_aes_key = None
    our_aes_iv = None

def connected(client):

    global our_rsa_private_key, our_rsa_public_key, our_aes_key, our_aes_iv

    our_rsa_private_key, our_rsa_public_key = generate_rsa_keys()
    our_aes_key, our_aes_iv = generate_aes_keys()

    client.send(our_rsa_public_key)

def send(data):

    global our_rsa_private_key, target_aes_key, target_aes_iv

    if target_aes_key is None:
        print("Error: No AES key")
        return None

    if target_aes_iv is None:
        print("Error: No AES iv")
        return None

    if len(data) > (payload_size - 2):
        print("Error: Data too large")
        return None

    random_data_size = math.floor(((payload_size - len(data)) - 2) / 2)
    payload = f'{generate_random_string(random_data_size)}-{data}-{generate_random_string(random_data_size)}'
    cipher_text = aes_encrypt(target_aes_key, target_aes_iv, payload)

    return cipher_text

def recv(data, client):

    global our_rsa_private_key, targets_rsa_public_key, target_aes_key, target_aes_iv, our_aes_key, our_aes_iv

    if targets_rsa_public_key is None:
        if verify_public_rsa_key(data):
            targets_rsa_public_key = data

            payload = f'{our_aes_key.hex()}:{our_aes_iv.hex()}'
            encrypted_payload = encrypt_with_rsa(targets_rsa_public_key, payload)
            client.send(encrypted_payload)

            return "RSA handshake complete, waiting for AES key", "Alert"
        else:
            print(f"Invalid public key: {data}")
    
    if target_aes_key is None and target_aes_iv is None:
        try:
            decrypted_payload = decrypt_with_rsa(our_rsa_private_key, data)
            
            target_aes_key, target_aes_iv = decrypted_payload.split(':')
            target_aes_key = bytes.fromhex(target_aes_key)
            target_aes_iv = bytes.fromhex(target_aes_iv)

            if not verify_aes_key(target_aes_key, target_aes_iv):
                target_aes_key = None
                target_aes_iv = None    
                return "Invalid AES key received", "Alert"
            
            return "AES key exchange complete, you may now chat!", "Alert"

        except Exception as e:
            print(e)
            return 'Failed to decrypt payload', "Alert"
        
    try:
        decrypted_data = aes_decrypt(our_aes_key, our_aes_iv, data)
        payload = decrypted_data.split('-')
        data = payload[1]
        return data, "Friend"
    except Exception as e:
        print(e)
        return 'Failed to decrypt message', "Alert"