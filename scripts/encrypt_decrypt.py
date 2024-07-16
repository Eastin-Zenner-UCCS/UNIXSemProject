import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def validate_key(key):
    """Validates the encryption key length."""
    # Check if the key length is one of the acceptable lengths (16, 24, 32 bytes)
    return len(key) in [16, 24, 32]

def encrypt_file(file_path, key, algorithm='AES'):
    """Encrypts a file using the specified algorithm (AES, Fernet, RSA, or 3DES)."""

    # Open the file and read its contents as bytes
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    if algorithm == 'AES':
        # Generate a random Initialization Vector (IV)
        iv = os.urandom(16)
        # Create a cipher object using AES algorithm in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the plaintext to be compatible with block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write the IV and ciphertext to a new file with '.enc' extension
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(iv + ciphertext)
    elif algorithm == 'Fernet':
        # Create a Fernet cipher object with the given key
        f = Fernet(key)
        # Encrypt the plaintext
        ciphertext = f.encrypt(plaintext)
        # Write the ciphertext to a new file with '.enc' extension
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(ciphertext)
    elif algorithm == 'RSA':
        # Load the public key
        public_key = serialization.load_pem_public_key(key, backend=default_backend())
        # Encrypt the plaintext using the public key
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Write the ciphertext to a new file with '.enc' extension
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(ciphertext)
    elif algorithm == '3DES':
        # Generate a random IV for 3DES
        iv = os.urandom(8)
        # Create a cipher object using 3DES algorithm in CFB mode
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the plaintext to be compatible with block size
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write the IV and ciphertext to a new file with '.enc' extension
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(iv + ciphertext)
    else:
        # Raise an error if the specified algorithm is invalid
        raise ValueError("Invalid encryption algorithm")

    print(f"File Encrypted successfully: {file_path}.enc")

def decrypt_file(file_path, key, algorithm='AES'):
    """Decrypts a file using the specified algorithm (AES, Fernet, RSA, or 3DES)."""

    # Open the encrypted file and read its contents
    with open(file_path, 'rb') as enc_file:
        ciphertext = enc_file.read()

    if algorithm == 'AES':
        # Read the IV from the encrypted file
        iv = enc_file.read(16)
        ciphertext = enc_file.read()

        # Create a cipher object using AES algorithm in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        # Write the decrypted plaintext to a new file, removing the '.enc' extension
        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)
    elif algorithm == 'Fernet':
        # Create a Fernet cipher object with the given key
        f = Fernet(key)
        # Decrypt the ciphertext
        plaintext = f.decrypt(ciphertext)
        # Write the decrypted plaintext to a new file, removing the '.enc' extension
        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)
    elif algorithm == 'RSA':
        # Load the private key
        private_key = serialization.load_pem_private_key(
            key,
            password=None,  # You'll need to provide the password here if the private key is encrypted
            backend=default_backend()
        )
        # Decrypt the ciphertext using the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Write the decrypted plaintext to a new file, removing the '.enc' extension
        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)
    elif algorithm == '3DES':
        # Read the IV from the encrypted file
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]

        # Create a cipher object using 3DES algorithm in CFB mode
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        # Write the decrypted plaintext to a new file, removing the '.enc' extension
        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)
    else:
        # Raise an error if the specified algorithm is invalid
        raise ValueError("Invalid encryption algorithm")

    print(f"File Decrypted successfully: {file_path[:-4]}")

# Generate an RSA key pair from a password
def generate_rsa_key_pair(password):
    """Generates an RSA key pair using a password-derived key."""

    # Generate a random salt
    salt = os.urandom(16)
    # Create a key derivation function (KDF) using PBKDF2 with SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    # Derive a key from the password
    key = kdf.derive(password)

    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Get the corresponding public key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format with encryption
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Return the serialized private and public keys
    return private_pem, public_pem
