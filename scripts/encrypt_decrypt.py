#Import tools
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Function to Check if Encryption Key is Valid 
def validate_key(key, algorithm):
    """Validates the encryption key length."""
    if algorithm in ['AES', '3DES']:
        return len(key) in [16, 24, 32]  # AES and 3DES need keys of 16, 24, or 32 bytes
    elif algorithm == 'Fernet':
        return len(key) == 32  # Fernet needs a 32-byte key
    elif algorithm == 'RSA':
        return True  # We'll check RSA keys differently later
    return False  # If it's not one of these algorithms, the key is invalid

#  Function to Encrypt a File 
def encrypt_file(file_path, password, algorithm='AES'):
    """Encrypts a file using the specified algorithm (AES, Fernet, RSA, or 3DES)."""
    try:  # Try this code, and if something goes wrong, jump to 'except'
        with open(file_path, 'rb') as file:  # Open the file to encrypt in binary mode ('rb')
            plaintext = file.read()  # Read all the file's content

        # Encrypt based on the selected algorithm
        if algorithm == 'AES':
            # Get a random salt (extra protection for the password)
            salt = os.urandom(16)  
            # Make a secure key from the password and salt (like combining ingredients for a stronger recipe)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())

            iv = os.urandom(16)  # Get a random starting point for the encryption process
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            output = salt + iv + ciphertext  # Include the salt in the output (we need it for decryption later!)
        elif algorithm == 'Fernet':  # Similar process, but using the Fernet library
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            output = f.encrypt(plaintext)
        elif algorithm == 'RSA':  # Encrypt with RSA (requires a public key)
            public_key = serialization.load_pem_public_key(password.encode(), backend=default_backend())
            output = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif algorithm == '3DES':  # Similar to AES, but with 3DES encryption
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,  # 3DES uses a 192-bit (24-byte) key
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())

            iv = os.urandom(8)  # 3DES uses an 8-byte IV
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            output = salt + iv + ciphertext
        else:  # If the algorithm isn't recognized, raise an error
            raise ValueError("Invalid encryption algorithm")

        # Write the encrypted content (output) to a new file with the '.enc' extension
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(output)

        print(f"File Encrypted successfully: {file_path}.enc")
    except Exception as e:  # If an error happened, catch it and tell the user
        print(f"Encryption failed: {str(e)}")

# --- Function to Decrypt a File ---
def decrypt_file(file_path, password, algorithm='AES'):
    """Decrypts a file using the specified algorithm (AES, Fernet, RSA, or 3DES)."""
    try:
        with open(file_path, 'rb') as enc_file:  # Open the encrypted file
            ciphertext = enc_file.read()  # Read all the encrypted content

        if algorithm == 'AES':
            salt = ciphertext[:16]  # Extract the salt (first 16 bytes)
            iv = ciphertext[16:32]  # Extract the IV (next 16 bytes)
            ciphertext = ciphertext[32:]  # The rest is the actual encrypted data

            # Recreate the key using the same process as in encryption
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())

            # Set up the decryption process
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        elif algorithm == 'Fernet':
            # Recreate the Fernet key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            plaintext = f.decrypt(ciphertext)
        elif algorithm == 'RSA':
            # Load the private key (password here is actually the private key PEM)
            private_key = serialization.load_pem_private_key(password.encode(), password=None, backend=default_backend())
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif algorithm == '3DES':
            salt = ciphertext[:16]  # Extract the salt (first 16 bytes)
            iv = ciphertext[16:24]  # Extract the IV (next 8 bytes for 3DES)
            ciphertext = ciphertext[24:]  # The rest is the actual encrypted data

            # Recreate the key using the same process as in encryption
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())

            # Set up the decryption process
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise ValueError("Invalid encryption algorithm")

        # Write the decrypted content to a new file (original filename without '.enc')
        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)

        print(f"File Decrypted successfully: {file_path[:-4]}")
    except Exception as e:  # If an error occurred, inform the user
        print(f"Decryption failed: {str(e)}")

# --- Function to Generate an RSA Key Pair ---
def generate_rsa_key_pair(password):
    """Generates an RSA key pair using a password-derived key."""
    salt = os.urandom(16)  # Generate a random salt
    # Create a key derivation function (KDF) to get a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate the RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard value for the public exponent
        key_size=2048,  # 2048-bit key size (you could use 4096 for even more security)
        backend=default_backend()
    )
    public_key = private_key.public_key()  # Get the corresponding public key

    # Convert the private key to PEM format, encrypted with the derived key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    # Convert the public key to PEM format (public keys are not encrypted)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# --- Main Code (What Runs When You Execute the Script) ---
if __name__ == "__main__":
    import sys  # Import the 'sys' library for handling command-line arguments

    print("Debug: Script started")
    print(f"Debug: Arguments received: {sys.argv}")

    # Check if we have the right number of arguments
    if len(sys.argv) != 5:
        print("Usage: python3 encrypt_decrypt.py <encrypt/decrypt> <filename> <password> <algorithm>")
        sys.exit(1)  # Exit the script with an error code

    # Get the arguments from the command line
    command, filename, password, algorithm = sys.argv[1:]

    #Try to encrypt/decrypt based on the first argument
    try:
        if command == "encrypt":
            # Print a message to show we're encrypting
            print(f"Attempting to encrypt {filename}")
            # Call the encrypt function
            encrypt_file(filename, password, algorithm)

        elif command == "decrypt":
            # Print a message to show we're decrypting
            print(f"Attempting to decrypt {filename}")
            # Call the decrypt function
            decrypt_file(filename, password, algorithm)

        else:
            # Print an error message if the command is invalid
            print(f"Invalid command: {command}")
    except Exception as e:
         # Catch any exceptions that occurred
        print(f"An error occurred: {str(e)}")

    # Print a message to show the script has finished
    print("Script finished ")