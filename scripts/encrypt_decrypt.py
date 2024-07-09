
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes    # libraries used to set up and perform encryption and decryption.
from cryptography.hazmat.backends import default_backend    # Provides the default backend for the cryptographic operations.
from cryptography.hazmat.primitives import padding  # padding module


def encrypt_file(file_path, key):
    """
    Encrypts a file using AES encryption.

    Parameters:
    file_path (str): The path to the file to be encrypted.
    key (bytes): The encryption key (must be 16, 24, or 32 bytes long).

    Returns:
    None
    """

    try: # for error handling 
        with open(file_path, 'rb') as file: # Open the file in binary read mode
            plaintext = file.read()  # Read the entire file content as plaintext

        iv = os.urandom(16)  # Generate a random 16-byte initialization vector (IV)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create a Cipher object using AES algorithm with CFB mode and the generated IV
        encryptor = cipher.encryptor()  # Create an encryptor object

        padder = padding.PKCS7(algorithms.AES.block_size).padder()  # Added padding
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()  # Encrypt the plaintext

        with open(file_path + '.enc', 'wb') as enc_file: # Open a new file in binary write mode to save the encrypted data
            enc_file.write(iv + ciphertext)  # Write the IV followed by the ciphertext to the new file
        print(f"File Encrypted successfully: {file_path}.enc")
    except Exception as e:
        print(f"Encryption failed: {str(e)}")


def decrypt_file(file_path, key):
    """
    Decrypts a file using AES encryption.

    Parameters:
    file_path (str): The path to the file to be decrypted.
    key (bytes): The decryption key (must be 16, 24, or 32 bytes long).

    Returns:
    None
    """

    try: # error handling 
        with open(file_path, 'rb') as enc_file: # Open the encrypted file in binary read mode
            iv = enc_file.read(16)  # Read the first 16 bytes to get the IV 
            ciphertext = enc_file.read()  # Read the remaining bytes as the ciphertext

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create a Cipher object using AES algorithm with CFB mode and the extracted IV
        decryptor = cipher.decryptor()  # Create a decryptor object

        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  # Added unpadding
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        #plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext

        # Open a new file in binary write mode to save the decrypted data
        with open(file_path[:-4], 'wb') as dec_file:  # The decrypted file will have the same name as the original, removing the '.enc' extension
            dec_file.write(plaintext)  # Write the decrypted plaintext to the new file
    except Exception as e: 
        print(f"Decryption failed: {str(e)}")
