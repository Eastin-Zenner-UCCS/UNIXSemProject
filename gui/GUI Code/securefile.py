import tkinter as tk
from tkinter import filedialog, messagebox, font
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

#checks encryption key length (from Francis and Nanbon)
def validate_key(key, algorithm):
    if algorithm in ['AES', '3DES']:
        return len(key) in [16, 24, 32]
    elif algorithm == 'Fernet':
        return len(key) == 32

#encrypt files
def encrypt_file(file_path, password, algorithm='AES'):
    try:
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        if algorithm == 'AES':
            salt = os.urandom(16)
            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            ))
            key = kdf.derive(password.encode())

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            output = salt + iv + ciphertext

        elif algorithm == 'Fernet':
            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=100000,
            ))
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            output = f.encrypt(plaintext)
        elif algorithm == '3DES':
            salt = os.urandom(16)
            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
            ))
            key = kdf.derive(password.encode())

            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            output = salt + iv + ciphertext
        else:
            raise ValueError("Error: not a method")

        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(output)

        messagebox.showinfo("Encryption", f"File Encrypted successfully")
    except Exception as e:
        messagebox.showerror("Encryption Failed", f"Encryption Failed")

#decrypts files
def decrypt_file(file_path, password, algorithm='AES'):
    try:
        with open(file_path, 'rb') as enc_file:
            ciphertext = enc_file.read()

        if algorithm == 'AES':
            salt = ciphertext[:16]
            iv = ciphertext[16:32]
            ciphertext = ciphertext[32:]

            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            ))

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        elif algorithm == 'Fernet':
            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=100000,
            ))

            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            plaintext = f.decrypt(ciphertext)
        elif algorithm == '3DES':
            salt = ciphertext[:16]
            iv = ciphertext[16:24]
            ciphertext = ciphertext[24:]

            kdf = (PBKDF2HMAC
            (
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
            ))

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise ValueError("Error not a decryption method")

        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)

        messagebox.showinfo("Decryption", f"File Decrypted")
    except Exception as e:
        messagebox.showerror("Decryption failed", f"Decryption failed")

#makes a new window wirth gui options
def showmethods(filepath, password):
    def methselect(method):
        if method in ["AES", "Fernet", "3DES"]:
            encrypt_file(filepath, password, method)

    method_window = tk.Toplevel(app)
    method_window.title("Choose Encryption Method")
    method_window.geometry("300x200")
    method_window.configure(bg="lightblue")

    tk.Label(method_window, text="Choose Encryption Method:", font=label_font).pack(pady=10)

    methods = ["AES", "Fernet", "3DES"]
    for method in methods:
        tk.Button(method_window, text=method, command=lambda m=method: methselect(m), font=button_font).pack(pady=5)

#ecyrpts the file
def encrypt():
    filepath = entry_file_path.get()
    password = entry_password.get()
    if not filepath or not password:
        messagebox.showwarning("Error", "Enter both a file and password.")
        return

    showmethods(filepath, password)

# decrypts a file
def decrypt():
    filepath = entry_file_path.get()
    password = entry_password.get()
    if not filepath or not password:
        messagebox.showwarning("Error", "Please provide both file and password.")
        return

    algorithm = 'AES'
    decrypt_file(filepath, password, algorithm)

#allows user to selects a file
def selectfile():
    filepath = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, filepath)
    print(f"Selected file: {filepath}")

#GUI
def gui():
    global app, entry_file_path, entry_password, label_font, button_font

    app = tk.Tk()
    app.title("SecureFile")
    app.geometry("900x500")
    app.configure(bg="lightblue")

    #loads image
    image_path = "securefile GUI Image.png"
    if not os.path.exists(image_path):
        image_path = None
    else:
        image = tk.PhotoImage(file=image_path)

    if image_path:
        image_label = tk.Label(app, image=image)
        image_label.grid(row=0, column=0, columnspan=3, pady=10, sticky="nsew")

    label_font = font.Font(family="DokChampa", size=12)
    entry_font = font.Font(family="Helvetica", size=12)
    button_font = font.Font(family="Helvetica", size=12)

    tk.Label(app, text="File:", font=label_font).grid(row=1, column=0, padx=10, pady=10, sticky="e")
    entry_file_path = tk.Entry(app, width=50, font=entry_font)
    entry_file_path.grid(row=1, column=1, padx=10, pady=10)
    tk.Button(app, text="File", command=selectfile, font=button_font, bg="blue", fg="white").grid(row=1, column=2, padx=10, pady=10)

    tk.Label(app, text="Password:", font=label_font).grid(row=2, column=0, padx=10, pady=10, sticky="e")
    entry_password = tk.Entry(app, width=50, show='#', font=entry_font)
    entry_password.grid(row=2, column=1, padx=10, pady=10)

    tk.Button(app, text="Encrypt", command=encrypt, font=button_font, bg="blue", fg="white", relief=tk.RAISED, borderwidth=3, width=8).grid(row=3, column=0, padx=10, pady=10)
    tk.Button(app, text="Decrypt", command=decrypt, font=button_font, bg="red", fg="white").grid(row=3, column=1, padx=10, pady=10)

    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=2)
    app.grid_columnconfigure(2, weight=1)

    app.mainloop()

if __name__ == "__main__":
    gui()
