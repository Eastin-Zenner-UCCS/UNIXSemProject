#adds tkinter and combines the algorithm code into the GUI
import tkinter as tk
from tkinter import filedialog, messagebox, font
import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#function to encrypt a file using (AES) from nanbons code
def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(iv + ciphertext)
        print(f"File Encrypted succesfully: {file_path}.enc")
    except Exception as e:
        print(f"Encryption faild: {str(e)}")

# function to decrypt a file (AES) from nanbons code
def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as enc_file:
            iv = enc_file.read(16)
            ciphertext = enc_file.read()

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        with open(file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)
        print(f"File Decrypted succesfully: {file_path[:-4]}")
    except Exception as e:
        print(f"Decryption faild: {str(e)}")

#lets user choose encryption method
def showmethods(filepath, password):
    def methselect(method):
        if method == "AES":
            key = password.encode().ljust(32)[:32]
            encrypt_file(filepath, key)
        method_window.destroy()
    #creates seperate window for choice
    method_window = tk.Toplevel(app)
    method_window.title("Select encryption method")
    method_window.geometry("300x200")
    method_window.configure(bg="blue")

    tk.Label(method_window, text="Choose encryption method:", font=label_font).pack(pady=10)
    #saved for later when we have methods
    methods = ["AES", "Blowfish", "DES"]
    for method in methods:
        tk.Button(method_window, text=method, command=lambda m=method: methselect(m), font=button_font).pack(pady=5)

#handles encryption
def encrypt():
    filepath = entry_file_path.get()
    password = entry_password.get()
    if not filepath or not password:
        messagebox.showwarning("Error", "give both file and password.")
        return

    showmethods(filepath, password)

#handles decryption
def decrypt():
    filepath = entry_file_path.get()
    password = entry_password.get()
    if not filepath or not password:
        messagebox.showwarning("Error", "give both file and password.")
        return

    key = password.encode().ljust(32)[:32]
    decrypt_file(filepath, key)

# function to select a file
def selectfile():
    filepath = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, filepath)
    print(f"Selected file: {filepath}")

#creates the command to run in the terminal
def terminalcommand():
    #explains command
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file.")
    #what the user must enter to work command
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("file_path", help="Path to the file to encrypt or decrypt")
    parser.add_argument("password", help="Password for e/d")

    args = parser.parse_args()

    key = args.password.encode().ljust(32)[:32]

    if args.mode == "encrypt":
        encrypt_file(args.file_path, key)
    elif args.mode == "decrypt":
        decrypt_file(args.file_path, key)

#gui window
def gui():
    global app, entry_file_path, entry_password, label_font, button_font

    app = tk.Tk()
    app.title("SecureFile")
    app.geometry("900x500")
    app.configure(bg="lightblue")

    #loads image
    image_path = "securefile GUI Image.png"
    if not os.path.exists(image_path):
        print("Image file not found!")
        image_path = None
    else:
        image = tk.PhotoImage(file=image_path)

    #shows image
    if image_path:
        image_label = tk.Label(app, image=image)
        image_label.grid(row=0, column=0, columnspan=3, pady=10, sticky="nsew")

    #silly fonts
    label_font = font.Font(family="DokChampa", size=12)
    entry_font = font.Font(family="Helvetica", size=12)
    button_font = font.Font(family="Helvetica", size=12)

    #confusing path selection code
    tk.Label(app, text="File:", font=label_font).grid(row=1, column=0, padx=10, pady=10, sticky="e")
    entry_file_path = tk.Entry(app, width=50, font=entry_font)
    entry_file_path.grid(row=1, column=1, padx=10, pady=10)
    tk.Button(app, text="File", command=selectfile, font=button_font, bg="blue", fg="white").grid(row=1, column=2, padx=10, pady=10)

    #password
    tk.Label(app, text="Password:", font=label_font).grid(row=2, column=0, padx=10, pady=10, sticky="e")
    entry_password = tk.Entry(app, width=50, show='#', font=entry_font)
    entry_password.grid(row=2, column=1, padx=10, pady=10)

    #encrypt and decrypt buttons
    tk.Button(app, text="Encrypt", command=encrypt, font=button_font, bg="blue", fg="white", relief=tk.RAISED, borderwidth=3, width=8).grid(row=3, column=0, padx=10, pady=10)
    tk.Button(app, text="Decrypt", command=decrypt, font=button_font, bg="red", fg="white").grid(row=3, column=1, padx=10, pady=10)

    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=2)
    app.grid_columnconfigure(2, weight=1)

    app.mainloop()

if __name__ == "__main__":
    #check if ran by terminal
    import sys

    if len(sys.argv) > 1:
        terminalcommand()
    else:
        gui()
