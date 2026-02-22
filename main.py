import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
import secrets
import logging

# Setup logging
logging.basicConfig(
    filename="securevault.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Key derivation function for AES
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# AES Encryption
def encrypt_with_aes(input_file, output_file, passphrase):
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)

        with open(input_file, "rb") as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(salt + iv + encrypted_data)

        logging.info(f"AES encryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File encrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"AES encryption failed: {e}")
        messagebox.showerror("Error", str(e))

# AES Decryption
def decrypt_with_aes(input_file, output_file, passphrase):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        key = derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        logging.info(f"AES decryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File decrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"AES decryption failed: {e}")
        messagebox.showerror("Error", str(e))

# ChaCha20-Poly1305 Encryption
def encrypt_with_chacha20(input_file, output_file, passphrase):
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)
        nonce = secrets.token_bytes(12)
        chacha = ChaCha20Poly1305(key)

        with open(input_file, "rb") as f:
            data = f.read()

        encrypted_data = chacha.encrypt(nonce, data, None)

        with open(output_file, "wb") as f:
            f.write(salt + nonce + encrypted_data)

        logging.info(f"ChaCha20 encryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File encrypted with ChaCha20 and saved to {output_file}")
    except Exception as e:
        logging.error(f"ChaCha20 encryption failed: {e}")
        messagebox.showerror("Error", str(e))

# ChaCha20-Poly1305 Decryption
def decrypt_with_chacha20(input_file, output_file, passphrase):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        salt = data[:16]
        nonce = data[16:28]
        encrypted_data = data[28:]

        key = derive_key(passphrase, salt)
        chacha = ChaCha20Poly1305(key)
        decrypted_data = chacha.decrypt(nonce, encrypted_data, None)

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        logging.info(f"ChaCha20 decryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File decrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"ChaCha20 decryption failed: {e}")
        messagebox.showerror("Error", "Decryption failed. Wrong passphrase or corrupted file.")

# RSA Hybrid Encryption (RSA-OAEP wraps an AES session key)
def encrypt_with_rsa(input_file, output_file, passphrase):
    try:
        # Generate ephemeral RSA key pair (2048-bit)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Generate a random AES session key and encrypt the file with AES
        session_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(input_file, "rb") as f:
            raw = f.read()

        padder = padding.PKCS7(128).padder()
        padded = padder.update(raw) + padder.finalize()
        encrypted_data = encryptor.update(padded) + encryptor.finalize()

        # Encrypt session key with RSA-OAEP
        encrypted_session_key = public_key.encrypt(
            session_key,
            OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        )

        # Serialize private key encrypted with passphrase
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )

        # Format: [4B key_len][encrypted_session_key][4B pem_len][private_pem][iv][encrypted_data]
        with open(output_file, "wb") as f:
            f.write(len(encrypted_session_key).to_bytes(4, 'big'))
            f.write(encrypted_session_key)
            f.write(len(private_pem).to_bytes(4, 'big'))
            f.write(private_pem)
            f.write(iv)
            f.write(encrypted_data)

        logging.info(f"RSA encryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File encrypted with RSA hybrid and saved to {output_file}")
    except Exception as e:
        logging.error(f"RSA encryption failed: {e}")
        messagebox.showerror("Error", str(e))

# RSA Hybrid Decryption
def decrypt_with_rsa(input_file, output_file, passphrase):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        offset = 0
        key_len = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
        encrypted_session_key = data[offset:offset+key_len]; offset += key_len
        pem_len = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
        private_pem = data[offset:offset+pem_len]; offset += pem_len
        iv = data[offset:offset+16]; offset += 16
        encrypted_data = data[offset:]

        private_key = serialization.load_pem_private_key(
            private_pem, password=passphrase.encode(), backend=default_backend()
        )
        session_key = private_key.decrypt(
            encrypted_session_key,
            OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        )

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded) + unpadder.finalize()

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        logging.info(f"RSA decryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File decrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"RSA decryption failed: {e}")
        messagebox.showerror("Error", "Decryption failed. Wrong passphrase or corrupted file.")

# GUI Functions
def validate_passphrase(passphrase, confirmation):
    """Validate the passphrase and confirmation."""
    if len(passphrase) < 8:
        messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
        return False
    if passphrase != confirmation:
        messagebox.showerror("Error", "Passphrases do not match. Please try again.")
        return False
    return True

def encrypt_action():
    method = encryption_method.get()
    input_file = filedialog.askopenfilename(title="Select file to encrypt")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".enc")
    if not output_file:
        return

    passphrase = passphrase_entry.get()
    confirmation = confirm_passphrase_entry.get()

    if not validate_passphrase(passphrase, confirmation):
        return

    if method == "AES":
        encrypt_with_aes(input_file, output_file, passphrase)
    elif method == "ChaCha20":
        encrypt_with_chacha20(input_file, output_file, passphrase)
    elif method == "RSA":
        encrypt_with_rsa(input_file, output_file, passphrase)

def decrypt_action():
    method = encryption_method.get()
    input_file = filedialog.askopenfilename(title="Select file to decrypt")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Save decrypted file")
    if not output_file:
        return

    passphrase = passphrase_entry.get()
    if len(passphrase) < 8:
        messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
        return

    if method == "AES":
        decrypt_with_aes(input_file, output_file, passphrase)
    elif method == "ChaCha20":
        decrypt_with_chacha20(input_file, output_file, passphrase)
    elif method == "RSA":
        decrypt_with_rsa(input_file, output_file, passphrase)

def quit_app():
    app.destroy()

# GUI Setup
app = tk.Tk()
app.title("SecureVault GUI")
app.geometry("400x350")

# Title
tk.Label(app, text="SecureVault - File Encryption and Decryption", font=("Arial", 14)).pack(pady=10)

# Encryption Method Dropdown
encryption_method = tk.StringVar(value="AES")
tk.Label(app, text="Encryption Method:").pack(pady=5)
tk.OptionMenu(app, encryption_method, "AES", "ChaCha20", "RSA").pack()

# Passphrase Input
tk.Label(app, text="Passphrase:").pack(pady=5)
passphrase_entry = tk.Entry(app, show="*", width=40)
passphrase_entry.pack()

# Passphrase Confirmation Input
tk.Label(app, text="Confirm Passphrase:").pack(pady=5)
confirm_passphrase_entry = tk.Entry(app, show="*", width=40)
confirm_passphrase_entry.pack()

# Action Buttons
tk.Button(app, text="Encrypt File", command=encrypt_action, width=20).pack(pady=10)
tk.Button(app, text="Decrypt File", command=decrypt_action, width=20).pack(pady=10)
tk.Button(app, text="Quit", command=quit_app, width=20).pack(pady=10)

app.mainloop()