# SecureVault

A Python-based encryption and decryption application built with `Tkinter` and `cryptography`. SecureVault allows users to encrypt and decrypt files using AES, ChaCha20, or RSA encryption methods via an intuitive GUI.

## Features
- **Encryption and Decryption**: Supports AES, ChaCha20, and RSA encryption.
- **Passphrase Validation**: Ensures secure passphrase entry with confirmation.
- **GUI Interface**: Built using `Tkinter` for an easy-to-use experience.
- **Logging**: Tracks encryption and decryption events.

## Requirements
- Python 3.8+
- Required Python packages (install via `requirements.txt`):
  - `cryptography`
  - `tkinter` (bundled with Python)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/SecureVault.git
   cd SecureVault

2. Install dependencies
   ```bash
   pip install -r requirements.txt

3. Run main app
    ```bash
   python main.py

## Usage
1.- Launch the application.
2.- Select the encryption method (AES, ChaCha20, RSA).
3.- Enter and confirm the passphrase for encryption or decryption.
4.- Choose the file to encrypt/decrypt.
5.- View the results and logs.
**License - This project is licensed under the MIT License.**