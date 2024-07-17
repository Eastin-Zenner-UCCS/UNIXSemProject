# SecureFile User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Command-Line Interface (CLI)](#command-line-interface-cli)
4. [Graphical User Interface (GUI)](#graphical-user-interface-gui)
5. [Best Practices](#best-practices)
6. [Troubleshooting](#troubleshooting)

## Introduction <a name="introduction"></a>

SecureFile is a user-friendly file encryption and decryption tool designed for use in the WSL2 environment. It offers both command-line and graphical interfaces, making it versatile for various user preferences.

## Installation <a name="installation"></a>

Follow these steps to set up SecureFile:

1. Clone the repository:
   ```bash
   git clone https://github.com/Eastin-Zenner-UCCS/UNIXSemProject
   cd GUI

2. Create and activate a virtual environment (optional):
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On macOS/Linux
    venv\Scripts\activate     # On Windows

3. Install dependencies:
    ```bash
    python3 -m pip install --upgrade pip
    sudo apt-get install python3-tk
    pip install -r requirements.txt

4. Navigate to directory
    ```bash
    To use GUI, change directory using cd gui/'GUI CODE'

## Command-Line Interface (CLI) <a name="command-line-interface-cli"></a>

### Basic Usage

The general syntax for using SecureFile via CLI is:

   ```bash
    ./secure.sh <encrypt/decrypt> <file_path> <password>
    
```
### Encrypting a File

To encrypt a file named ` document.txt` with the password `"mySecretPass"`:

```bash
./secure.sh encrypt document.txt mySecretPass
```
This will create an encrypted file named `document.txt.enc`.

### Decrypting a File

To decrypt the file `document.txt.enc` using the same password, you can use the following bash command:

```bash
./secure.sh decrypt document.txt.enc mySecretPass
```
## Graphical User Interface (GUI)  <a name="graphical-user-interface-gui"></a>

1. To launch the GUI, you can use the following bash command:

```bash
python securefile.py
```
2. Using the Interface

```
    1. Click "**File**" to select the file you want to encrypt or decrypt.
    2. Enter your password in the designated field.
    3. Choose "**Encrypt**" or "**Decrypt**" based on your needs.

```
3. The operation will be performed, and you'll see a confirmation message.

## Best Practices <a name="best-practices"></a>

- **Password Security**: Use strong, unique passwords for each file.
- **Backup**: Always keep backups of your original files.
- **Password Management**: Use a password manager to store your encryption passwords securely.
- **File Naming**: Keep track of which files are encrypted (they will have a `.enc` extension).

## Troubleshooting  <a name="troubleshooting"></a>

| Issue | Solution |
| --- | --- |
| "File not found" error | Ensure you're in the correct directory and the file exists |
| Decryption fails | Double-check that you're using the correct password |
| GUI doesn't launch | Verify that all dependencies are installed correctly |


For more assistance, please open an issue on our GitHub repository.










