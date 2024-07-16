#!/bin/bash

# Default encryption algorithm
DEFAULT_ALGORITHM="AES"

# Function to check if required dependencies are installed
check_dependencies() {
    # List of required dependencies
    dependencies=("python3" "pip3")

    # Loop through each dependency and check if it is installed
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            # If a dependency is not installed, print a message and exit the script
            echo "$dep is not installed. Please install it before running this script."
            exit 1
        fi
    done

    # Check if the Python 'cryptography' package is installed
    if ! python3 -c "import cryptography" &> /dev/null; then
        # If the package is not installed, print a message and install it
        echo "The Python 'cryptography' package is not installed. Installing..."
        pip3 install cryptography
    fi
}

# Function to encrypt a file
encrypt_file() {
    local file="$1"  # The file to encrypt
    local password="$2"  # The password to use for encryption
    local algorithm="${3:-$DEFAULT_ALGORITHM}"  # The encryption algorithm (default is AES)

    # Check if the file exists
    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' not found!"
        return 1
    fi

    if [[ "$algorithm" == "RSA" ]]; then
        # Generate RSA key pair if the algorithm is RSA
        python3 scripts/encrypt_decrypt.py generate_rsa_key_pair "$password"
        public_key="public_key.pem"
        private_key="private_key.pem"
        echo "RSA key pair generated."
    else
        # For other algorithms, use the password directly as the key
        public_key="$password"
        private_key="$password"
    fi

    # Call the Python script to encrypt the file
    python3 scripts/encrypt_decrypt.py encrypt "$file" "$public_key" "$algorithm"
}

# Function to decrypt a file
decrypt_file() {
    local file="$1"  # The file to decrypt
    local password="$2"  # The password to use for decryption
    local algorithm="${3:-$DEFAULT_ALGORITHM}"  # The decryption algorithm (default is AES)

    # Check if the file exists
    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' not found!"
        return 1
    fi

    # Check if the file has a '.enc' extension
    if [[ "$file" != *.enc ]]; then
        echo "Error: The file to be decrypted must have a '.enc' extension!"
        return 1
    fi

    if [[ "$algorithm" == "RSA" ]]; then
        # Set the private key file if the algorithm is RSA
        private_key="private_key.pem"
    else
        # For other algorithms, use the password directly as the key
        private_key="$password"
    fi

    # Call the Python script to decrypt the file
    python3 scripts/encrypt_decrypt.py decrypt "$file" "$private_key" "$algorithm"
}

# Function to generate RSA key pair (for demonstration)
generate_rsa_key_pair() {
    local password="$1"  # The password to use for generating the RSA key pair
    # Call the Python script to generate the RSA key pair
    python3 scripts/encrypt_decrypt.py generate_rsa_key_pair "$password"
    echo "RSA key pair generated."
}

# Main script logic
case "$1" in
    encrypt)
        # Check if there are at least 3 arguments
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 encrypt <filename> <password> [algorithm]"
            exit 1
        fi
        # Call the encrypt_file function with the provided arguments
        encrypt_file "$2" "$3" "$4"
        ;;
    decrypt)
        # Check if there are at least 3 arguments
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 decrypt <filename> <password> [algorithm]"
            exit 1
        fi
        # Call the decrypt_file function with the provided arguments
        decrypt_file "$2" "$3" "$4"
        ;;
    generate_rsa_key_pair)  # Added for demonstration
        # Check if there are exactly 2 arguments
        if [[ $# -ne 2 ]]; then
            echo "Usage: $0 generate_rsa_key_pair <password>"
            exit 1
        fi
        # Call the generate_rsa_key_pair function with the provided argument
        generate_rsa_key_pair "$2"
        ;;
    *)
        # Print usage information if the command is not recognized
        echo "Usage: $0 {encrypt|decrypt|generate_rsa_key_pair} <filename> <password> [algorithm]"
        exit 1
        ;;
esac
