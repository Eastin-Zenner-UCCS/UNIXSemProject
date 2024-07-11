
#!/bin/bash

# Default encryption algorithm
DEFAULT_ALGORITHM="aes-256-cbc"

# Function to encrypt a file
encrypt_file() {
    local file="$1"           # The path to the file to be encrypted
    local password="$2"       # The password to use for encryption
    local algorithm="${3:-$DEFAULT_ALGORITHM}"  # The encryption algorithm to use, defaulting to aes-256-cbc if not provided
    
    if [[ ! -f "$file" ]]; then  # file existence check
        echo "Error: File '$file' not found!"
        return 1
    fi
    
    openssl enc -"$algorithm" -pbkdf2 -salt -in "$file" -out "${file}.enc" -pass pass:"$password" # Password-Based Key Derivation Function 2
    if [[ $? -eq 0 ]]; then
        echo "File encrypted successfully: ${file}.enc" # Print/echo a success message with the name of the encrypted file
        rm "$file" 
        echo "Original file deleted."
    else
        echo "Encryption failed!"
        return 1
    fi
}

# Function to decrypt a file
decrypt_file() {
    local file="$1"           # The path to the file to be decrypted
    local password="$2"       # The password to use for decryption
    local algorithm="${3:-$DEFAULT_ALGORITHM}"  # The encryption algorithm to use, defaulting to aes-256-cbc if not provided
    
    if [[ ! -f "$file" ]]; then  # file existence check
        echo "Error: File '$file' not found!"
        return 1
    fi

    if [[ "$file" != *.enc ]]; then # file extension check
        echo "Error: The file to be decrypted must have a '.enc' extension!"
        return 1
    fi

    openssl enc -d -"$algorithm" -pbkdf2 -in "$file" -out "${file%.enc}" -pass pass:"$password" # Decrypt the file using the specified algorithm and password, with PBKDF2 for key derivation
    if [[ $? -eq 0 ]]; then
        echo "File decrypted successfully: ${file%.enc}" # Print a success message with the name of the decrypted file
    else
        echo "Decryption failed!"
        return 1
    fi
}

# Main script logic
case $1 in
    encrypt)
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 encrypt filename password [algorithm]"
            exit 1
        fi
        encrypt_file "$2" "$3" "$4" # Call encrypt_file function with the provided arguments: filename, password, and algorithm->(optional)
        ;;
        
    decrypt)
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 decrypt filename password [algorithm]"
            exit 1
        fi
        decrypt_file "$2" "$3" "$4" # Call decrypt_file function with the provided arguments: filename, password, and algorithm->(optional)
        ;;
    *)
        echo "Usage: $0 {encrypt|decrypt} filename password [algorithm]" # Print usage instructions if the command is not recognized
        exit 1
        ;;
esac
