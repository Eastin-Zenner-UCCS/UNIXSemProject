#!/bin/bash

# Default encryption algorithm
DEFAULT_ALGORITHM="AES"

# Function to check if required dependencies are installed
check_dependencies() {
  # List of required dependencies
  dependencies=(python3 pip3)

  # Loop through each dependency and check if it is installed
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      echo "$dep is not installed. Please install it before running this script."
      exit 1
    fi
  done

  # Check if the Python 'cryptography' package is installed
  if ! python3 -c "import cryptography" &> /dev/null; then
    echo "The Python 'cryptography' package is not installed. Installing..."
    pip3 install cryptography
  fi
}

# Function to encrypt a file
encrypt_file() {
  local file="$1"
  local password="$2"
  local algorithm="${3:-$DEFAULT_ALGORITHM}"

  if [[ ! -f "$file" ]]; then
    echo "Error: File '$file' not found!"
    return 1
  fi

  if [[ "$algorithm" == "RSA" ]]; then
    python3 encrypt_decrypt.py generate_rsa_key_pair "$password"
    public_key="public_key.pem"
    private_key="private_key.pem"
    echo "RSA key pair generated."
  else
    public_key="$password"
    private_key="$password"
  fi

  python3 encrypt_decrypt.py encrypt "$file" "$public_key" "$algorithm"
}

# Function to decrypt a file
decrypt_file() {
  local file="$1"
  local password="$2"
  local algorithm="${3:-$DEFAULT_ALGORITHM}"

  if [[ ! -f "$file" ]]; then
    echo "Error: File '$file' not found!"
    return 1
  fi

  if [[ "$file" != *.enc ]]; then
    echo "Error: The file to be decrypted must have a '.enc' extension!"
    return 1
  fi

  if [[ "$algorithm" == "RSA" ]]; then
    private_key="private_key.pem"
  else
    private_key="$password"
  fi

  python3 encrypt_decrypt.py decrypt "$file" "$private_key" "$algorithm"
}

# Function to generate RSA key pair
generate_rsa_key_pair() {
  local password="$1"
  python3 encrypt_decrypt.py generate_rsa_key_pair "$password"
  echo "RSA key pair generated."
}

# Main script logic
main() {
  check_dependencies

  case "$1" in
    encrypt)
      if [[ $# -lt 3 ]]; then
        echo "Usage: $0 encrypt <filename> <password> [algorithm]"
        exit 1
      fi
      encrypt_file "$2" "$3" "$4"
      ;;
    decrypt)
      if [[ $# -lt 3 ]]; then
        echo "Usage: $0 decrypt <filename> <password> [algorithm]"
        exit 1
      fi
      decrypt_file "$2" "$3" "$4"
      ;;
    generate_rsa_key_pair)
      if [[ $# -ne 2 ]]; then
        echo "Usage: $0 generate_rsa_key_pair <password>"
        exit 1
      fi
      generate_rsa_key_pair "$2"
      ;;
    *)
      echo "Usage: $0 {encrypt|decrypt|generate_rsa_key_pair} <filename> <password> [algorithm]"
      exit 1
      ;;
  esac
}

main "$@"