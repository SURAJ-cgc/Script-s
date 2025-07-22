#!/usr/bin/env python3
from Crypto.Cipher import DES3
from base64 import b64decode, binascii
import sys
import re

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    """Decrypt a base64-encoded DES3-CBC encrypted password."""
    try:
        data = b64decode(encrypted_password)
        iv, ciphertext = data[:8], data[8:]
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        
        return decrypted.rstrip(b"\0").decode('utf-8', errors='ignore')
        
    except Exception as e:
        return f"Error: {str(e)}"

def validate_base64(s: str) -> bool:
    """Validate if string is valid base64."""
    try:
        b64decode(s)
        return True
    except (binascii.Error, ValueError):
        return False

def get_decrypt_key() -> bytes:
    """Get and validate decrypt key from user."""
    while True:
        decrypt_key = input("\n[1] Enter your decrypt key: ").strip()
        
        if not decrypt_key:
            print("❌ Error: Decrypt key cannot be empty! Please try again.")
            continue
        
        key_bytes = decrypt_key.encode('utf-8')
        
        # Handle key length for DES3
        if len(key_bytes) == 24:
            print("✅ Perfect! 24-byte key detected.")
            return key_bytes
        elif len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b'\0')
            print(f"🔧 Key padded from {len(decrypt_key.encode('utf-8'))} to 24 bytes.")
            return key_bytes
        else:
            key_bytes = key_bytes[:24]
            print(f"🔧 Key truncated from {len(decrypt_key.encode('utf-8'))} to 24 bytes.")
            return key_bytes

def get_encrypted_password() -> str:
    """Get and validate encrypted password from user."""
    while True:
        encrypted_password = input("\n[2] Enter the encrypted password (base64): ").strip()
        
        if not encrypted_password:
            print("❌ Error: Encrypted password cannot be empty! Please try again.")
            continue
        
        if not validate_base64(encrypted_password):
            print("❌ Error: Invalid base64 format! Please check your input and try again.")
            continue
        
        print("✅ Valid base64 format detected.")
        return encrypted_password

def main():
    """Main interactive function."""
    try:
        print("=" * 55)
        print("        🔓 DES3-CBC Password Decryption Tool 🔓")
        print("=" * 55)
        
        # Get user inputs with validation
        key_bytes = get_decrypt_key()
        encrypted_password = get_encrypted_password()
        
        print("\n" + "=" * 55)
        print("        🔄 Processing Decryption...")
        print("=" * 55)
        
        # Perform decryption
        result = decrypt_password(encrypted_password, key_bytes)
        
        # Display results
        print(f"\n📊 Decryption Summary:")
        print("─" * 40)
        print(f"🔑 Key Used: {key_bytes.decode('utf-8', errors='ignore')}")
        print(f"🔒 Encrypted: {encrypted_password}")
        print(f"🔓 Result: {result}")
        print("─" * 40)
        
        if result.startswith("Error:"):
            print(f"\n❌ Decryption Failed!")
            print(f" [-]  Reason: {result}")
        else:
            print(f"\n✅ Decryption Successful!")
            print(f" [+] Your  Password: '{result}'")
            
        # Ask if user wants to try again
        again = input(f"\n🔄 Do you want to decrypt another password? (y/n): ").lower()
        if again in ['y', 'yes']:
            print("\n" + "="*55)
            main()  # Recursive call for another round
            
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Operation cancelled by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
