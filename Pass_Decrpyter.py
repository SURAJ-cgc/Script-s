#!/usr/bin/env python3
from Crypto.Cipher import DES3
from base64 import b64decode, b64encode
import sys
import os

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

def encrypt_password(password: str, key: bytes) -> str:
    """Encrypt a password using DES3-CBC."""
    try:
        # Generate random 8-byte IV
        iv = os.urandom(8)
        
        # Prepare password with PKCS7-like padding
        password_bytes = password.encode('utf-8')
        block_size = 8
        padding_length = block_size - (len(password_bytes) % block_size)
        padded_password = password_bytes + (bytes([padding_length]) * padding_length)
        
        # Encrypt
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(padded_password)
        
        # Combine IV + ciphertext and encode as base64
        encrypted_data = iv + ciphertext
        return b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        return f"Encryption Error: {str(e)}"

def decrypt_password_pkcs7(encrypted_password: str, key: bytes) -> str:
    """Decrypt with proper PKCS7 padding removal."""
    try:
        data = b64decode(encrypted_password)
        iv, ciphertext = data[:8], data[8:]
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        if padding_length <= 8:
            decrypted = decrypted[:-padding_length]
        else:
            # Fallback to null byte removal
            decrypted = decrypted.rstrip(b"\0")
        
        return decrypted.decode('utf-8', errors='ignore')
        
    except Exception as e:
        return f"Error: {str(e)}"

def create_real_example():
    """Create a real working example."""
    print("\n" + "🔧" * 25 + " CREATING REAL EXAMPLE " + "🔧" * 25)
    
    original_password = "hello_you_got-it"
    example_key = "my_secret_key_123456789!"  # 24 bytes
    
    key_bytes = example_key.encode('utf-8')
    
    print(f"\n📝 Creating real encrypted example...")
    print(f"├─ Password: '{original_password}'")
    print(f"├─ Key: '{example_key}' ({len(key_bytes)} bytes)")
    
    # Create real encrypted version
    encrypted = encrypt_password(original_password, key_bytes)
    
    print(f"└─ Encrypted: {encrypted}")
    
    # Test both decryption methods
    print(f"\n🧪 Testing decryption...")
    result1 = decrypt_password(encrypted, key_bytes)
    result2 = decrypt_password_pkcs7(encrypted, key_bytes)
    
    print(f"├─ Method 1 (null padding): '{result1}'")
    print(f"└─ Method 2 (PKCS7 padding): '{result2}'")
    
    if result2 == original_password:
        print("✅ SUCCESS! PKCS7 method works!")
        return example_key, encrypted, "pkcs7"
    elif result1 == original_password:
        print("✅ SUCCESS! Null padding method works!")
        return example_key, encrypted, "null"
    else:
        print("❌ Both methods failed. Let's try with null padding encryption...")
        
        # Try with null padding encryption
        encrypted_null = encrypt_with_null_padding(original_password, key_bytes)
        result_null = decrypt_password(encrypted_null, key_bytes)
        
        print(f"\n🔄 Trying null padding encryption...")
        print(f"├─ Encrypted (null): {encrypted_null}")
        print(f"└─ Decrypted: '{result_null}'")
        
        if result_null == original_password:
            print("✅ SUCCESS! Null padding method works!")
            return example_key, encrypted_null, "null"
    
    return None, None, None

def encrypt_with_null_padding(password: str, key: bytes) -> str:
    """Encrypt with null byte padding (simpler method)."""
    try:
        iv = os.urandom(8)
        
        password_bytes = password.encode('utf-8')
        # Pad to multiple of 8 bytes with null bytes
        padding_length = 8 - (len(password_bytes) % 8)
        if padding_length == 8:
            padding_length = 0
        padded_password = password_bytes + (b'\0' * padding_length)
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(padded_password)
        
        encrypted_data = iv + ciphertext
        return b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        return f"Encryption Error: {str(e)}"

def main():
    """Main function with real example."""
    try:
        print("=" * 75)
        print("            🔓 DES3-CBC Password Decryption Tool 🔓")
        print("=" * 75)
        
        print("\n1️⃣  Choose an option:")
        print("   [1] Generate and test a real working example")
        print("   [2] Enter your own decrypt key and encrypted password")
        
        choice = input("\nEnter choice (1 or 2): ").strip()
        
        if choice == "1":
            example_key, encrypted, method = create_real_example()
            
            if example_key and encrypted:
                print(f"\n" + "="*75)
                print("                        📋 COPY THESE VALUES 📋")
                print("="*75)
                print(f"🔑 Decrypt Key: {example_key}")
                print(f"🔒 Encrypted Password: {encrypted}")
                print(f"🔧 Method: {method}")
                print("="*75)
                
                test_now = input("\nTest decryption now? (y/n): ").lower()
                if test_now in ['y', 'yes']:
                    key_bytes = example_key.encode('utf-8')
                    
                    if method == "pkcs7":
                        result = decrypt_password_pkcs7(encrypted, key_bytes)
                    else:
                        result = decrypt_password(encrypted, key_bytes)
                    
                    print(f"\n🔓 Decrypted: '{result}'")
                    if result == "hello_you_got-it":
                        print("🎉 PERFECT! The example works!")
                    else:
                        print("❌ Something's still wrong...")
                
                return
            else:
                print("❌ Failed to create working example")
                return
        
        # Manual input mode
        print(f"\n📝 Manual Input Mode:")
        
        while True:
            decrypt_key = input("\n[1] Enter your decrypt key: ").strip()
            if decrypt_key:
                break
            print("❌ Key cannot be empty!")
        
        key_bytes = decrypt_key.encode('utf-8')
        if len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b'\0')
            print(f"🔧 Key padded to 24 bytes")
        elif len(key_bytes) > 24:
            key_bytes = key_bytes[:24]
            print(f"🔧 Key truncated to 24 bytes")
        
        while True:
            encrypted_password = input("\n[2] Enter encrypted password: ").strip()
            if encrypted_password:
                break
            print("❌ Encrypted password cannot be empty!")
        
        print(f"\n" + "="*75)
        print("                        🔄 DECRYPTING...")
        print("="*75)
        
        # Try both methods
        result1 = decrypt_password(encrypted_password, key_bytes)
        result2 = decrypt_password_pkcs7(encrypted_password, key_bytes)
        
        print(f"\n📊 Results:")
        print(f"├─ Method 1 (null padding): '{result1}'")
        print(f"└─ Method 2 (PKCS7 padding): '{result2}'")
        
        print(f"\n🎯 Most likely result: '{result2 if not result2.startswith('Error') else result1}'")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
