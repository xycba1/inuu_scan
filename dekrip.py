from cryptography.fernet import Fernet
import base64

# Encrypted message and key (replace these with actual values from encrypted_message.py)
encrypted_message = b'gAAAAABmqKU-rspIsB6XtXl65DOB5x0UzmfMGhNN8myzwqO9SJOQk8QcYmBDyCu0TbCiO400U3yTA3-6FBp0AIT88M-smFkOJQ=='  # Update with the actual encrypted message
key = base64.urlsafe_b64decode(b'dUpqdk1ydHF6VGtpRHplWDE0RnRieldISFZZMVJlRWdIalZKa0ZoakN0ST0=')  # Update with the actual base64-encoded key

# Initialize cipher suite
cipher_suite = Fernet(key)

def decrypt_message(encrypted_message):
    decrypted_data = cipher_suite.decrypt(encrypted_message)
    return decrypted_data.decode('utf-8')

def main():
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
