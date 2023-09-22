import os
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from base64 import urlsafe_b64encode

def create_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(message.encode())
    return encrypted_text

def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_message).decode()
    return decrypted_text

def main():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts
                    (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password BLOB)''')

    master_password = input("Enter your master password: ")
    salt = os.urandom(16)  # You should store this securely for later use
    key = create_key_from_password(master_password, salt)

    while True:
        print("\n1. Store a password\n2. Retrieve a password\n3. Quit")
        choice = input("Enter your choice: ")
        if choice == "1":
            website = input("Enter website name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            encrypted_password = encrypt_message(password, key)
            cursor.execute("INSERT INTO accounts (website, username, password) VALUES (?, ?, ?)", (website, username, encrypted_password))
            conn.commit()
        elif choice == "2":
            website = input("Enter website name to retrieve the password: ")
            cursor.execute("SELECT username, password FROM accounts WHERE website=?", (website,))
            account = cursor.fetchone()
            if account:
                decrypted_password = decrypt_message(account[1], key)
                print(f"Website: {website}\nUsername: {account[0]}\nPassword: {decrypted_password}")
            else:
                print("No account found for this website.")
        elif choice == "3":
            break

    conn.close()

if __name__ == '__main__':
    main()
