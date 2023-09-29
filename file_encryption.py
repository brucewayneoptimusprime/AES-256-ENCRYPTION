import os
import base64
import mysql.connector
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Function to generate a random encryption key (AES 256)
def generate_random_key():
    key = os.urandom(32)  # Generate a 256-bit (32-byte) random key
    return key

# Function to save the encryption key to a text file
def save_key_to_file(key, file_path):
    key_file_path = file_path + '.key'
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)

# Function to save the encryption key to the MySQL database
def save_key_to_mysql(key):
    # Replace with your MySQL database credentials
    db_host = 'localhost'
    db_user = 'root'
    db_password = 'brucewayneoptimusprime232004@free'
    db_name = 'key_storage'  # Your database name

    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )

        cursor = connection.cursor()

        # Insert the encryption key into the table
        insert_query = "INSERT INTO encryption_keys (key_data) VALUES (%s)"
        key_data = (key,)  # The key is binary data

        # Execute the INSERT query
        cursor.execute(insert_query, key_data)

        # Commit the changes and close the connection
        connection.commit()
        connection.close()
        print("Encryption key saved to MySQL database successfully.")
    except mysql.connector.Error as err:
        print(f"Error: {err}")

# Function to encrypt a file using AES 256
def encrypt_file(file_path, key):
    output_file_path = file_path + '.enc'
    iv = os.urandom(16)  # Generate a random initialization vector (IV)

    # Create an AES 256 cipher with CBC mode and PKCS7 padding
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Pad the data to the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)

    save_key_to_file(key, file_path)  # Save the key to a text file
    save_key_to_mysql(key)  # Save the key to MySQL
    os.remove(file_path)
    print(f'File encrypted and saved as {output_file_path}')

# Function to decrypt a file using AES 256
def decrypt_file(encrypted_file_path, key):
    decrypted_file_path = encrypted_file_path[:-4]  # Remove the '.enc' extension

    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        encrypted_data = encrypted_file.read()

    # Create an AES 256 cipher with CBC mode and PKCS7 padding
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(unpadded_data)

    os.remove(encrypted_file_path)
    print(f'File decrypted and saved as {decrypted_file_path}')

if __name__ == '__main__':
    action = input("Enter 'encrypt' or 'decrypt': ").lower()
    file_path = input("Enter the file path: ")

    if action == 'encrypt':
        key = generate_random_key()
        encrypt_file(file_path, key)
        print(f'Encryption Key (Base64 Encoded): {base64.urlsafe_b64encode(key).decode()}')
    elif action == 'decrypt':
        key = input("Enter the decryption key (Base64 Encoded): ")
        key = base64.urlsafe_b64decode(key)
        decrypt_file(file_path, key)
    else:
        print("Invalid action. Please enter 'encrypt' or 'decrypt'.")




