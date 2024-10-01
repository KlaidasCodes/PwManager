import datetime
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import json
import binascii

def encrypt_text(enc_key, text):
    """takes encryption key and text and returns that text encrypted text with random IV as its 1st 16bytes (128bits)"""
    # turns received text into bytes
    text_in_bytes = text.encode("UTF-8")
    # generates a random 16byte IV number
    random_iv = os.urandom(16)
    # creates a cipher that will use AES with your key, CBC XORed with the IV and everything else using the backend.
    cipher = Cipher(algorithms.AES(key=enc_key), modes.CBC(random_iv), backend=default_backend())
    # creates the encryptor
    encryptor = cipher.encryptor()
    # makes sure our text has bits that would be a multiple of 128bits (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(text_in_bytes) + padder.finalize()
    # takes the padded text and encrypts it
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    # returns one joint string of the IV + encrypted text
    return random_iv + encrypted_text

def decrypt_text(key, encrypted_text):
    """takes a key and encrypted text and returns the decrypted original text"""
    # getting the IV from the encrypted text, it's 16bytes long
    iv = encrypted_text[:16]
    # getting the actual encrypted text without IV
    remaining_text = encrypted_text[16:]
    # creating a cipher that uses AES with a key, does CBC XOR with IV
    cipher = Cipher(algorithms.AES(key=key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # decrypting the encrypted text using the cipher
    decrypted_text = decryptor.update(remaining_text) + decryptor.finalize()
    # unpadding the text to get our original plaintext
    depadder = padding.PKCS7(128).unpadder()
    unpadded_decrypted_text = depadder.update(decrypted_text) + depadder.finalize()
    # returns clean decrypted text
    return unpadded_decrypted_text.decode("UTF-8")

def turn_byte_enc_password_to_hex(encrypted_byte_password):
    """Takes the encrypted password in byte form and transforms it into hex format, so it can be stored as json"""
    encrypted_password_hex = binascii.hexlify(encrypted_byte_password).decode()
    return encrypted_password_hex

def turn_hex_password_to_byte(encrypted_hex_password):
    """Takes encrypted password in hex form and transforms it into bytes, so it can be used to be decrypted"""
    encrypted_password_bytes = binascii.unhexlify(encrypted_hex_password)
    return encrypted_password_bytes

def sub_dictionary_input(website_name, web_username, web_encrypted_pw):
    """Takes website name, username and encrypted password and puts them into an acceptable dictionary format, ready
    to be put into the master dictionary with all the info"""
    sub_dict_temp = {website_name: {
        "username": web_username,
        "password": web_encrypted_pw,
    }}
    return sub_dict_temp

def generate_password():
    """Generates a randomized set of 16 characters that can be used as password, returns password"""
    characters = string.digits + string.ascii_letters + string.punctuation
    generated_password = "".join(secrets.choice(characters) for i in range(16))
    return generated_password

def update_master_dict(new_sub_dict, json_file_path):
    with open(json_file_path, "r") as json_file:
        master_dict = json.load(json_file)
        master_dict.update(new_sub_dict)
        with open(json_file_path, "w") as json_file_2:
            json.dump(master_dict, json_file_2, indent=4)
            print("The master dictionary has been updated successfully.")
            # print(master_dict)

def take_info():
    password_temp = generate_password()
    print(f"16 digit password: {password_temp}")
    username_temp = input("Username:\t")
    website_temp = input("Website/App:\t").lower()
    return password_temp, username_temp, website_temp

def time_increments(time_to_wait, is_password_correct):
    """If inputted password is incorrect, the wait time before you can try again doubles. 1s-> 2s-> 4s-> 8s
    The function takes the current cooldown time and a boolean is_password_correct and returns the new cooldown time"""
    time_to_wait_temp = time_to_wait
    if not is_password_correct:
        time_to_wait_temp *= 2
    return time_to_wait_temp

def browse_main_dict(dict_main_path, word_to_browse):
    """Takes an input word and then browses the main_dict for any matches"""
    with open(dict_main_path, "r") as json_file:
        data = json.load(json_file)
        needed_data = data[word_to_browse.lower()]
        website = word_to_browse.lower()
        username = needed_data["username"]
        encoded_pw = needed_data["password"]
        return website, username, encoded_pw


