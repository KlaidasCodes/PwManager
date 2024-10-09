import datetime
import secrets
import string
import hashlib
import os
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

def byte_to_hex(encrypted_byte_password):
    """Takes the encrypted password in byte form and transforms it into hex format, so it can be stored as json"""
    encrypted_password_hex = binascii.hexlify(encrypted_byte_password).decode()
    return encrypted_password_hex

def hex_to_byte(encrypted_hex_password):
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
    with open(json_file_path, "w") as json_file:
        json.dump(master_dict, json_file, indent=4)


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


def creating_random_16_bit():
    random_salt = os.urandom(16)
    return random_salt


def deriving_key_from_master_password(master_pw, salt, iterations=1000000, key_length=32):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        master_pw.encode(),
        salt,
        iterations,
        dklen=key_length
    )
    return salt, key


def taking_key_from_usb(path):
    usb_not_found = True
    while usb_not_found:
        try:
            with open(path) as file:
                key_from_usb = file.read()
                usb_not_found = False
                return key_from_usb
        except FileNotFoundError:
            print("USB not found. Plug it in and press enter:\n")
            pressed_enter = input("")


def encrypting_json_file_with_new_password(json_path, key, salt):
    """takes json, converts it to string in byte format, encrypts and adds a salt as the first 16 bytes.
    And then replaces the json with the new info just encrypted. Returns nothing."""
    with open(json_path) as main_file:
        json_as_dictionary = json.load(main_file)
        json_as_string = json.dumps(json_as_dictionary)
        # instead of derived_key, needs to be the actual derivedKey inputted into the
        # function
        json_as_string_byte_enc = encrypt_text(key, json_as_string)

        json_as_string_byte_enc_with_salt = salt + json_as_string_byte_enc
        # print(json_as_string_byte_enc)
        json_as_string_hex_enc_with_salt = byte_to_hex(json_as_string_byte_enc_with_salt)
        # print(json_as_string_hex_enc)
        with open("data_copy.json", "w") as main_file_2:
            json.dump(json_as_string_hex_enc_with_salt, main_file_2)


def split_encrypted_json_and_salt(encrypted_json_with_salt):
    encrypted_json_with_salt_formatted = encrypted_json_with_salt[1:-1]
    """takes the json file and returns encrypted text and salt separately. Takes encrypted json in hex format"""
    encrypted_json = encrypted_json_with_salt_formatted[32:]
    salt = encrypted_json_with_salt_formatted[:32]
    return encrypted_json, salt


def returns_encrypted_json_and_salt_separately(json_path):
    with open(json_path, "r") as file:
        encrypted_json_with_salt_dict = json.load(file)
        encrypted_json_with_salt_string = json.dumps(encrypted_json_with_salt_dict)
        # print(encrypted_json_with_salt_string)
        # encrypted_json_with_salt_string_byte = hex_to_byte(encrypted_json_with_salt_string)
        encrypted_json_string_byte, salt_str_byte = split_encrypted_json_and_salt(encrypted_json_with_salt_string)
        # print(f"encrypted json string byte: {encrypted_json_string_byte}")
        # print(f"salt str byte: {salt_str_byte}")
        return encrypted_json_string_byte, salt_str_byte


def ask_for_master_pw():
    return input("What's the password?\n")


def decrypt_json(json_path):
    """Takes the encrypted json from the destination, separates its salt and encrypted parts
    and then decrypts the json, returning decrypted json(str) and its salt(byte)"""
    encrypted_json, salt = returns_encrypted_json_and_salt_separately(json_path)
    encrypted_json_byte = hex_to_byte(encrypted_json)
    master_password = ask_for_master_pw()
    # master_password = test_password
    # print(salt)
    # master password has to be converted to bytes first, just like salt.
    salt_byte = hex_to_byte(salt)
    derived_used_salt, derived_key_from_master_pw = deriving_key_from_master_password(master_pw=master_password, salt=salt_byte)
    # print(f"derived key from master pw: {derived_key_from_master_pw}")
    # derived_key_from_master_pw_byte = hex_to_byte(derived_key_from_master_pw)
    final_result = decrypt_text(derived_key_from_master_pw, encrypted_json_byte)
    # print("Password is correct!\n\n\n\n\n")
    # print(f"Final result: {final_result}")
    return final_result, salt_byte


def initial_json_encryption(json_path, drv_salt, drv_key):
    """Takes inputs of json_path, derived salt, derived key (from KDF). Replaces the content in the destination
    (the json file) with an encrypted version of it in string hex format."""
    with open(json_path, "r") as file:
        json_file_as_dict = json.load(file)
        json_file_as_string = json.dumps(json_file_as_dict)
        # print(json_file_as_string)
        encrypted_json_str_byte = encrypt_text(drv_key, json_file_as_string)
        # print(encrypted_json_str)
        enc_json_str_and_salt_bytes = drv_salt + encrypted_json_str_byte
        # The code read the json file and encrypted it, added a salt as the first 16 bytes. Now it needs to replace the
        # current unencrypted json file
        encrypted_json_str_and_salt_hex = byte_to_hex(enc_json_str_and_salt_bytes)
        print(f"Encrypted json: {encrypted_json_str_and_salt_hex}")
        with open("data_copy.json", "w") as file1:
            json.dump(encrypted_json_str_and_salt_hex, file1)
