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
from function_storage import *


# generate just once and then keep on a USB, not in the code

# key = os.urandom(32)
# print(key)
master_dictionary = {}
KEY = b'\x93\xe9\x13\xe6\xed>\x97\xa8*\xaa\xd1H\xacMs\x08=&L\xdcDp\x9dc7~\xdd\xbf\x88l\xfb%'
key_hex = "93e913e6ed3e97a82aaad148ac4d73083d264cdc44709d63377eddbf886cfb25"

usb_path = "D:\placeholder_for_key.txt"

# TODO-1 code a notes app first without any encryption
# TODO-2 look into pgp, watch some videos and learn about it in depth. Will give me a deeper understanding of
# how to make it actually secure and how to protect it against possible attacks and breaches, or passwords
# showing in my source code, if that is exposed.
# TODO-3 apply pgp encryption onto the notes app. Notes will be stored in a .txt file very possibly,
# so just encrypt the .txt file
# TODO-3.1(fixed) Encrypt passwords using AES256 encryption. When need a new password, the app generates a 16 digit
# code that can be copied and pasted into the website. Then we go back to the app, input the remaining information:
# website and username used. The code then encrypts the password using AES256 and creates a dictionary in this format:
# {website_name: {username: your_username,
#                 password: encrypted_password}
# and then it is added to a larger dictionary that will hold all of those website account information dictionaries
# the overall dictionary then needs to be locked under a master key, which would allow the user to access the master
# dictionary of account information. However, the passwords inside would be encrypted, so a key is needed if you want
# to get to a password.
# TODO-4 create a system that would take the website, username and pw and return them so the data can be processed
# by the following functions
# TODO-5 don't forget to change the overall code to be a pw manager and not a notes app

date_today = datetime.date.today()
do_continue = True
if __name__ == "__main__":
    while do_continue:
        new_or_old_info = input("1 - Add new account information\n2 - Retrieve existing account information\n").lower()
        if new_or_old_info == "1":
            # still need to fix the part where the key has to come from a usb, not from my computer
            temp_password, temp_username, temp_website = take_info()
            print(f"The details you have inputted:\n\nUsername:\t\t{temp_username}\nWebsite:\t\t{temp_website}\n\n"
                  f"Are the details correct?")
            are_details_correct = input("Y/N\n").lower()
            if are_details_correct == "n":
                while are_details_correct == "n":
                    temp_password, temp_username, temp_website = take_info()
                    print(f"The details you have inputted:\n\nUsername:\t\t{temp_username}\nWebsite:\t\t{temp_website}\n\n"
                          f"Are the details correct?")
                    are_details_correct = input("Y/N\n").lower()
            # encrypting the password and turning it into a hex format from byte:
            encrypted_password = encrypt_text(enc_key=KEY, text=temp_password)
            encrypted_hex_password = byte_to_hex(encrypted_password)
            # print(f"Encrypted HEX password: {encrypted_hex_password}")
            dictionary_with_info = sub_dictionary_input(website_name=temp_website, web_username=temp_username,
                                                        web_encrypted_pw=encrypted_hex_password)
            # print(f"To put into the master dictionary: {dictionary_with_info}")
            # master_dictionary.update(dictionary_with_info)
            # so far the code generates a password that I can copy, then asks for your username and website,
            # encrypts the password and puts everything together in a sub-dictionary which is then ready to be moved
            # to the master dictionary

            # the sub_dict is then moved to a master dict which is a json file and stored in there
            update_master_dict(json_file_path="data.json", new_sub_dict=dictionary_with_info)
            do_continue = input("Anything else? (Y/N)\n").lower()
            if do_continue == "n":
                break
        elif new_or_old_info == "2":
            website_choice = input("What website info would you like?\n").lower()
            try:
                website, username, encrypted_hex_password = browse_main_dict("data.json", website_choice)
                encrypted_byte_pw = hex_to_byte(encrypted_hex_password)
                # decrypted_password = decrypt_text(KEY, encrypted_byte_pw)
                # Now gotta request a key to decrypt a password. It can be manually entered or pulled straight
                # from a USB.
                type_or_pull_key = input("1 - Enter the key manually\n2 - Pull the key from USB\n")
                if type_or_pull_key == "1":
                    ask_for_key_hex = input("Enter the key:\n")
                    # the problem here is that I input a string instead of a byte format. Ideally, I'd paste a hex
                    # form, then it would get converted to byte and used to decrypt.
                    key_byte_format = binascii.unhexlify(ask_for_key_hex)
                    decrypted_pw = decrypt_text(key_byte_format, encrypted_byte_pw)
                    print(f"The decrypted password for {website} is {decrypted_pw}")
                    do_continue = input("Anything else? (Y/N)\n").lower()
                    if do_continue == "n":
                        break
                elif type_or_pull_key == "2":
                    key_from_usb = taking_key_from_usb(usb_path)
                    print(key_from_usb)
                    key_byte_format = binascii.unhexlify(key_from_usb)
                    decrypted_pw = decrypt_text(key_byte_format, encrypted_byte_pw)
                    print(f"The decrypted password for {website} is {decrypted_pw}")
                    do_continue = input("Anything else? (Y/N)\n").lower()
                    if do_continue == "n":
                        break
            except KeyError:
                print("Couldn't find any data for the inputted website.")
        else:
            print("Invalid input.")
            # Now we're gonna store the master dictionary as a json file. The json file then gets encrypted using AES
            # and a master password (the 4 word one). We'll use KDF (key derivation function) to derive a secure 256bit
            # key from my master password, generate a salt and IV (will just put them in front of the encrypted text again)
            # And then all I'll need to do to unlock the json file will be to input the master password


# ok so the password generation, encryption and login info storage in a master dict (JSON) all works.
# now gotta work out the other parts - the master password f


# TODO-1: convert json to hex, encrypt the json with AES and KDF.
# testing in "trying_encryption.py"




# IDEA FOR FUTURE: add an option to change the master password so it doesnt have to be manipulated
# by going through code manually.



# Still need to encrypt the USB and put a passord on it. DOwnloaded VeraCrypt, do it with that. 
