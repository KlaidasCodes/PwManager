import json
import binascii
from function_storage import *
#
# KEY = b'\x93\xe9\x13\xe6\xed>\x97\xa8*\xaa\xd1H\xacMs\x08=&L\xdcDp\x9dc7~\xdd\xbf\x88l\xfb%'
# key_in_hex = binascii.hexlify(KEY).decode("UTF-8")
# print(key_in_hex)
#


# print(file_readable)


# logic of the encryption:
# we open the json file and get the contents from it (the contents will be encrypted by the
# master password. Then we decrypt that and data can then be manipulated
# When the app shuts down, the last thing it does is encrypt the json again and update
# json file both on the computer and the USB drive so they both have current versions.

# we need an encryption funcion now

test_password = "I_like_dan_cing_in_the_rain"

our_json_file_path = "C:/Users/Klaidas/PycharmProjects/todolist/data_copy.json"

# still needs a bunch of exceptions for incorrect key handling

# initial_json_encryption("data_copy.json", drv_salt=derived_salt, drv_key=derived_key)


# These 4 lines:
# Generate a random salt, then use KDF to derive a key from a master password. Using that it takes the json file
# and encrypts it into a string in hex plus its salt as the first 16bytes (32 symbols in hex). This logic only needs to
# be used once, it establishes a master password and locks json essentially.
random_salt = creating_random_16_bit()
derived_salt, derived_key = deriving_key_from_master_password(test_password, random_salt)
initial_json_encryption("data_copy.json", derived_salt, derived_key)


# This line takes the encrypted json file, asks for a master password and then decrypts it, returning the salt used and
# the decrypted json content. Now it can be browsed through. Will have to go in the "if ans=="2" (accessing info)

decrypted_json, salt = decrypt_json("data_copy.json")
print(f"decrypted json: {decrypted_json}")
