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
random_salt = creating_random_16_bit()
derived_salt, derived_key = deriving_key_from_master_password(test_password, random_salt)
print(derived_key)



our_json_file_path = "C:/Users/Klaidas/PycharmProjects/todolist/data_copy.json"
with open(our_json_file_path, "r") as file:
    file_readable = json.load(file)
    encrypted_json = encrypt_text(derived_key, text=file_readable)
    print(encrypted_json)
    # FINISH THIS ####################
    ################################
    ###############################
    #############################
