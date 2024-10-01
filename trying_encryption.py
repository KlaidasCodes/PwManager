# # import json
import binascii
# # # from function_storage import *
# # KEY = b'\x93\xe9\x13\xe6\xed>\x97\xa8*\xaa\xd1H\xacMs\x08=&L\xdcDp\x9dc7~\xdd\xbf\x88l\xfb%'
# #
# #
# # website, username, encrypted_password = browse_main_dict("data.json", "gmail")
# # encrypted_password_byte = turn_hex_password_to_byte(encrypted_password)
# #
# #
# # decrypted_pw = decrypt_text(encrypted_text=encrypted_password_byte, key=KEY)
# # print(decrypted_pw)
# #
# #
# #
#
#
# print(idkwgat)

KEY = b'\x93\xe9\x13\xe6\xed>\x97\xa8*\xaa\xd1H\xacMs\x08=&L\xdcDp\x9dc7~\xdd\xbf\x88l\xfb%'
key_in_hex = binascii.hexlify(KEY).decode("UTF-8")
print(key_in_hex)



