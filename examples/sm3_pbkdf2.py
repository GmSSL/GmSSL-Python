# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0


from gmssl import *


print("SM3_PBKDF2_MIN_ITER =", SM3_PBKDF2_MIN_ITER)
print("SM3_PBKDF2_MAX_ITER =", SM3_PBKDF2_MAX_ITER)
print("SM3_PBKDF2_MAX_SALT_SIZE =", SM3_PBKDF2_MAX_SALT_SIZE)
print("SM3_PBKDF2_DEFAULT_SALT_SIZE =", SM3_PBKDF2_DEFAULT_SALT_SIZE)
print("SM3_PBKDF2_MAX_KEY_SIZE =", SM3_PBKDF2_MAX_KEY_SIZE)
print("")

passwd = "Password"
salt = rand_bytes(SM3_PBKDF2_DEFAULT_SALT_SIZE)
iterator = SM3_PBKDF2_MIN_ITER
keylen = 32

key = sm3_pbkdf2(passwd, salt, iterator, keylen)
print("Password :", passwd)
print("Salt :", salt.hex())
print("Iterator :", iterator)
print("Keylen :", keylen)
print("sm2_pbkdf2(Password, Salt, Iter, Keylen) :", key.hex())

