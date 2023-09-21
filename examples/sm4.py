# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

print("SM4_KEY_SIZE =", SM4_KEY_SIZE)
print("SM4_BLOCK_SIZE =", SM4_BLOCK_SIZE)
print("")

key = rand_bytes(SM4_KEY_SIZE)
plaintext = rand_bytes(SM4_BLOCK_SIZE)

sm4_enc = Sm4(key, DO_ENCRYPT)
ciphertext = sm4_enc.encrypt(plaintext)

sm4_dec = Sm4(key, DO_DECRYPT)
decrypted = sm4_dec.encrypt(ciphertext)

print("key =", key.hex())
print("plaintext =", plaintext.hex())
print("ciphertext = ", ciphertext.hex())
print("decrypted =", decrypted.hex())

