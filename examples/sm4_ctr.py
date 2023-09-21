# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

print("SM4_KEY_SIZE =", SM4_KEY_SIZE)
print("SM4_CTR_IV_SIZE =", SM4_CTR_IV_SIZE)
print("")

key = rand_bytes(SM4_KEY_SIZE)
iv = rand_bytes(SM4_CTR_IV_SIZE)
plaintext = b'abc'

sm4_enc = Sm4Ctr(key, iv)
ciphertext = sm4_enc.update(plaintext)
ciphertext += sm4_enc.finish()

sm4_dec = Sm4Ctr(key, iv)
decrypted = sm4_dec.update(ciphertext)
decrypted += sm4_dec.finish()

print("key =", key.hex())
print("iv =", iv.hex())
print("plaintext =", plaintext.hex())
print("ciphertext = ", ciphertext.hex())
print("decrypted =", decrypted.hex())

