# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *


print("SM4_GCM_MIN_IV_SIZE =", SM4_GCM_MIN_IV_SIZE)
print("SM4_GCM_MAX_IV_SIZE =", SM4_GCM_MAX_IV_SIZE)
print("SM4_GCM_DEFAULT_IV_SIZE =", SM4_GCM_DEFAULT_IV_SIZE)
print("SM4_GCM_DEFAULT_TAG_SIZE =", SM4_GCM_DEFAULT_TAG_SIZE)
print("SM4_GCM_MAX_TAG_SIZE =", SM4_GCM_MAX_TAG_SIZE)
print("")


key = rand_bytes(SM4_KEY_SIZE)
iv = rand_bytes(SM4_GCM_DEFAULT_IV_SIZE)
aad = b'Additional auth-data'
plaintext = b'abc'
taglen = SM4_GCM_DEFAULT_TAG_SIZE

sm4_enc = Sm4Gcm(key, iv, aad, taglen, DO_ENCRYPT)
ciphertext = sm4_enc.update(plaintext)
ciphertext += sm4_enc.finish()

sm4_dec = Sm4Gcm(key, iv, aad, taglen, DO_DECRYPT)
decrypted = sm4_dec.update(ciphertext)
decrypted += sm4_dec.finish()

print("key =", key.hex())
print("iv =", iv.hex())
print("aad =", aad.hex())
print("taglen =", taglen)
print("plaintext =", plaintext.hex())
print("ciphertext = ", ciphertext.hex())
print("decrypted =", decrypted.hex())

