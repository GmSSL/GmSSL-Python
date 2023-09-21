# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

print("ZUC_KEY_SIZE =", ZUC_KEY_SIZE)
print("ZUC_IV_SIZE =", ZUC_IV_SIZE)
print("")

key = rand_bytes(ZUC_KEY_SIZE)
iv = rand_bytes(ZUC_IV_SIZE)
plaintext = b'abc'

zuc_enc = Zuc(key, iv)
ciphertext = zuc_enc.update(plaintext)
ciphertext += zuc_enc.finish()

zuc_dec = Zuc(key, iv)
decrypted = zuc_dec.update(ciphertext)
decrypted += zuc_dec.finish()

print("key =", key.hex())
print("iv =", iv.hex())
print("plaintext =", plaintext.hex())
print("ciphertext = ", ciphertext.hex())
print("decrypted =", decrypted.hex())

