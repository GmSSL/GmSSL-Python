# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *


print("SM9_MAX_ID_SIZE =", SM9_MAX_ID_SIZE)
print("SM9_MAX_PLAINTEXT_SIZE =", SM9_MAX_PLAINTEXT_SIZE)
print("SM9_MAX_CIPHERTEXT_SIZE =", SM9_MAX_CIPHERTEXT_SIZE)
print("")

master_key = Sm9EncMasterKey()
master_key.generate_master_key()
print("SM9 master key generated")

master_key.export_encrypted_master_key_info_pem('enc_msk.pem', 'password')
master_key.export_public_master_key_pem('enc_mpk.pem')
print("Export master key and public master key")

# Encrypt
master_pub = Sm9EncMasterKey()
master_pub.import_public_master_key_pem('enc_mpk.pem')

plaintext = rand_bytes(SM4_KEY_SIZE + SM3_HMAC_MIN_KEY_SIZE)

receiver_id = 'Alice'

ciphertext = master_pub.encrypt(plaintext, receiver_id)

# Decrypt
master = Sm9EncMasterKey()
master.import_encrypted_master_key_info_pem('enc_msk.pem', 'password')

receiver_key = master.extract_key(receiver_id)

decrypted = receiver_key.decrypt(ciphertext)

print("receiver :", receiver_id)
print("plaintext :", plaintext.hex())
print("ciphertext:", ciphertext.hex())
print("decrypted :", decrypted.hex())

