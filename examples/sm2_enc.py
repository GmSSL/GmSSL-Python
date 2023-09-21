# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

# run sm2_key.py first



# Sender

public_key = Sm2Key()
public_key.import_public_key_info_pem('sm2pub.pem')

plaintext = b'Plaintext message'
ciphertext = public_key.encrypt(plaintext)


# Receiver

private_key = Sm2Key()
private_key.import_encrypted_private_key_info_pem('sm2.pem', 'password')

decrypted = private_key.decrypt(ciphertext)

print("plaintext :", plaintext.hex())
print("ciphertext :", ciphertext.hex())
print("decrypted :", decrypted.hex())

