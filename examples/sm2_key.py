# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

sm2 = Sm2Key()
sm2.generate_key()

sm2.export_encrypted_private_key_info_pem('sm2.pem', 'password')
print('export private key to encrypted file sm2.pem')

sm2.export_public_key_info_pem('sm2pub.pem')
print('export public key to file sm2pub.pem')

private_key = Sm2Key()
private_key.import_encrypted_private_key_info_pem('sm2.pem', 'password')
print("private key has private key :", private_key.has_private_key())
print("private key has public key :", private_key.has_public_key())

public_key = Sm2Key()
public_key.import_public_key_info_pem('sm2pub.pem')
print("public key has private key :", public_key.has_private_key())
print("public key has public key :", public_key.has_public_key())

