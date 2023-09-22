# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *


print("SM9_MAX_ID_SIZE =", SM9_MAX_ID_SIZE)
print("SM9_SIGNATURE_SIZE =", SM9_SIGNATURE_SIZE)
print("")


master_key = Sm9SignMasterKey()
master_key.generate_master_key()
print("SM9 master key generated")

master_key.export_encrypted_master_key_info_pem('sign_msk.pem', 'password')
master_key.export_public_master_key_pem('sign_mpk.pem')
print("Export master key and public master key")


master = Sm9SignMasterKey()
master.import_encrypted_master_key_info_pem('sign_msk.pem', 'password')

signer_id = 'Alice'
key = master.extract_key(signer_id)

message = "Message to be signed"

sign = Sm9Signature(DO_SIGN)
sign.update(message.encode('utf-8'))
sig = sign.sign(key)


master_pub = Sm9SignMasterKey()
master_pub.import_public_master_key_pem('sign_mpk.pem')

verify = Sm9Signature(DO_VERIFY)
verify.update(message.encode('utf-8'))
ret = verify.verify(sig, master_pub, signer_id)

print("signer :", signer_id)
print("message :", message)
print("signature :", sig.hex())
print("verify success :", ret)

