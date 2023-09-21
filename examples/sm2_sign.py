# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

# run sm2_key.py first


# Signer

private_key = Sm2Key()
private_key.import_encrypted_private_key_info_pem('sm2.pem', 'password')

z = private_key.compute_z(SM2_DEFAULT_ID)

sm3 = Sm3()
sm3.update(z)
sm3.update(b'abc')
dgst = sm3.digest()

sig = private_key.sign(dgst)
print("signature1 :", sig.hex())

signer = Sm2Signature(private_key, SM2_DEFAULT_ID, DO_SIGN)
signer.update(b'abc')
sig2 = signer.sign()
print("signature2 :", sig2.hex())

# Verifier

public_key = Sm2Key()
public_key.import_public_key_info_pem('sm2pub.pem')

z = public_key.compute_z(SM2_DEFAULT_ID)

sm3 = Sm3()
sm3.update(z)
sm3.update(b'abc')
dgst = sm3.digest()

ret = public_key.verify(dgst, sig)
print("Verify signature1 success :", ret)

ret = public_key.verify(dgst, sig2)
print("Verify signature2 success :", ret)

verifier = Sm2Signature(public_key, SM2_DEFAULT_ID, DO_VERIFY)
verifier.update(b'abc')
ret = verifier.verify(sig)
print("Verify signature1 success :", ret)

verifier = Sm2Signature(public_key, SM2_DEFAULT_ID, DO_VERIFY)
verifier.update(b'abc')
ret = verifier.verify(sig2)
print("Verify signature2 success :", ret)


