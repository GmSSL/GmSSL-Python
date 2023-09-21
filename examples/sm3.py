# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

print("SM3_DIGEST_SIZE =", SM3_DIGEST_SIZE)

sm3 = Sm3()
sm3.update(b'abc')
dgst = sm3.digest()
print("sm3('abc') : " + dgst.hex())

sm3.reset()
for i in range(16):
	sm3.update(b'abcd')
dgst = sm3.digest()
print("sm3('abcd'*16) : " + dgst.hex())

