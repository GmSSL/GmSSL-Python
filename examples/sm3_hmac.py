# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

print("SM3_HMAC_MIN_KEY_SIZE =", SM3_HMAC_MIN_KEY_SIZE)
print("SM3_HMAC_MAX_KEY_SIZE =", SM3_HMAC_MAX_KEY_SIZE)
print("SM3_HMAC_SIZE =", SM3_HMAC_SIZE)

key = rand_bytes(SM3_HMAC_MIN_KEY_SIZE)

sm3_hmac = Sm3Hmac(key)
sm3_hmac.update(b'abc')
mac = sm3_hmac.generate_mac()
print("key = " + key.hex())
print("sm3_hmac('abc') : " + mac.hex())

sm3_hmac.reset(key)
for i in range(16):
	sm3_hmac.update(b'abcd')
mac = sm3_hmac.generate_mac()
print("sm3_hmac('abcd'*16) : " + mac.hex())

