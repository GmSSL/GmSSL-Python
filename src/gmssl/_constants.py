# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Constants definitions

"""
Internal module for all GmSSL constants.
This module should not be imported directly by users.
"""

# =============================================================================
# SM3 Hash Constants
# =============================================================================

SM3_DIGEST_SIZE = 32
SM3_HMAC_MIN_KEY_SIZE = 16
SM3_HMAC_MAX_KEY_SIZE = 64
SM3_HMAC_SIZE = SM3_DIGEST_SIZE
SM3_PBKDF2_MIN_ITER = 10000  # from <gmssl/pbkdf2.h>
SM3_PBKDF2_MAX_ITER = 16777216  # 2^24
SM3_PBKDF2_MAX_SALT_SIZE = 64  # from <gmssl/pbkdf2.h>
SM3_PBKDF2_DEFAULT_SALT_SIZE = 8  # from <gmssl/pbkdf2.h>
SM3_PBKDF2_MAX_KEY_SIZE = 256  # from gmssljni.c:sm3_pbkdf2():sizeof(keybuf)

# =============================================================================
# SM4 Block Cipher Constants
# =============================================================================

SM4_KEY_SIZE = 16
SM4_BLOCK_SIZE = 16
SM4_CBC_IV_SIZE = SM4_BLOCK_SIZE
SM4_CTR_IV_SIZE = 16
SM4_GCM_MIN_IV_SIZE = 1
SM4_GCM_MAX_IV_SIZE = 64
SM4_GCM_DEFAULT_IV_SIZE = 12
SM4_GCM_DEFAULT_TAG_SIZE = 16
SM4_GCM_MAX_TAG_SIZE = 16

# =============================================================================
# ZUC Stream Cipher Constants
# =============================================================================

ZUC_KEY_SIZE = 16
ZUC_IV_SIZE = 16
ZUC_BLOCK_SIZE = 4  # ZUC is a stream cipher with 4-byte (32-bit) blocks

# =============================================================================
# SM2 Public Key Cryptography Constants
# =============================================================================

SM2_DEFAULT_ID = "1234567812345678"
SM2_MAX_SIGNATURE_SIZE = 72
SM2_MIN_PLAINTEXT_SIZE = 1
SM2_MAX_PLAINTEXT_SIZE = 255
SM2_MIN_CIPHERTEXT_SIZE = 45
SM2_MAX_CIPHERTEXT_SIZE = 366

# =============================================================================
# Encryption/Decryption and Sign/Verify Mode Constants
# =============================================================================

DO_ENCRYPT = True
DO_DECRYPT = False
DO_SIGN = True
DO_VERIFY = False

# =============================================================================
# SM9 Identity-Based Cryptography Constants
# =============================================================================

SM9_MAX_ID_SIZE = 63
SM9_MAX_PLAINTEXT_SIZE = 255
SM9_MAX_CIPHERTEXT_SIZE = 367
SM9_SIGNATURE_SIZE = 104

# =============================================================================
# Internal Constants (not exported in __init__.py)
# =============================================================================

_SM3_STATE_WORDS = 8
_SM3_BLOCK_SIZE = 64
_SM4_NUM_ROUNDS = 32
_ASN1_TAG_IA5String = 22
_ASN1_TAG_SEQUENCE = 0x30
_ASN1_TAG_SET = 0x31
