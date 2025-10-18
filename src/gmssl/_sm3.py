# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - SM3 hash, HMAC, and PBKDF2

"""
Internal module for SM3 cryptographic hash functions.
This module should not be imported directly by users.
"""

from ctypes import (
    Structure,
    byref,
    c_char_p,
    c_size_t,
    c_uint8,
    c_uint32,
    c_uint64,
    create_string_buffer,
)

from gmssl._constants import (
    _SM3_BLOCK_SIZE,
    _SM3_STATE_WORDS,
    SM3_DIGEST_SIZE,
    SM3_HMAC_MAX_KEY_SIZE,
    SM3_HMAC_MIN_KEY_SIZE,
    SM3_HMAC_SIZE,
    SM3_PBKDF2_MAX_ITER,
    SM3_PBKDF2_MAX_KEY_SIZE,
    SM3_PBKDF2_MAX_SALT_SIZE,
    SM3_PBKDF2_MIN_ITER,
)
from gmssl._lib import checked, gmssl

# =============================================================================
# SM3 Hash
# =============================================================================


class Sm3(Structure):
    _fields_ = [
        ("dgst", c_uint32 * _SM3_STATE_WORDS),
        ("nblocks", c_uint64),
        ("block", c_uint8 * _SM3_BLOCK_SIZE),
        ("num", c_size_t),
    ]

    def __init__(self):
        gmssl.sm3_init(byref(self))

    def reset(self):
        gmssl.sm3_init(byref(self))

    def update(self, data):
        gmssl.sm3_update(byref(self), data, c_size_t(len(data)))

    def digest(self):
        dgst = create_string_buffer(SM3_DIGEST_SIZE)
        gmssl.sm3_finish(byref(self), dgst)
        return dgst.raw


# =============================================================================
# SM3 HMAC
# =============================================================================


class Sm3Hmac(Structure):
    _fields_ = [("sm3_ctx", Sm3), ("key", c_uint8 * _SM3_BLOCK_SIZE)]

    def __init__(self, key):
        if len(key) < SM3_HMAC_MIN_KEY_SIZE or len(key) > SM3_HMAC_MAX_KEY_SIZE:
            raise ValueError("Invalid SM3 HMAC key length")
        gmssl.sm3_hmac_init(byref(self), key, c_size_t(len(key)))

    def reset(self, key):
        if len(key) < SM3_HMAC_MIN_KEY_SIZE or len(key) > SM3_HMAC_MAX_KEY_SIZE:
            raise ValueError("Invalid SM3 HMAC key length")
        gmssl.sm3_hmac_init(byref(self), key, c_size_t(len(key)))

    def update(self, data):
        gmssl.sm3_hmac_update(byref(self), data, c_size_t(len(data)))

    def generate_mac(self):
        hmac = create_string_buffer(SM3_HMAC_SIZE)
        gmssl.sm3_hmac_finish(byref(self), hmac)
        return hmac.raw


# =============================================================================
# SM3 PBKDF2
# =============================================================================


def sm3_pbkdf2(passwd, salt, iterator, keylen):
    if len(salt) > SM3_PBKDF2_MAX_SALT_SIZE:
        raise ValueError("Invalid salt length")

    if iterator < SM3_PBKDF2_MIN_ITER or iterator > SM3_PBKDF2_MAX_ITER:
        raise ValueError("Invalid iterator value")

    if keylen > SM3_PBKDF2_MAX_KEY_SIZE:
        raise ValueError("Invalid key length")

    passwd = passwd.encode("utf-8")
    key = create_string_buffer(keylen)

    checked.sm3_pbkdf2(
        c_char_p(passwd),
        c_size_t(len(passwd)),
        salt,
        c_size_t(len(salt)),
        c_size_t(iterator),
        c_size_t(keylen),
        key,
    )

    return key.raw
