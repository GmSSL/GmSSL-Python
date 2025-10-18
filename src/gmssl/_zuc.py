# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - ZUC stream cipher

"""
Internal module for ZUC stream cipher.
This module should not be imported directly by users.
"""

from ctypes import Structure, byref, c_size_t, c_uint8, c_uint32, create_string_buffer

from gmssl._constants import ZUC_BLOCK_SIZE, ZUC_IV_SIZE, ZUC_KEY_SIZE
from gmssl._lib import checked

# =============================================================================
# ZUC Stream Cipher
# =============================================================================


class ZucState(Structure):
    _fields_ = [("LFSR", c_uint32 * 16), ("R1", c_uint32), ("R2", c_uint32)]


class Zuc(Structure):
    _fields_ = [
        ("zuc_state", ZucState),
        ("block", c_uint8 * 4),
        ("block_nbytes", c_size_t),
    ]

    def __init__(self, key, iv):
        if len(key) != ZUC_KEY_SIZE:
            raise ValueError("Invalid key length")
        if len(iv) != ZUC_IV_SIZE:
            raise ValueError("Invalid IV size")
        checked.zuc_encrypt_init(byref(self), key, iv)

    def update(self, data):
        outbuf = create_string_buffer(len(data) + ZUC_BLOCK_SIZE)
        outlen = c_size_t()
        checked.zuc_encrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen))
        return outbuf[0 : outlen.value]

    def finish(self):
        outbuf = create_string_buffer(ZUC_BLOCK_SIZE)
        outlen = c_size_t()
        checked.zuc_encrypt_finish(byref(self), outbuf, byref(outlen))
        return outbuf[: outlen.value]
