# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - SM2 public key cryptography and signature

"""
Internal module for SM2 elliptic curve cryptography.
This module should not be imported directly by users.
"""

from ctypes import Structure, byref, c_char_p, c_size_t, c_uint, c_uint8, create_string_buffer

from gmssl._constants import (
    DO_SIGN,
    DO_VERIFY,
    SM2_DEFAULT_ID,
    SM2_MAX_CIPHERTEXT_SIZE,
    SM2_MAX_PLAINTEXT_SIZE,
    SM2_MAX_SIGNATURE_SIZE,
    SM3_DIGEST_SIZE,
)
from gmssl._lib import StateError, checked, gmssl

# Import cross-platform PEM wrappers
from gmssl._pem_utils import (
    pem_export_encrypted_key,
    pem_export_public_key,
    pem_import_encrypted_key,
    pem_import_public_key,
)
from gmssl._sm3 import Sm3

# =============================================================================
# SM2 Public Key Cryptography
# =============================================================================


class Sm2Z256Point(Structure):
    """SM2_Z256_POINT structure using Jacobian coordinates (X, Y, Z)."""

    _fields_ = [
        ("X", c_uint8 * 32),  # sm2_z256_t
        ("Y", c_uint8 * 32),  # sm2_z256_t
        ("Z", c_uint8 * 32),  # sm2_z256_t
    ]


class Sm2Key(Structure):
    _fields_ = [("public_key", Sm2Z256Point), ("private_key", c_uint8 * 32)]

    def __init__(self):
        self._has_public_key = False
        self._has_private_key = False

    def generate_key(self):
        checked.sm2_key_generate(byref(self))
        self._has_public_key = True
        self._has_private_key = True

    def has_private_key(self):
        return self._has_private_key

    def has_public_key(self):
        return self._has_public_key

    def compute_z(self, signer_id=SM2_DEFAULT_ID):
        if not self._has_public_key:
            raise TypeError("has no public key")
        signer_id = signer_id.encode("utf-8")
        z = create_string_buffer(SM3_DIGEST_SIZE)
        gmssl.sm2_compute_z(z, byref(self), c_char_p(signer_id), c_size_t(len(signer_id)))
        return z.raw

    def export_encrypted_private_key_info_pem(self, path, passwd):
        if not self._has_private_key:
            raise TypeError("has no private key")
        passwd = passwd.encode("utf-8")
        pem_export_encrypted_key(self, path, passwd, "sm2_private_key_info_encrypt_to_pem")

    def import_encrypted_private_key_info_pem(self, path, passwd):
        passwd = passwd.encode("utf-8")
        pem_import_encrypted_key(self, path, passwd, "sm2_private_key_info_decrypt_from_pem")
        self._has_public_key = True
        self._has_private_key = True

    def export_public_key_info_pem(self, path):
        if not self._has_public_key:
            raise TypeError("has no public key")
        pem_export_public_key(self, path, "sm2_public_key_info_to_pem")

    def import_public_key_info_pem(self, path):
        pem_import_public_key(self, path, "sm2_public_key_info_from_pem")
        self._has_public_key = True
        self._has_private_key = False

    def sign(self, dgst):
        if not self._has_private_key:
            raise TypeError("has no private key")
        if len(dgst) != SM3_DIGEST_SIZE:
            raise ValueError("Invalid SM3 digest size")
        sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
        siglen = c_size_t()
        checked.sm2_sign(byref(self), dgst, sig, byref(siglen))
        return sig[: siglen.value]

    def verify(self, dgst, signature):
        if not self._has_public_key:
            raise TypeError("has no public key")
        if len(dgst) != SM3_DIGEST_SIZE:
            raise ValueError("Invalid SM3 digest size")
        return gmssl.sm2_verify(byref(self), dgst, signature, c_size_t(len(signature))) == 1

    def encrypt(self, data):
        if not self._has_public_key:
            raise TypeError("has no public key")
        if len(data) > SM2_MAX_PLAINTEXT_SIZE:
            raise ValueError("Plaintext too long")
        outbuf = create_string_buffer(SM2_MAX_CIPHERTEXT_SIZE)
        outlen = c_size_t()
        checked.sm2_encrypt(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen))
        return outbuf[: outlen.value]

    def decrypt(self, ciphertext):
        if not self._has_private_key:
            raise TypeError("has no private key")
        outbuf = create_string_buffer(SM2_MAX_PLAINTEXT_SIZE)
        outlen = c_size_t()
        checked.sm2_decrypt(
            byref(self),
            ciphertext,
            c_size_t(len(ciphertext)),
            outbuf,
            byref(outlen),
        )
        return outbuf[: outlen.value]


# =============================================================================
# SM2 Signature
# =============================================================================


class Sm2SignPreComp(Structure):
    _fields_ = [
        ("k", c_uint8 * 32),  # sm2_z256_t = uint64_t[4] = 32 bytes
        ("x1_modn", c_uint8 * 32),
    ]


class Sm2Signature(Structure):
    _fields_ = [
        ("sm3_ctx", Sm3),
        ("saved_sm3_ctx", Sm3),
        ("key", Sm2Key),
        ("fast_sign_private", c_uint8 * 32),  # sm2_z256_t
        ("pre_comp", Sm2SignPreComp * 32),  # SM2_SIGN_PRE_COMP_COUNT = 32
        ("num_pre_comp", c_uint),  # unsigned int
        ("public_point_table", Sm2Z256Point * 16),
    ]

    def __init__(self, sm2_key, signer_id=SM2_DEFAULT_ID, sign=DO_SIGN):
        signer_id = signer_id.encode("utf-8")
        if sign == DO_SIGN:
            if not sm2_key.has_private_key():
                raise TypeError("SM2 key has no private key")
            checked.sm2_sign_init(
                byref(self),
                byref(sm2_key),
                c_char_p(signer_id),
                c_size_t(len(signer_id)),
            )
        else:
            if not sm2_key.has_public_key():
                raise TypeError("SM2 key has no public key")
            checked.sm2_verify_init(
                byref(self),
                byref(sm2_key),
                c_char_p(signer_id),
                c_size_t(len(signer_id)),
            )
        self._sign = sign

    def update(self, data):
        if self._sign == DO_SIGN:
            checked.sm2_sign_update(byref(self), data, c_size_t(len(data)))
        else:
            checked.sm2_verify_update(byref(self), data, c_size_t(len(data)))

    def sign(self):
        if self._sign != DO_SIGN:
            raise StateError("not sign state")
        sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
        siglen = c_size_t()
        checked.sm2_sign_finish(byref(self), sig, byref(siglen))
        return sig[: siglen.value]

    def verify(self, signature):
        if self._sign != DO_VERIFY:
            raise StateError("not verify state")
        return gmssl.sm2_verify_finish(byref(self), signature, c_size_t(len(signature))) == 1
