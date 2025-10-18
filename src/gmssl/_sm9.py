# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - SM9 identity-based cryptography

"""
Internal module for SM9 identity-based cryptography.
This module should not be imported directly by users.
"""

from ctypes import (
    Structure,
    byref,
    c_char_p,
    c_size_t,
    c_uint64,
    create_string_buffer,
)

from gmssl._constants import (
    DO_SIGN,
    DO_VERIFY,
    SM9_MAX_CIPHERTEXT_SIZE,
    SM9_MAX_PLAINTEXT_SIZE,
    SM9_SIGNATURE_SIZE,
)
from gmssl._lib import NativeError, StateError, gmssl

# Import cross-platform PEM wrappers
from gmssl._pem_utils import (
    pem_export_encrypted_key,
    pem_export_public_key,
    pem_import_encrypted_key,
    pem_import_public_key,
)
from gmssl._sm3 import Sm3

# =============================================================================
# SM9 Base Types
# =============================================================================


class sm9_bn_t(Structure):
    _fields_ = [("d", c_uint64 * 8)]


class sm9_fp2_t(Structure):
    _fields_ = [("d", sm9_bn_t * 2)]


class Sm9Point(Structure):
    _fields_ = [("X", sm9_bn_t), ("Y", sm9_bn_t), ("Z", sm9_bn_t)]


class Sm9TwistPoint(Structure):
    _fields_ = [("X", sm9_fp2_t), ("Y", sm9_fp2_t), ("Z", sm9_fp2_t)]


# =============================================================================
# SM9 Encryption - User Key
# =============================================================================


class Sm9EncKey(Structure):
    _fields_ = [("Ppube", Sm9Point), ("de", Sm9TwistPoint)]

    def __init__(self, owner_id):
        self._id = owner_id.encode("utf-8")
        self._has_private_key = False

    def get_id(self):
        return self._id

    def has_private_key(self):
        return self._has_private_key

    def import_encrypted_private_key_info_pem(self, path, passwd):
        passwd = passwd.encode("utf-8")
        pem_import_encrypted_key(self, path, passwd, "sm9_enc_key_info_decrypt_from_pem")
        self._has_private_key = True

    def export_encrypted_private_key_info_pem(self, path, passwd):
        if not self._has_private_key:
            raise TypeError("has no private key")
        passwd = passwd.encode("utf-8")
        pem_export_encrypted_key(self, path, passwd, "sm9_enc_key_info_encrypt_to_pem")

    def import_enc_master_public_key_pem(self, path):
        pem_import_public_key(self, path, "sm9_enc_master_public_key_from_pem")

    def encrypt(self, plaintext):
        if len(plaintext) > SM9_MAX_PLAINTEXT_SIZE:
            raise ValueError("Invalid plaintext length")
        outbuf = create_string_buffer(SM9_MAX_CIPHERTEXT_SIZE)
        outlen = c_size_t()
        if (
            gmssl.sm9_encrypt(
                byref(self),
                c_char_p(self._id),
                c_size_t(len(self._id)),
                plaintext,
                c_size_t(len(plaintext)),
                outbuf,
                byref(outlen),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]

    def decrypt(self, ciphertext):
        if not self._has_private_key:
            raise TypeError("has no private key")
        outbuf = create_string_buffer(SM9_MAX_PLAINTEXT_SIZE)
        outlen = c_size_t()
        if (
            gmssl.sm9_decrypt(
                byref(self),
                c_char_p(self._id),
                c_size_t(len(self._id)),
                ciphertext,
                c_size_t(len(ciphertext)),
                outbuf,
                byref(outlen),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]


# =============================================================================
# SM9 Encryption - Master Key
# =============================================================================


class Sm9EncMasterKey(Structure):
    _fields_ = [("Ppube", Sm9Point), ("ke", sm9_bn_t)]

    def __init__(self):
        self._has_public_key = False
        self._has_private_key = False

    def generate_master_key(self):
        if gmssl.sm9_enc_master_key_generate(byref(self)) != 1:
            raise NativeError("libgmssl inner error")
        self._has_public_key = True
        self._has_private_key = True

    def extract_key(self, identity):
        if not self._has_private_key:
            raise TypeError("has no master key")
        key = Sm9EncKey(identity)
        identity = identity.encode("utf-8")
        if (
            gmssl.sm9_enc_master_key_extract_key(
                byref(self), c_char_p(identity), c_size_t(len(identity)), byref(key)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        key._has_private_key = True
        return key

    def import_encrypted_master_key_info_pem(self, path, passwd):
        passwd = passwd.encode("utf-8")
        pem_import_encrypted_key(self, path, passwd, "sm9_enc_master_key_info_decrypt_from_pem")
        self._has_public_key = True
        self._has_private_key = True

    def export_encrypted_master_key_info_pem(self, path, passwd):
        if not self._has_private_key:
            raise TypeError("has no master key")
        passwd = passwd.encode("utf-8")
        pem_export_encrypted_key(self, path, passwd, "sm9_enc_master_key_info_encrypt_to_pem")

    def export_public_master_key_pem(self, path):
        if not self._has_public_key:
            raise TypeError("has no public master key")
        pem_export_public_key(self, path, "sm9_enc_master_public_key_to_pem")

    def import_public_master_key_pem(self, path):
        pem_import_public_key(self, path, "sm9_enc_master_public_key_from_pem")
        self._has_public_key = True
        self._has_private_key = False

    def encrypt(self, plaintext, to):
        if not self._has_public_key:
            raise TypeError("has no public master key")
        if len(plaintext) > SM9_MAX_PLAINTEXT_SIZE:
            raise ValueError("Invalid plaintext length")
        to = to.encode("utf-8")
        outbuf = create_string_buffer(SM9_MAX_CIPHERTEXT_SIZE)
        outlen = c_size_t()
        if (
            gmssl.sm9_encrypt(
                byref(self),
                c_char_p(to),
                c_size_t(len(to)),
                plaintext,
                c_size_t(len(plaintext)),
                outbuf,
                byref(outlen),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        return outbuf[: outlen.value]


# =============================================================================
# SM9 Signature - User Key
# =============================================================================


class Sm9SignKey(Structure):
    _fields_ = [("Ppubs", Sm9TwistPoint), ("ds", Sm9Point)]

    def __init__(self, owner_id):
        self._id = owner_id.encode("utf-8")
        self._has_public_key = False
        self._has_private_key = False

    def get_id(self):
        return self._id

    def has_private_key(self):
        return self._has_private_key

    def has_public_key(self):
        return self._has_public_key

    def import_encrypted_private_key_info_pem(self, path, passwd):
        passwd = passwd.encode("utf-8")
        pem_import_encrypted_key(self, path, passwd, "sm9_sign_key_info_decrypt_from_pem")
        self._has_public_key = True
        self._has_private_key = True

    def export_encrypted_private_key_info_pem(self, path, passwd):
        if not self._has_private_key:
            raise TypeError("has no private key")
        passwd = passwd.encode("utf-8")
        pem_export_encrypted_key(self, path, passwd, "sm9_sign_key_info_encrypt_to_pem")

    def import_sign_master_public_key_pem(self, path):
        pem_import_public_key(self, path, "sm9_sign_master_public_key_from_pem")
        self._has_public_key = True
        self._has_private_key = False


# =============================================================================
# SM9 Signature - Master Key
# =============================================================================


class Sm9SignMasterKey(Structure):
    _fields_ = [("Ppubs", Sm9TwistPoint), ("ks", sm9_bn_t)]

    def __init__(self):
        self._has_public_key = False
        self._has_private_key = False

    def generate_master_key(self):
        if gmssl.sm9_sign_master_key_generate(byref(self)) != 1:
            raise NativeError("libgmssl inner error")
        self._has_public_key = True
        self._has_private_key = True

    def extract_key(self, identity):
        if not self._has_private_key:
            raise TypeError("has no master key")
        key = Sm9SignKey(identity)
        identity = identity.encode("utf-8")
        if (
            gmssl.sm9_sign_master_key_extract_key(
                byref(self), c_char_p(identity), c_size_t(len(identity)), byref(key)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        key._has_public_key = True
        key._has_private_key = True
        return key

    def import_encrypted_master_key_info_pem(self, path, passwd):
        passwd = passwd.encode("utf-8")
        pem_import_encrypted_key(self, path, passwd, "sm9_sign_master_key_info_decrypt_from_pem")
        self._has_public_key = True
        self._has_private_key = True

    def export_encrypted_master_key_info_pem(self, path, passwd):
        if not self._has_private_key:
            raise TypeError("has no master key")
        passwd = passwd.encode("utf-8")
        pem_export_encrypted_key(self, path, passwd, "sm9_sign_master_key_info_encrypt_to_pem")

    def export_public_master_key_pem(self, path):
        if not self._has_public_key:
            raise TypeError("has no public master key")
        pem_export_public_key(self, path, "sm9_sign_master_public_key_to_pem")

    def import_public_master_key_pem(self, path):
        pem_import_public_key(self, path, "sm9_sign_master_public_key_from_pem")
        self._has_public_key = True
        self._has_private_key = False


# =============================================================================
# SM9 Signature Context
# =============================================================================


class Sm9Signature(Structure):
    _fields_ = [("sm3", Sm3)]

    def __init__(self, sign=DO_SIGN):
        if sign == DO_SIGN:
            if gmssl.sm9_sign_init(byref(self)) != 1:
                raise NativeError("libgmssl inner error")
        else:
            if gmssl.sm9_verify_init(byref(self)) != 1:
                raise NativeError("libgmssl inner error")
        self._sign = sign

    def update(self, data):
        if self._sign == DO_SIGN:
            if gmssl.sm9_sign_update(byref(self), data, c_size_t(len(data))) != 1:
                raise NativeError("libgmssl inner error")
        else:
            if gmssl.sm9_verify_update(byref(self), data, c_size_t(len(data))) != 1:
                raise NativeError("libgmssl inner error")

    def sign(self, sign_key):
        if self._sign != DO_SIGN:
            raise StateError("not sign state")
        if not sign_key.has_private_key():
            raise TypeError("has no private key")
        sig = create_string_buffer(SM9_SIGNATURE_SIZE)
        siglen = c_size_t(SM9_SIGNATURE_SIZE)
        if gmssl.sm9_sign_finish(byref(self), byref(sign_key), sig, byref(siglen)) != 1:
            raise NativeError("libgmssl inner error")
        return sig[: siglen.value]

    def verify(self, signature, public_master_key, signer_id):
        if self._sign != DO_VERIFY:
            raise StateError("not verify state")
        signer_id = signer_id.encode("utf-8")
        return (
            gmssl.sm9_verify_finish(
                byref(self),
                signature,
                c_size_t(len(signature)),
                byref(public_master_key),
                c_char_p(signer_id),
                c_size_t(len(signer_id)),
            )
            == 1
        )
