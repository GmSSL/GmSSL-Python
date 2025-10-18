#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
Error handling and exception tests for GmSSL Python binding.

Tests various error conditions and exception handling to ensure
robust error reporting and proper validation.
"""

import pytest

from gmssl import (
    DO_DECRYPT,
    DO_ENCRYPT,
    DO_SIGN,
    DO_VERIFY,
    SM2_DEFAULT_ID,
    SM2_MAX_PLAINTEXT_SIZE,
    Sm2Key,
    Sm2Signature,
    Sm3Hmac,
    Sm4,
    Sm4Cbc,
    Sm4Ctr,
    Sm4Gcm,
    StateError,
    Zuc,
    sm3_pbkdf2,
)

# =============================================================================
# SM3 Error Tests
# =============================================================================


def test_sm3_hmac_invalid_key_too_short():
    """SM3-HMAC should reject keys that are too short."""
    with pytest.raises(ValueError, match="Invalid SM3 HMAC key length"):
        Sm3Hmac(b"short")


def test_sm3_hmac_invalid_key_too_long():
    """SM3-HMAC should reject keys that are too long."""
    # SM3_HMAC_MAX_KEY_SIZE is 64
    with pytest.raises(ValueError, match="Invalid SM3 HMAC key length"):
        Sm3Hmac(b"x" * 65)


def test_sm3_pbkdf2_invalid_salt_too_long():
    """SM3-PBKDF2 should reject salt that is too long."""
    # SM3_PBKDF2_MAX_SALT_SIZE is 64
    with pytest.raises(ValueError, match="Invalid salt length"):
        sm3_pbkdf2("password", b"x" * 65, 10000, 32)


def test_sm3_pbkdf2_invalid_iterator_too_small():
    """SM3-PBKDF2 should reject iterator count that is too small."""
    # SM3_PBKDF2_MIN_ITER is 1
    with pytest.raises(ValueError, match="Invalid iterator value"):
        sm3_pbkdf2("password", b"salt", 0, 32)


def test_sm3_pbkdf2_invalid_iterator_too_large():
    """SM3-PBKDF2 should reject iterator count that is too large."""
    # SM3_PBKDF2_MAX_ITER is 16777216
    with pytest.raises(ValueError, match="Invalid iterator value"):
        sm3_pbkdf2("password", b"salt", 16777217, 32)


def test_sm3_pbkdf2_invalid_keylen_too_large():
    """SM3-PBKDF2 should reject key length that is too large."""
    # SM3_PBKDF2_MAX_KEY_SIZE is 256
    with pytest.raises(ValueError, match="Invalid key length"):
        sm3_pbkdf2("password", b"salt", 10000, 257)


# =============================================================================
# SM4 Error Tests
# =============================================================================


def test_sm4_invalid_key_length():
    """SM4 should reject invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
        Sm4(b"short_key", DO_ENCRYPT)


def test_sm4_invalid_block_size():
    """SM4 encrypt should reject invalid block size."""
    sm4 = Sm4(b"1234567812345678", DO_ENCRYPT)
    with pytest.raises(ValueError, match="Invalid block size"):
        sm4.encrypt(b"short")


def test_sm4_decrypt_on_encrypt_mode():
    """SM4 decrypt should fail when called on encryption mode instance."""
    sm4 = Sm4(b"1234567812345678", DO_ENCRYPT)
    with pytest.raises(ValueError, match="Cannot call decrypt\\(\\) on encryption mode instance"):
        sm4.decrypt(b"1234567812345678")


def test_sm4_decrypt_invalid_block_size():
    """SM4 decrypt should reject invalid block size."""
    sm4 = Sm4(b"1234567812345678", DO_DECRYPT)
    with pytest.raises(ValueError, match="Invalid block size"):
        sm4.decrypt(b"short")


def test_sm4_cbc_invalid_key_length():
    """SM4-CBC should reject invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
        Sm4Cbc(b"short", b"1234567812345678", DO_ENCRYPT)


def test_sm4_cbc_invalid_iv_size():
    """SM4-CBC should reject invalid IV size."""
    with pytest.raises(ValueError, match="Invalid IV size"):
        Sm4Cbc(b"1234567812345678", b"short", DO_ENCRYPT)


def test_sm4_ctr_invalid_key_length():
    """SM4-CTR should reject invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
        Sm4Ctr(b"short", b"1234567812345678")


def test_sm4_ctr_invalid_ctr_size():
    """SM4-CTR should reject invalid CTR size."""
    with pytest.raises(ValueError, match="Invalid CTR size"):
        Sm4Ctr(b"1234567812345678", b"short")


def test_sm4_gcm_invalid_key_length():
    """SM4-GCM should reject invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
        Sm4Gcm(b"short", b"0123456789ab", b"aad", 16, DO_ENCRYPT)


def test_sm4_gcm_invalid_iv_too_short():
    """SM4-GCM should reject IV that is too short."""
    # SM4_GCM_MIN_IV_SIZE is 1
    with pytest.raises(ValueError, match="Invalid IV size"):
        Sm4Gcm(b"1234567812345678", b"", b"aad", 16, DO_ENCRYPT)


def test_sm4_gcm_invalid_iv_too_long():
    """SM4-GCM should reject IV that is too long."""
    # SM4_GCM_MAX_IV_SIZE is 64
    with pytest.raises(ValueError, match="Invalid IV size"):
        Sm4Gcm(b"1234567812345678", b"x" * 65, b"aad", 16, DO_ENCRYPT)


def test_sm4_gcm_invalid_tag_length():
    """SM4-GCM should reject invalid tag length."""
    with pytest.raises(ValueError, match="Invalid Tag length"):
        Sm4Gcm(b"1234567812345678", b"0123456789ab", b"aad", 0, DO_ENCRYPT)


# =============================================================================
# ZUC Error Tests
# =============================================================================


def test_zuc_invalid_key_length():
    """ZUC should reject invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
        Zuc(b"short", b"1234567812345678")


def test_zuc_invalid_iv_size():
    """ZUC should reject invalid IV size."""
    with pytest.raises(ValueError, match="Invalid IV size"):
        Zuc(b"1234567812345678", b"short")


# =============================================================================
# SM2 Error Tests
# =============================================================================


def test_sm2_sign_without_private_key():
    """SM2 sign should fail without private key."""
    sm2 = Sm2Key()
    # Key not generated, no private key
    with pytest.raises(TypeError, match="has no private key"):
        sm2.sign(b"0" * 32)


def test_sm2_encrypt_without_public_key():
    """SM2 encrypt should fail without public key."""
    sm2 = Sm2Key()
    # Key not generated, no public key
    with pytest.raises(TypeError, match="has no public key"):
        sm2.encrypt(b"plaintext")


def test_sm2_verify_without_public_key():
    """SM2 verify should fail without public key."""
    sm2 = Sm2Key()
    # Key not generated, no public key
    with pytest.raises(TypeError, match="has no public key"):
        sm2.verify(b"0" * 32, b"signature")


def test_sm2_decrypt_without_private_key():
    """SM2 decrypt should fail without private key."""
    sm2 = Sm2Key()
    # Key not generated, no private key
    with pytest.raises(TypeError, match="has no private key"):
        sm2.decrypt(b"ciphertext")


def test_sm2_compute_z_without_public_key():
    """SM2 compute_z should fail without public key."""
    sm2 = Sm2Key()
    # Key not generated, no public key
    with pytest.raises(TypeError, match="has no public key"):
        sm2.compute_z(SM2_DEFAULT_ID)


def test_sm2_sign_invalid_digest_size():
    """SM2 sign should reject invalid digest size."""
    sm2 = Sm2Key()
    sm2.generate_key()
    with pytest.raises(ValueError, match="Invalid SM3 digest size"):
        sm2.sign(b"invalid_digest")


def test_sm2_verify_invalid_digest_size():
    """SM2 verify should reject invalid digest size."""
    sm2 = Sm2Key()
    sm2.generate_key()
    with pytest.raises(ValueError, match="Invalid SM3 digest size"):
        sm2.verify(b"invalid_digest", b"signature")


def test_sm2_encrypt_plaintext_too_long():
    """SM2 encrypt should reject plaintext that is too long."""
    sm2 = Sm2Key()
    sm2.generate_key()
    with pytest.raises(ValueError, match="Plaintext too long"):
        sm2.encrypt(b"x" * (SM2_MAX_PLAINTEXT_SIZE + 1))


def test_sm2_export_private_key_without_private_key():
    """SM2 export private key should fail without private key."""
    sm2 = Sm2Key()
    # Key not generated, no private key
    with pytest.raises(TypeError, match="has no private key"):
        sm2.export_encrypted_private_key_info_pem("/tmp/test.pem", "password")


def test_sm2_export_public_key_without_public_key():
    """SM2 export public key should fail without public key."""
    sm2 = Sm2Key()
    # Key not generated, no public key
    with pytest.raises(TypeError, match="has no public key"):
        sm2.export_public_key_info_pem("/tmp/test.pem")


# =============================================================================
# SM2 Signature State Error Tests
# =============================================================================


def test_sm2_signature_sign_in_verify_state():
    """SM2 Signature sign should fail in verify state."""
    sm2 = Sm2Key()
    sm2.generate_key()

    verify = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
    verify.update(b"message")

    with pytest.raises(StateError, match="not sign state"):
        verify.sign()


def test_sm2_signature_verify_in_sign_state():
    """SM2 Signature verify should fail in sign state."""
    sm2 = Sm2Key()
    sm2.generate_key()

    sign = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)
    sign.update(b"message")

    with pytest.raises(StateError, match="not verify state"):
        sign.verify(b"signature")


def test_sm2_signature_init_without_private_key():
    """SM2 Signature init for signing should fail without private key."""
    sm2 = Sm2Key()
    # Key not generated, no private key
    with pytest.raises(TypeError, match="SM2 key has no private key"):
        Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)


def test_sm2_signature_init_without_public_key():
    """SM2 Signature init for verifying should fail without public key."""
    sm2 = Sm2Key()
    # Key not generated, no public key
    with pytest.raises(TypeError, match="SM2 key has no public key"):
        Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
