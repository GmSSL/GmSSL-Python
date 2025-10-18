#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
Edge case and boundary condition tests for GmSSL Python binding.

Tests boundary values, empty data, maximum sizes, and other edge cases
to ensure robust handling of unusual inputs.
"""

from gmssl import (
    DO_DECRYPT,
    DO_ENCRYPT,
    DO_SIGN,
    DO_VERIFY,
    SM2_DEFAULT_ID,
    SM2_MAX_PLAINTEXT_SIZE,
    SM2_MIN_PLAINTEXT_SIZE,
    SM3_HMAC_MAX_KEY_SIZE,
    SM3_HMAC_MIN_KEY_SIZE,
    SM3_PBKDF2_MAX_KEY_SIZE,
    SM3_PBKDF2_MAX_SALT_SIZE,
    SM3_PBKDF2_MIN_ITER,
    SM4_GCM_MAX_IV_SIZE,
    SM4_GCM_MAX_TAG_SIZE,
    SM4_GCM_MIN_IV_SIZE,
    SM9_MAX_PLAINTEXT_SIZE,
    Sm2Key,
    Sm2Signature,
    Sm3,
    Sm3Hmac,
    Sm4,
    Sm4Cbc,
    Sm4Ctr,
    Sm4Gcm,
    Sm9EncMasterKey,
    Sm9Signature,
    Sm9SignMasterKey,
    Zuc,
    rand_bytes,
    sm3_pbkdf2,
)

# =============================================================================
# SM3 Edge Cases
# =============================================================================


def test_sm3_empty_data():
    """SM3 should handle empty data."""
    sm3 = Sm3()
    sm3.update(b"")
    dgst = sm3.digest()
    # SM3 of empty string has a known value
    assert len(dgst) == 32
    assert dgst.hex() == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"


def test_sm3_multiple_updates():
    """SM3 should handle multiple update calls."""
    sm3_single = Sm3()
    sm3_single.update(b"abcdefghijklmnopqrstuvwxyz")
    dgst_single = sm3_single.digest()

    sm3_multi = Sm3()
    sm3_multi.update(b"abc")
    sm3_multi.update(b"def")
    sm3_multi.update(b"ghi")
    sm3_multi.update(b"jklmnopqrstuvwxyz")
    dgst_multi = sm3_multi.digest()

    assert dgst_single == dgst_multi


def test_sm3_reset_multiple_times():
    """SM3 reset should work multiple times."""
    sm3 = Sm3()

    for _ in range(5):
        sm3.update(b"test")
        dgst = sm3.digest()
        assert len(dgst) == 32
        sm3.reset()


def test_sm3_hmac_min_key_size():
    """SM3-HMAC should accept minimum key size."""
    key = b"x" * SM3_HMAC_MIN_KEY_SIZE
    sm3_hmac = Sm3Hmac(key)
    sm3_hmac.update(b"test")
    mac = sm3_hmac.generate_mac()
    assert len(mac) == 32


def test_sm3_hmac_max_key_size():
    """SM3-HMAC should accept maximum key size."""
    key = b"x" * SM3_HMAC_MAX_KEY_SIZE
    sm3_hmac = Sm3Hmac(key)
    sm3_hmac.update(b"test")
    mac = sm3_hmac.generate_mac()
    assert len(mac) == 32


def test_sm3_hmac_reset():
    """SM3-HMAC reset should allow key change."""
    key1 = b"1234567812345678"
    key2 = b"8765432187654321"

    sm3_hmac = Sm3Hmac(key1)
    sm3_hmac.update(b"abc")
    mac1 = sm3_hmac.generate_mac()

    sm3_hmac.reset(key2)
    sm3_hmac.update(b"abc")
    mac2 = sm3_hmac.generate_mac()

    # Different keys should produce different MACs
    assert mac1 != mac2


def test_sm3_hmac_empty_data():
    """SM3-HMAC should handle empty data."""
    key = b"1234567812345678"
    sm3_hmac = Sm3Hmac(key)
    sm3_hmac.update(b"")
    mac = sm3_hmac.generate_mac()
    assert len(mac) == 32


def test_sm3_pbkdf2_min_iterator():
    """SM3-PBKDF2 should accept minimum iterator count."""
    key = sm3_pbkdf2("password", b"salt", SM3_PBKDF2_MIN_ITER, 32)
    assert len(key) == 32


def test_sm3_pbkdf2_max_salt_size():
    """SM3-PBKDF2 should accept maximum salt size."""
    salt = b"x" * SM3_PBKDF2_MAX_SALT_SIZE
    key = sm3_pbkdf2("password", salt, SM3_PBKDF2_MIN_ITER, 32)
    assert len(key) == 32


def test_sm3_pbkdf2_max_key_size():
    """SM3-PBKDF2 should accept maximum key size."""
    key = sm3_pbkdf2("password", b"salt", SM3_PBKDF2_MIN_ITER, SM3_PBKDF2_MAX_KEY_SIZE)
    assert len(key) == SM3_PBKDF2_MAX_KEY_SIZE


def test_sm3_pbkdf2_empty_password():
    """SM3-PBKDF2 should handle empty password."""
    key = sm3_pbkdf2("", b"salt", SM3_PBKDF2_MIN_ITER, 32)
    assert len(key) == 32


# =============================================================================
# SM4 Edge Cases
# =============================================================================


def test_sm4_decrypt_method():
    """SM4 decrypt method should provide clearer API for decryption."""
    key = b"1234567812345678"
    plaintext = b"block of message"

    # Encrypt
    sm4_enc = Sm4(key, DO_ENCRYPT)
    ciphertext = sm4_enc.encrypt(plaintext)

    # Decrypt using the decrypt method (clearer than using encrypt method)
    sm4_dec = Sm4(key, DO_DECRYPT)
    decrypted = sm4_dec.decrypt(ciphertext)

    assert decrypted == plaintext


def test_sm4_cbc_empty_data():
    """SM4-CBC should handle empty data."""
    key = b"1234567812345678"
    iv = b"1234567812345678"

    sm4_cbc = Sm4Cbc(key, iv, DO_ENCRYPT)
    ciphertext = sm4_cbc.update(b"")
    ciphertext += sm4_cbc.finish()

    # Empty plaintext should produce padding block
    assert len(ciphertext) == 16


def test_sm4_cbc_multiple_updates():
    """SM4-CBC should handle multiple update calls."""
    key = b"1234567812345678"
    iv = b"1234567812345678"
    plaintext = b"This is a longer message that will be split"

    # Single update
    sm4_single = Sm4Cbc(key, iv, DO_ENCRYPT)
    cipher_single = sm4_single.update(plaintext)
    cipher_single += sm4_single.finish()

    # Multiple updates
    sm4_multi = Sm4Cbc(key, iv, DO_ENCRYPT)
    cipher_multi = sm4_multi.update(plaintext[:10])
    cipher_multi += sm4_multi.update(plaintext[10:20])
    cipher_multi += sm4_multi.update(plaintext[20:])
    cipher_multi += sm4_multi.finish()

    assert cipher_single == cipher_multi


def test_sm4_ctr_empty_data():
    """SM4-CTR should handle empty data."""
    key = b"1234567812345678"
    iv = b"1234567812345678"

    sm4_ctr = Sm4Ctr(key, iv)
    ciphertext = sm4_ctr.update(b"")
    ciphertext += sm4_ctr.finish()

    assert len(ciphertext) == 0


def test_sm4_gcm_min_iv_size():
    """SM4-GCM should accept minimum IV size."""
    key = b"1234567812345678"
    iv = b"x" * SM4_GCM_MIN_IV_SIZE
    aad = b"aad"

    sm4_gcm = Sm4Gcm(key, iv, aad, 16, DO_ENCRYPT)
    ciphertext = sm4_gcm.update(b"plaintext")
    ciphertext += sm4_gcm.finish()

    assert len(ciphertext) > 0


def test_sm4_gcm_max_iv_size():
    """SM4-GCM should accept maximum IV size."""
    key = b"1234567812345678"
    iv = b"x" * SM4_GCM_MAX_IV_SIZE
    aad = b"aad"

    sm4_gcm = Sm4Gcm(key, iv, aad, 16, DO_ENCRYPT)
    ciphertext = sm4_gcm.update(b"plaintext")
    ciphertext += sm4_gcm.finish()

    assert len(ciphertext) > 0


def test_sm4_gcm_max_tag_size():
    """SM4-GCM should accept maximum tag size."""
    key = b"1234567812345678"
    iv = b"0123456789ab"
    aad = b"aad"

    sm4_gcm = Sm4Gcm(key, iv, aad, SM4_GCM_MAX_TAG_SIZE, DO_ENCRYPT)
    ciphertext = sm4_gcm.update(b"plaintext")
    ciphertext += sm4_gcm.finish()

    assert len(ciphertext) > 0


def test_sm4_gcm_empty_aad():
    """SM4-GCM should handle empty AAD."""
    key = b"1234567812345678"
    iv = b"0123456789ab"
    aad = b""

    sm4_gcm = Sm4Gcm(key, iv, aad, 16, DO_ENCRYPT)
    ciphertext = sm4_gcm.update(b"plaintext")
    ciphertext += sm4_gcm.finish()

    sm4_gcm_dec = Sm4Gcm(key, iv, aad, 16, DO_DECRYPT)
    decrypted = sm4_gcm_dec.update(ciphertext)
    decrypted += sm4_gcm_dec.finish()

    assert decrypted == b"plaintext"


# =============================================================================
# ZUC Edge Cases
# =============================================================================


def test_zuc_empty_data():
    """ZUC should handle empty data."""
    key = b"1234567812345678"
    iv = b"1234567812345678"

    zuc = Zuc(key, iv)
    ciphertext = zuc.update(b"")
    ciphertext += zuc.finish()

    assert len(ciphertext) == 0


def test_zuc_multiple_updates():
    """ZUC should handle multiple update calls."""
    key = b"1234567812345678"
    iv = b"1234567812345678"
    plaintext = b"This is a test message"

    # Single update
    zuc_single = Zuc(key, iv)
    cipher_single = zuc_single.update(plaintext)
    cipher_single += zuc_single.finish()

    # Multiple updates
    zuc_multi = Zuc(key, iv)
    cipher_multi = zuc_multi.update(plaintext[:5])
    cipher_multi += zuc_multi.update(plaintext[5:10])
    cipher_multi += zuc_multi.update(plaintext[10:])
    cipher_multi += zuc_multi.finish()

    assert cipher_single == cipher_multi


# =============================================================================
# SM2 Edge Cases
# =============================================================================


def test_sm2_encrypt_min_plaintext():
    """SM2 should handle minimum plaintext size."""
    sm2 = Sm2Key()
    sm2.generate_key()

    plaintext = b"x" * SM2_MIN_PLAINTEXT_SIZE
    ciphertext = sm2.encrypt(plaintext)
    decrypted = sm2.decrypt(ciphertext)

    assert decrypted == plaintext


def test_sm2_encrypt_max_plaintext():
    """SM2 should handle maximum plaintext size."""
    sm2 = Sm2Key()
    sm2.generate_key()

    plaintext = b"x" * SM2_MAX_PLAINTEXT_SIZE
    ciphertext = sm2.encrypt(plaintext)
    decrypted = sm2.decrypt(ciphertext)

    assert decrypted == plaintext


def test_sm2_signature_multiple_updates():
    """SM2 Signature should handle multiple update calls."""
    sm2 = Sm2Key()
    sm2.generate_key()

    message = b"This is a long message to be signed"

    # Single update
    sign_single = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)
    sign_single.update(message)
    sig_single = sign_single.sign()

    # Multiple updates
    sign_multi = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)
    sign_multi.update(message[:10])
    sign_multi.update(message[10:20])
    sign_multi.update(message[20:])
    sig_multi = sign_multi.sign()

    # Both signatures should be valid
    verify = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
    verify.update(message)
    assert verify.verify(sig_single)

    verify2 = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
    verify2.update(message)
    assert verify2.verify(sig_multi)


def test_sm2_custom_id():
    """SM2 should work with custom signer ID."""
    sm2 = Sm2Key()
    sm2.generate_key()

    custom_id = "custom_user@example.com"

    # Compute Z with custom ID
    z = sm2.compute_z(custom_id)
    assert len(z) == 32

    # Sign and verify with custom ID
    sign = Sm2Signature(sm2, custom_id, DO_SIGN)
    sign.update(b"message")
    sig = sign.sign()

    verify = Sm2Signature(sm2, custom_id, DO_VERIFY)
    verify.update(b"message")
    assert verify.verify(sig)


# =============================================================================
# SM9 Edge Cases
# =============================================================================


def test_sm9_encrypt_max_plaintext():
    """SM9 should handle maximum plaintext size."""
    master_key = Sm9EncMasterKey()
    master_key.generate_master_key()

    plaintext = b"x" * SM9_MAX_PLAINTEXT_SIZE
    ciphertext = master_key.encrypt(plaintext, "Alice")

    key = master_key.extract_key("Alice")
    decrypted = key.decrypt(ciphertext)

    assert decrypted == plaintext


def test_sm9_sign_multiple_updates():
    """SM9 Signature should handle multiple update calls."""
    master_key = Sm9SignMasterKey()
    master_key.generate_master_key()

    key = master_key.extract_key("Alice")
    message = b"This is a long message to be signed"

    # Single update
    sign_single = Sm9Signature(DO_SIGN)
    sign_single.update(message)
    sig_single = sign_single.sign(key)

    # Multiple updates
    sign_multi = Sm9Signature(DO_SIGN)
    sign_multi.update(message[:10])
    sign_multi.update(message[10:20])
    sign_multi.update(message[20:])
    sig_multi = sign_multi.sign(key)

    # Both signatures should be valid
    verify = Sm9Signature(DO_VERIFY)
    verify.update(message)
    assert verify.verify(sig_single, master_key, "Alice")

    verify2 = Sm9Signature(DO_VERIFY)
    verify2.update(message)
    assert verify2.verify(sig_multi, master_key, "Alice")


# =============================================================================
# Random Number Edge Cases
# =============================================================================


def test_rand_bytes_various_sizes():
    """rand_bytes should work with various sizes."""
    for size in [1, 16, 32, 64, 128, 256, 1024]:
        data = rand_bytes(size)
        assert len(data) == size


def test_rand_bytes_uniqueness():
    """rand_bytes should generate unique values."""
    # Generate multiple random values and check they're different
    values = [rand_bytes(32) for _ in range(10)]
    # All values should be unique
    assert len(set(values)) == len(values)
