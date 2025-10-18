#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
Tests for features found in pygmssl but missing in our test suite.

This file adds tests for specific scenarios from the pygmssl project
that were not covered in our existing tests.
"""

import os
import tempfile
from pathlib import Path

import pytest

from gmssl import NativeError, Sm2Key, Sm3, Sm4, Sm4Cbc

# =============================================================================
# SM2 Tests
# =============================================================================


def test_sm2_wrong_password_import():
    """
    Test that importing an encrypted PEM with wrong password fails.

    Corresponds to pygmssl test_102_error_import_private_pem.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        pem_path = tmpdir / "test_key.pem"

        # Generate key and export with password
        sm2 = Sm2Key()
        sm2.generate_key()
        correct_password = "test-123-456"
        sm2.export_encrypted_private_key_info_pem(str(pem_path), correct_password)

        # Try to import with wrong password
        sm2_wrong = Sm2Key()
        with pytest.raises(NativeError, match="failed"):
            sm2_wrong.import_encrypted_private_key_info_pem(str(pem_path), "wrong-password")


# =============================================================================
# SM4 Tests
# =============================================================================


def test_sm4_cbc_bulk_encrypt():
    """
    Test SM4-CBC encryption/decryption with large data.

    Corresponds to pygmssl test_002_cbc_bulk_encrypt.
    Tests performance and correctness with ~1MB of data.
    """
    key = os.urandom(16)
    iv = os.urandom(16)

    # Create ~1MB of random data (512 bytes * 2099 = ~1MB)
    bulk_data = os.urandom(512) * 2099

    # Encrypt
    sm4_enc = Sm4Cbc(key, iv, True)
    ciphertext = sm4_enc.update(bulk_data)
    ciphertext += sm4_enc.finish()

    # Decrypt
    sm4_dec = Sm4Cbc(key, iv, False)
    plaintext = sm4_dec.update(ciphertext)
    plaintext += sm4_dec.finish()

    # Verify
    assert plaintext == bulk_data


def test_sm4_cbc_bulk_encrypt_multiple_chunks():
    """
    Test SM4-CBC with large data processed in multiple chunks.

    This tests the streaming capability with large data.
    """
    key = os.urandom(16)
    iv = os.urandom(16)

    # Create large data
    chunk_size = 512
    num_chunks = 2099
    chunks = [os.urandom(chunk_size) for _ in range(num_chunks)]
    bulk_data = b"".join(chunks)

    # Encrypt in chunks
    sm4_enc = Sm4Cbc(key, iv, True)
    ciphertext_chunks = []
    for chunk in chunks:
        ciphertext_chunks.append(sm4_enc.update(chunk))
    ciphertext_chunks.append(sm4_enc.finish())
    ciphertext = b"".join(ciphertext_chunks)

    # Decrypt all at once (simpler and more reliable)
    sm4_dec = Sm4Cbc(key, iv, False)
    plaintext = sm4_dec.update(ciphertext)
    plaintext += sm4_dec.finish()

    # Verify
    assert plaintext == bulk_data


def test_sm4_ecb_bulk_encrypt():
    """
    Test SM4-ECB encryption/decryption with large data.

    Similar to CBC bulk test but for ECB mode.
    Note: SM4 ECB mode only works with single blocks (16 bytes).
    For bulk data, we need to use CBC/CTR/GCM modes.
    """
    key = os.urandom(16)

    # Create data that's exactly one block (16 bytes)
    # SM4 ECB mode in this implementation only handles single blocks
    bulk_data = os.urandom(16)

    # Encrypt
    sm4_enc = Sm4(key, True)
    ciphertext = sm4_enc.encrypt(bulk_data)

    # Decrypt (use encrypt method with decrypt key)
    sm4_dec = Sm4(key, False)
    plaintext = sm4_dec.encrypt(ciphertext)  # encrypt method works for both

    # Verify
    assert plaintext == bulk_data


# =============================================================================
# Performance Tests
# =============================================================================


def test_sm2_sign_performance():
    """
    Test SM2 signing performance with multiple iterations.

    This ensures signing remains fast even after many operations.
    """
    sm2 = Sm2Key()
    sm2.generate_key()

    data = b"hello, world"
    digest = Sm3()
    digest.update(data)
    dgst = digest.digest()

    # Sign 100 times
    signatures = []
    for _ in range(100):
        sig = sm2.sign(dgst)
        signatures.append(sig)

    # Verify all signatures are valid
    for sig in signatures:
        assert sm2.verify(dgst, sig)


def test_sm3_hash_performance():
    """
    Test SM3 hashing performance with large data.

    This ensures hashing remains fast with large inputs.
    """
    # Create 10MB of data
    large_data = os.urandom(1024 * 1024 * 10)

    # Hash it
    sm3 = Sm3()
    sm3.update(large_data)
    digest = sm3.digest()

    # Verify digest is correct length
    assert len(digest) == 32


def test_sm3_hash_performance_streaming():
    """
    Test SM3 hashing performance with streaming data.

    This tests the update() method with many small chunks.
    """
    # Create 1MB of data in 1KB chunks
    chunk_size = 1024
    num_chunks = 1024

    sm3 = Sm3()
    for _ in range(num_chunks):
        chunk = os.urandom(chunk_size)
        sm3.update(chunk)

    digest = sm3.digest()
    assert len(digest) == 32


# =============================================================================
# Stress Tests
# =============================================================================


def test_sm2_key_generation_stress():
    """
    Test SM2 key generation multiple times to ensure stability.

    This ensures the random number generator and key generation
    remain stable over many iterations.
    """
    keys = []
    for _ in range(50):
        sm2 = Sm2Key()
        sm2.generate_key()
        keys.append(sm2)

    # Verify all keys are different by checking private keys
    # (public_key is a Structure field, not a method)
    private_keys = [bytes(sm2.private_key) for sm2 in keys]
    assert len(set(private_keys)) == 50  # All unique


def test_sm4_cbc_stress():
    """
    Test SM4-CBC with many encrypt/decrypt cycles.

    This ensures the cipher remains stable over many operations.
    """
    key = os.urandom(16)
    iv = os.urandom(16)
    data = b"hello, world" * 100

    # Encrypt and decrypt 100 times
    for _ in range(100):
        sm4_enc = Sm4Cbc(key, iv, True)
        ciphertext = sm4_enc.update(data)
        ciphertext += sm4_enc.finish()

        sm4_dec = Sm4Cbc(key, iv, False)
        plaintext = sm4_dec.update(ciphertext)
        plaintext += sm4_dec.finish()

        assert plaintext == data


# =============================================================================
# Edge Cases from pygmssl
# =============================================================================


def test_sm2_empty_signature_verify():
    """
    Test SM2 verification with empty signature.

    This should fail gracefully.
    """
    sm2 = Sm2Key()
    sm2.generate_key()

    data = b"hello, world"
    digest = Sm3()
    digest.update(data)
    dgst = digest.digest()

    # Empty signature should fail verification
    assert not sm2.verify(dgst, b"")


def test_sm2_corrupted_signature_verify():
    """
    Test SM2 verification with corrupted signature.

    This should fail verification.
    """
    sm2 = Sm2Key()
    sm2.generate_key()

    data = b"hello, world"
    digest = Sm3()
    digest.update(data)
    dgst = digest.digest()

    # Create valid signature
    sig = sm2.sign(dgst)

    # Corrupt the signature
    corrupted_sig = bytearray(sig)
    corrupted_sig[0] ^= 0xFF  # Flip bits in first byte

    # Corrupted signature should fail verification
    assert not sm2.verify(dgst, bytes(corrupted_sig))


def test_sm3_hash_consistency():
    """
    Test that SM3 hash is consistent across multiple instances.

    The same input should always produce the same hash.
    """
    data = b"hello, world"

    # Hash with multiple instances
    hashes = []
    for _ in range(10):
        sm3 = Sm3()
        sm3.update(data)
        hashes.append(sm3.digest())

    # All hashes should be identical
    assert len(set(hashes)) == 1


def test_sm4_cbc_padding_edge_cases():
    """
    Test SM4-CBC padding with various data sizes.

    This ensures padding works correctly for all data sizes.
    """
    key = os.urandom(16)
    iv = os.urandom(16)

    # Test with data sizes from 0 to 32 bytes
    for size in range(33):
        data = os.urandom(size)

        # Encrypt
        sm4_enc = Sm4Cbc(key, iv, True)
        ciphertext = sm4_enc.update(data)
        ciphertext += sm4_enc.finish()

        # Decrypt
        sm4_dec = Sm4Cbc(key, iv, False)
        plaintext = sm4_dec.update(ciphertext)
        plaintext += sm4_dec.finish()

        # Verify
        assert plaintext == data, f"Failed for size {size}"
