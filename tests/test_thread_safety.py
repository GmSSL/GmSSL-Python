#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
Thread safety tests for GmSSL Python binding.

Tests concurrent operations to ensure thread safety of cryptographic operations.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from gmssl import (
    Sm2Key,
    Sm3,
    Sm3Hmac,
    Sm4Cbc,
    Sm9EncMasterKey,
    Zuc,
    rand_bytes,
)

# =============================================================================
# Random Number Generation Thread Safety
# =============================================================================


def test_rand_bytes_thread_safety():
    """
    Test that rand_bytes is thread-safe.

    Multiple threads should be able to generate random bytes concurrently
    without conflicts or duplicate values.
    """
    num_threads = 10
    bytes_per_thread = 100

    def generate_random():
        return [rand_bytes(32) for _ in range(bytes_per_thread)]

    # Generate random bytes in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(generate_random) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # Flatten results
    all_random = [rb for thread_results in results for rb in thread_results]

    # Verify all values are unique (extremely high probability)
    assert len(set(all_random)) == len(all_random)


# =============================================================================
# SM3 Hash Thread Safety
# =============================================================================


def test_sm3_hash_thread_safety():
    """
    Test that SM3 hashing is thread-safe.

    Multiple threads should be able to hash data concurrently.
    """
    num_threads = 20
    data = b"hello, world"

    def hash_data():
        sm3 = Sm3()
        sm3.update(data)
        return sm3.digest()

    # Hash in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(hash_data) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All results should be identical
    assert len(set(results)) == 1


def test_sm3_hmac_thread_safety():
    """
    Test that SM3-HMAC is thread-safe.

    Multiple threads should be able to generate MACs concurrently.
    """
    num_threads = 20
    key = b"test_key_1234567"
    data = b"hello, world"

    def generate_mac():
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(data)
        return sm3_hmac.generate_mac()

    # Generate MACs in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(generate_mac) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All results should be identical
    assert len(set(results)) == 1


# =============================================================================
# SM4 Cipher Thread Safety
# =============================================================================


def test_sm4_cbc_thread_safety():
    """
    Test that SM4-CBC is thread-safe.

    Multiple threads should be able to encrypt/decrypt concurrently.
    """
    num_threads = 20
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"hello, world" * 10

    def encrypt_decrypt():
        # Encrypt
        sm4_enc = Sm4Cbc(key, iv, True)
        ciphertext = sm4_enc.update(plaintext)
        ciphertext += sm4_enc.finish()

        # Decrypt
        sm4_dec = Sm4Cbc(key, iv, False)
        decrypted = sm4_dec.update(ciphertext)
        decrypted += sm4_dec.finish()

        return decrypted

    # Encrypt/decrypt in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(encrypt_decrypt) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All results should be identical to plaintext
    assert all(result == plaintext for result in results)


# =============================================================================
# ZUC Stream Cipher Thread Safety
# =============================================================================


def test_zuc_thread_safety():
    """
    Test that ZUC stream cipher is thread-safe.

    Multiple threads should be able to encrypt/decrypt concurrently.
    """
    num_threads = 20
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"hello, world" * 10

    def encrypt_decrypt():
        # Encrypt
        zuc_enc = Zuc(key, iv)
        ciphertext = zuc_enc.update(plaintext)
        ciphertext += zuc_enc.finish()

        # Decrypt
        zuc_dec = Zuc(key, iv)
        decrypted = zuc_dec.update(ciphertext)
        decrypted += zuc_dec.finish()

        return decrypted

    # Encrypt/decrypt in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(encrypt_decrypt) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All results should be identical to plaintext
    assert all(result == plaintext for result in results)


# =============================================================================
# SM2 Public Key Cryptography Thread Safety
# =============================================================================


def test_sm2_key_generation_thread_safety():
    """
    Test that SM2 key generation is thread-safe.

    Multiple threads should be able to generate keys concurrently.
    """
    num_threads = 20

    def generate_key():
        sm2 = Sm2Key()
        sm2.generate_key()
        return bytes(sm2.private_key)

    # Generate keys in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(generate_key) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All keys should be unique
    assert len(set(results)) == num_threads


def test_sm2_sign_verify_thread_safety():
    """
    Test that SM2 signing and verification is thread-safe.

    Multiple threads should be able to sign and verify concurrently.
    """
    num_threads = 20

    # Generate a shared key
    sm2 = Sm2Key()
    sm2.generate_key()

    data = b"hello, world"
    digest = Sm3()
    digest.update(data)
    dgst = digest.digest()

    def sign_verify():
        # Sign
        sig = sm2.sign(dgst)

        # Verify
        assert sm2.verify(dgst, sig)

        return sig

    # Sign/verify in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(sign_verify) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All signatures should be valid (may be different due to randomness)
    assert len(results) == num_threads


def test_sm2_encrypt_decrypt_thread_safety():
    """
    Test that SM2 encryption and decryption is thread-safe.

    Multiple threads should be able to encrypt and decrypt concurrently.
    """
    num_threads = 20

    # Generate a shared key
    sm2 = Sm2Key()
    sm2.generate_key()

    plaintext = b"hello, world"

    def encrypt_decrypt():
        # Encrypt
        ciphertext = sm2.encrypt(plaintext)

        # Decrypt
        decrypted = sm2.decrypt(ciphertext)

        return decrypted

    # Encrypt/decrypt in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(encrypt_decrypt) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All results should be identical to plaintext
    assert all(result == plaintext for result in results)


# =============================================================================
# SM9 Identity-Based Cryptography Thread Safety
# =============================================================================


def test_sm9_key_generation_thread_safety():
    """
    Test that SM9 key generation is thread-safe.

    Multiple threads should be able to generate master keys concurrently.
    """
    num_threads = 10  # Fewer threads as SM9 is slower

    def generate_master_key():
        master = Sm9EncMasterKey()
        master.generate_master_key()
        return True

    # Generate master keys in multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(generate_master_key) for _ in range(num_threads)]
        results = [future.result() for future in as_completed(futures)]

    # All operations should succeed
    assert all(results)


# =============================================================================
# Mixed Operations Thread Safety
# =============================================================================


def test_mixed_operations_thread_safety():
    """
    Test thread safety with mixed cryptographic operations.

    Multiple threads performing different operations concurrently.
    """
    num_iterations = 50

    def sm3_operation():
        sm3 = Sm3()
        sm3.update(b"test data")
        return sm3.digest()

    def sm4_operation():
        key = os.urandom(16)
        iv = os.urandom(16)
        sm4 = Sm4Cbc(key, iv, True)
        ciphertext = sm4.update(b"test data")
        ciphertext += sm4.finish()
        return ciphertext

    def sm2_operation():
        sm2 = Sm2Key()
        sm2.generate_key()
        return bytes(sm2.private_key)

    def random_operation():
        return rand_bytes(32)

    operations = [sm3_operation, sm4_operation, sm2_operation, random_operation]

    # Run mixed operations in multiple threads
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for _ in range(num_iterations):
            for op in operations:
                futures.append(executor.submit(op))

        results = [future.result() for future in as_completed(futures)]

    # All operations should complete successfully
    assert len(results) == num_iterations * len(operations)
