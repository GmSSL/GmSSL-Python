#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
Additional method tests for GmSSL Python binding.

Tests for methods that were not covered in the main test suite,
including import/export operations, get_id methods, and other utilities.
"""

import tempfile
from pathlib import Path

import pytest

from gmssl import (
    DO_SIGN,
    DO_VERIFY,
    SM9_MAX_PLAINTEXT_SIZE,
    Sm2Certificate,
    Sm9EncKey,
    Sm9EncMasterKey,
    Sm9Signature,
    Sm9SignKey,
    Sm9SignMasterKey,
)

# =============================================================================
# SM9 Encryption Key Tests
# =============================================================================


def test_sm9_enc_key_get_id():
    """SM9 EncKey should return correct ID."""
    key = Sm9EncKey("Alice")
    assert key.get_id() == b"Alice"


def test_sm9_enc_key_import_export():
    """SM9 EncKey should support import/export of encrypted private key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_msk_pem = tmpdir / "enc_msk.pem"
        enc_key_pem = tmpdir / "enc_key.pem"

        # Generate master key and extract user key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(enc_msk_pem), "password")

        key = master_key.extract_key("Alice")

        # Export user key
        key.export_encrypted_private_key_info_pem(str(enc_key_pem), "userpass")

        # Import user key
        key2 = Sm9EncKey("Alice")
        key2.import_encrypted_private_key_info_pem(str(enc_key_pem), "userpass")

        # Test decryption with imported key
        ciphertext = master_key.encrypt(b"test message", "Alice")
        plaintext = key2.decrypt(ciphertext)
        assert plaintext == b"test message"


def test_sm9_enc_key_has_private_key():
    """SM9 EncKey should track private key status."""
    # New key without private key
    key = Sm9EncKey("Alice")
    assert not key.has_private_key()

    # Extract key from master key
    master_key = Sm9EncMasterKey()
    master_key.generate_master_key()
    key = master_key.extract_key("Alice")
    assert key.has_private_key()


# =============================================================================
# SM9 Signature Key Tests
# =============================================================================


def test_sm9_sign_key_get_id():
    """SM9 SignKey should return correct ID."""
    key = Sm9SignKey("Bob")
    assert key.get_id() == b"Bob"


def test_sm9_sign_key_import_export():
    """SM9 SignKey should support import/export of encrypted private key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sign_msk_pem = tmpdir / "sign_msk.pem"
        sign_key_pem = tmpdir / "sign_key.pem"

        # Generate master key and extract user key
        master_key = Sm9SignMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(sign_msk_pem), "password")

        key = master_key.extract_key("Bob")

        # Export user key
        key.export_encrypted_private_key_info_pem(str(sign_key_pem), "userpass")

        # Import user key
        key2 = Sm9SignKey("Bob")
        key2.import_encrypted_private_key_info_pem(str(sign_key_pem), "userpass")

        # Test signing with imported key
        sign = Sm9Signature(DO_SIGN)
        sign.update(b"message")
        sig = sign.sign(key2)

        # Verify signature
        verify = Sm9Signature(DO_VERIFY)
        verify.update(b"message")
        assert verify.verify(sig, master_key, "Bob")


def test_sm9_sign_key_has_private_key():
    """SM9 SignKey should track private key status."""
    # New key without private key
    key = Sm9SignKey("Bob")
    assert not key.has_private_key()

    # Extract key from master key
    master_key = Sm9SignMasterKey()
    master_key.generate_master_key()
    key = master_key.extract_key("Bob")
    assert key.has_private_key()


def test_sm9_sign_key_has_public_key():
    """SM9 SignKey should track public key status."""
    # New key without public key
    key = Sm9SignKey("Bob")
    assert not key.has_public_key()

    # Extract key from master key
    master_key = Sm9SignMasterKey()
    master_key.generate_master_key()
    key = master_key.extract_key("Bob")
    assert key.has_public_key()


# =============================================================================
# SM9 User Key - Master Public Key Import Tests
# =============================================================================


def test_sm9_enc_key_import_master_public_key():
    """SM9 EncKey should support importing master public key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_mpk_pem = tmpdir / "enc_mpk.pem"

        # Generate and export master public key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(enc_mpk_pem))

        # Import master public key into user key
        user_key = Sm9EncKey("Alice")
        user_key.import_enc_master_public_key_pem(str(enc_mpk_pem))

        # Should be able to encrypt with the imported public key
        plaintext = b"test message"
        ciphertext = user_key.encrypt(plaintext)
        assert len(ciphertext) > 0


def test_sm9_sign_key_import_master_public_key():
    """SM9 SignKey should support importing master public key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sign_mpk_pem = tmpdir / "sign_mpk.pem"

        # Generate and export master public key
        master_key = Sm9SignMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(sign_mpk_pem))

        # Import master public key into user key
        user_key = Sm9SignKey("Bob")
        user_key.import_sign_master_public_key_pem(str(sign_mpk_pem))

        # Should have public key but no private key
        assert user_key.has_public_key()
        assert not user_key.has_private_key()


# =============================================================================
# SM9 EncKey Direct Encryption Test
# =============================================================================


def test_sm9_enc_key_encrypt_with_master_public_key():
    """SM9 EncKey can encrypt after importing master public key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_mpk_pem = tmpdir / "enc_mpk.pem"
        enc_msk_pem = tmpdir / "enc_msk.pem"

        # Generate master key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(enc_mpk_pem))
        master_key.export_encrypted_master_key_info_pem(str(enc_msk_pem), "password")

        # Create user key with master public key
        alice_key = Sm9EncKey("Alice")
        alice_key.import_enc_master_public_key_pem(str(enc_mpk_pem))

        # Encrypt using user key (which has master public key)
        plaintext = b"secret message"
        ciphertext = alice_key.encrypt(plaintext)

        # Decrypt using extracted private key
        master = Sm9EncMasterKey()
        master.import_encrypted_master_key_info_pem(str(enc_msk_pem), "password")
        alice_private = master.extract_key("Alice")
        decrypted = alice_private.decrypt(ciphertext)

        assert decrypted == plaintext


def test_sm9_enc_key_encrypt_plaintext_too_long():
    """SM9 EncKey encrypt should reject plaintext that is too long."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_mpk_pem = tmpdir / "enc_mpk.pem"

        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(enc_mpk_pem))

        alice_key = Sm9EncKey("Alice")
        alice_key.import_enc_master_public_key_pem(str(enc_mpk_pem))

        # Try to encrypt plaintext that's too long
        with pytest.raises(ValueError, match="Invalid plaintext length"):
            alice_key.encrypt(b"x" * (SM9_MAX_PLAINTEXT_SIZE + 1))


# =============================================================================
# SM2 Certificate Tests
# =============================================================================


def test_sm2_certificate_export_pem():
    """SM2 Certificate should support export to PEM."""
    cert_txt = """\
-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import_pem = tmpdir / "import.pem"
        export_pem = tmpdir / "export.pem"

        # Write certificate to file
        import_pem.write_text(cert_txt)

        # Import certificate
        cert = Sm2Certificate()
        cert.import_pem(str(import_pem))

        # Export certificate
        cert.export_pem(str(export_pem))

        # Verify exported file exists and has content
        assert export_pem.exists()
        exported_content = export_pem.read_text()
        assert "BEGIN CERTIFICATE" in exported_content
        assert "END CERTIFICATE" in exported_content


def test_sm2_certificate_get_raw():
    """SM2 Certificate should return raw DER data."""
    cert_txt = """\
-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        cert_pem = tmpdir / "cert.pem"
        cert_pem.write_text(cert_txt)

        # Import certificate
        cert = Sm2Certificate()
        cert.import_pem(str(cert_pem))

        # Get raw DER data
        raw_data = cert.get_raw()

        # Raw data should be a ctypes array (not bytes) and non-empty
        # The _cert field is a ctypes.c_char_Array
        assert hasattr(raw_data, "__len__")
        assert len(raw_data) > 0


# =============================================================================
# SM9 Master Key Status Tests
# =============================================================================


def test_sm9_enc_master_key_has_keys():
    """SM9 EncMasterKey should track key status."""
    master_key = Sm9EncMasterKey()

    # Initially no keys
    assert not master_key._has_public_key
    assert not master_key._has_private_key

    # After generation
    master_key.generate_master_key()
    assert master_key._has_public_key
    assert master_key._has_private_key


def test_sm9_sign_master_key_has_keys():
    """SM9 SignMasterKey should track key status."""
    master_key = Sm9SignMasterKey()

    # Initially no keys
    assert not master_key._has_public_key
    assert not master_key._has_private_key

    # After generation
    master_key.generate_master_key()
    assert master_key._has_public_key
    assert master_key._has_private_key


def test_sm9_enc_master_key_import_public_only():
    """SM9 EncMasterKey should support importing public key only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_mpk_pem = tmpdir / "enc_mpk.pem"

        # Generate and export public master key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(enc_mpk_pem))

        # Import public key only
        master_pub = Sm9EncMasterKey()
        master_pub.import_public_master_key_pem(str(enc_mpk_pem))

        # Should have public key but not private key
        assert master_pub._has_public_key
        assert not master_pub._has_private_key

        # Should be able to encrypt
        ciphertext = master_pub.encrypt(b"test", "Alice")
        assert len(ciphertext) > 0


def test_sm9_sign_master_key_import_public_only():
    """SM9 SignMasterKey should support importing public key only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sign_mpk_pem = tmpdir / "sign_mpk.pem"

        # Generate and export public master key
        master_key = Sm9SignMasterKey()
        master_key.generate_master_key()
        master_key.export_public_master_key_pem(str(sign_mpk_pem))

        # Import public key only
        master_pub = Sm9SignMasterKey()
        master_pub.import_public_master_key_pem(str(sign_mpk_pem))

        # Should have public key but not private key
        assert master_pub._has_public_key
        assert not master_pub._has_private_key


# =============================================================================
# Integration Tests
# =============================================================================


def test_sm9_enc_full_workflow_with_key_export():
    """Test complete SM9 encryption workflow with key export/import."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_msk_pem = tmpdir / "enc_msk.pem"
        enc_mpk_pem = tmpdir / "enc_mpk.pem"
        enc_key_pem = tmpdir / "enc_key.pem"

        # 1. Generate master key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(enc_msk_pem), "masterpass")
        master_key.export_public_master_key_pem(str(enc_mpk_pem))

        # 2. Extract and export user key
        user_key = master_key.extract_key("Alice")
        user_key.export_encrypted_private_key_info_pem(str(enc_key_pem), "userpass")

        # 3. Encrypt with public master key
        master_pub = Sm9EncMasterKey()
        master_pub.import_public_master_key_pem(str(enc_mpk_pem))
        plaintext = b"Secret message for Alice"
        ciphertext = master_pub.encrypt(plaintext, "Alice")

        # 4. Decrypt with imported user key
        user_key2 = Sm9EncKey("Alice")
        user_key2.import_encrypted_private_key_info_pem(str(enc_key_pem), "userpass")
        decrypted = user_key2.decrypt(ciphertext)

        assert decrypted == plaintext


def test_sm9_sign_full_workflow_with_key_export():
    """Test complete SM9 signature workflow with key export/import."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sign_msk_pem = tmpdir / "sign_msk.pem"
        sign_mpk_pem = tmpdir / "sign_mpk.pem"
        sign_key_pem = tmpdir / "sign_key.pem"

        # 1. Generate master key
        master_key = Sm9SignMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(sign_msk_pem), "masterpass")
        master_key.export_public_master_key_pem(str(sign_mpk_pem))

        # 2. Extract and export user key
        user_key = master_key.extract_key("Bob")
        user_key.export_encrypted_private_key_info_pem(str(sign_key_pem), "userpass")

        # 3. Sign with imported user key
        user_key2 = Sm9SignKey("Bob")
        user_key2.import_encrypted_private_key_info_pem(str(sign_key_pem), "userpass")

        sign = Sm9Signature(DO_SIGN)
        sign.update(b"Message to sign")
        sig = sign.sign(user_key2)

        # 4. Verify with imported public master key
        master_pub = Sm9SignMasterKey()
        master_pub.import_public_master_key_pem(str(sign_mpk_pem))

        verify = Sm9Signature(DO_VERIFY)
        verify.update(b"Message to sign")
        assert verify.verify(sig, master_pub, "Bob")
