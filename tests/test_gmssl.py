#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

"""
GmSSL Python binding tests.

Following Linus's philosophy: "Talk is cheap. Show me the code."
Simple functions, no unnecessary abstractions.
"""

import tempfile
from pathlib import Path

from gmssl import (
    DO_DECRYPT,
    DO_ENCRYPT,
    DO_SIGN,
    DO_VERIFY,
    GMSSL_LIBRARY_VERSION,
    GMSSL_PYTHON_VERSION,
    SM2_DEFAULT_ID,
    Sm2Certificate,
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
    gmssl_library_version_num,
    rand_bytes,
    sm3_pbkdf2,
)


# Version tests
def test_library_version_num():
    """Library version number should be positive."""
    assert gmssl_library_version_num() > 0


def test_library_version_string():
    """Library version string should not be empty."""
    assert len(GMSSL_LIBRARY_VERSION) > 0


def test_python_version_string():
    """Python binding version string should not be empty."""
    assert len(GMSSL_PYTHON_VERSION) > 0


# Random number generation
def test_rand_bytes():
    """rand_bytes should generate correct length."""
    keylen = 20
    key = rand_bytes(keylen)
    assert len(key) == keylen


# SM3 hash tests
def test_sm3_hash():
    """SM3 hash of 'abc' should match known value."""
    dgst_hex = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    sm3 = Sm3()
    sm3.update(b"abc")
    dgst = sm3.digest()
    assert dgst == bytes.fromhex(dgst_hex)


def test_sm3_reset():
    """SM3 reset should allow reuse."""
    sm3 = Sm3()
    sm3.update(b"abc")
    dgst1 = sm3.digest()

    sm3.reset()
    for _ in range(16):
        sm3.update(b"abcd")
    dgst2 = sm3.digest()

    # Different inputs should produce different hashes
    assert dgst1 != dgst2


# SM3-HMAC test
def test_sm3_hmac():
    """SM3-HMAC should match known value."""
    key = b"1234567812345678"
    mac_hex = "0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080"
    sm3_hmac = Sm3Hmac(key)
    sm3_hmac.update(b"abc")
    mac = sm3_hmac.generate_mac()
    assert mac == bytes.fromhex(mac_hex)


# SM3-PBKDF2 test
def test_sm3_pbkdf2():
    """SM3-PBKDF2 should derive correct key."""
    passwd = "password"
    salt = b"12345678"
    iterator = 10000
    keylen = 32
    keyhex = "ac5b4a93a130252181434970fa9d8e6f1083badecafc4409aaf0097c813e9fc6"
    key = sm3_pbkdf2(passwd, salt, iterator, keylen)
    assert key == bytes.fromhex(keyhex)


# SM4 block cipher test
def test_sm4_encrypt_decrypt():
    """SM4 encryption and decryption should be reversible."""
    key = b"1234567812345678"
    plaintext = b"block of message"
    ciphertext_hex = "dd99d30fd7baf5af2930335d2554ddb7"

    # Encrypt
    sm4_enc = Sm4(key, DO_ENCRYPT)
    ciphertext = sm4_enc.encrypt(plaintext)
    assert ciphertext == bytes.fromhex(ciphertext_hex)

    # Decrypt
    sm4_dec = Sm4(key, DO_DECRYPT)
    decrypted = sm4_dec.decrypt(ciphertext)
    assert decrypted == plaintext


# SM4-CBC test
def test_sm4_cbc_encrypt_decrypt():
    """SM4-CBC encryption and decryption should be reversible."""
    key = b"1234567812345678"
    iv = b"1234567812345678"
    plaintext = b"abc"
    ciphertext_hex = "532b22f9a096e7e5b8d84a620f0f7078"

    # Encrypt
    sm4_cbc = Sm4Cbc(key, iv, DO_ENCRYPT)
    ciphertext = sm4_cbc.update(plaintext)
    ciphertext += sm4_cbc.finish()
    assert ciphertext == bytes.fromhex(ciphertext_hex)

    # Decrypt
    sm4_cbc = Sm4Cbc(key, iv, DO_DECRYPT)
    decrypted = sm4_cbc.update(ciphertext)
    decrypted += sm4_cbc.finish()
    assert decrypted == plaintext


# SM4-CTR test
def test_sm4_ctr_encrypt_decrypt():
    """SM4-CTR encryption and decryption should be reversible."""
    key = b"1234567812345678"
    iv = b"1234567812345678"
    plaintext = b"abc"
    ciphertext_hex = "890106"

    # Encrypt
    sm4_ctr = Sm4Ctr(key, iv)
    ciphertext = sm4_ctr.update(plaintext)
    ciphertext += sm4_ctr.finish()
    assert ciphertext == bytes.fromhex(ciphertext_hex)

    # Decrypt
    sm4_ctr = Sm4Ctr(key, iv)
    decrypted = sm4_ctr.update(ciphertext)
    decrypted += sm4_ctr.finish()
    assert decrypted == plaintext


# SM4-GCM test
def test_sm4_gcm_encrypt_decrypt():
    """SM4-GCM encryption and decryption should be reversible."""
    key = b"1234567812345678"
    iv = b"0123456789ab"
    aad = b"Additional Authenticated Data"
    taglen = 16
    plaintext = b"abc"
    ciphertext_hex = "7d8bd8fdc7ea3b04c15fb61863f2292c15eeaa"

    # Encrypt
    sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_ENCRYPT)
    ciphertext = sm4_gcm.update(plaintext)
    ciphertext += sm4_gcm.finish()
    assert ciphertext == bytes.fromhex(ciphertext_hex)

    # Decrypt
    sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_DECRYPT)
    decrypted = sm4_gcm.update(ciphertext)
    decrypted += sm4_gcm.finish()
    assert decrypted == plaintext


# ZUC test
def test_zuc_encrypt_decrypt():
    """ZUC encryption and decryption should be reversible."""
    key = b"1234567812345678"
    iv = b"1234567812345678"
    plaintext = b"abc"
    ciphertext_hex = "3d144b"

    # Encrypt
    zuc = Zuc(key, iv)
    ciphertext = zuc.update(plaintext)
    ciphertext += zuc.finish()
    assert ciphertext == bytes.fromhex(ciphertext_hex)

    # Decrypt
    zuc = Zuc(key, iv)
    decrypted = zuc.update(ciphertext)
    decrypted += zuc.finish()
    assert decrypted == plaintext


# SM2 key tests
def test_sm2_key_generation_and_export():
    """SM2 key generation, export, and import should work."""
    dgst = bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
    plaintext = b"abc"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sm2_pem = tmpdir / "sm2.pem"
        sm2pub_pem = tmpdir / "sm2pub.pem"

        # Generate key
        sm2 = Sm2Key()
        sm2.generate_key()
        sm2.export_encrypted_private_key_info_pem(str(sm2_pem), "password")
        sm2.export_public_key_info_pem(str(sm2pub_pem))

        # Import private key
        sm2pri = Sm2Key()
        sm2pri.import_encrypted_private_key_info_pem(str(sm2_pem), "password")

        # Import public key
        sm2pub = Sm2Key()
        sm2pub.import_public_key_info_pem(str(sm2pub_pem))

        # Test signature
        sig = sm2pri.sign(dgst)
        verify_ret = sm2pub.verify(dgst, sig)
        assert verify_ret

        # Test encryption
        ciphertext = sm2pub.encrypt(plaintext)
        decrypted = sm2pri.decrypt(ciphertext)
        assert decrypted == plaintext


def test_sm2_compute_z():
    """SM2 compute_z should match known value."""
    pem_txt = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE+XVF76aof3ZtBVUwXobDQwQn+Sb2
ethykPiYkXDLFdLnTrqr0b9QuA63DPdyrxJS3LZZwp9qzaMSyStai8+nrQ==
-----END PUBLIC KEY-----"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        pub_pem = tmpdir / "pub.pem"
        pub_pem.write_text(pem_txt)

        z_hex = "4e469c92c425960603a315491bb2181c2f25939172775e223e1759b413cfc8ba"
        sm2pub = Sm2Key()
        sm2pub.import_public_key_info_pem(str(pub_pem))
        z = sm2pub.compute_z(SM2_DEFAULT_ID)
        assert z == bytes.fromhex(z_hex)


# SM2 signature test
def test_sm2_signature_context():
    """SM2 signature context should work correctly."""
    sm2 = Sm2Key()
    sm2.generate_key()

    # Sign
    sign = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)
    sign.update(b"abc")
    sig = sign.sign()

    # Verify
    verify = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
    verify.update(b"abc")
    verify_ret = verify.verify(sig)
    assert verify_ret


# SM9 encryption test
def test_sm9_enc_decrypt():
    """SM9 encryption and decryption should work."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        enc_msk_pem = tmpdir / "enc_msk.pem"
        enc_mpk_pem = tmpdir / "enc_mpk.pem"

        # Generate master key
        master_key = Sm9EncMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(enc_msk_pem), "password")
        master_key.export_public_master_key_pem(str(enc_mpk_pem))

        # Encrypt with public master key
        master_pub = Sm9EncMasterKey()
        master_pub.import_public_master_key_pem(str(enc_mpk_pem))
        ciphertext = master_pub.encrypt(b"plaintext", "Alice")

        # Decrypt with extracted user key
        master = Sm9EncMasterKey()
        master.import_encrypted_master_key_info_pem(str(enc_msk_pem), "password")
        key = master.extract_key("Alice")
        plaintext = key.decrypt(ciphertext)
        assert plaintext == b"plaintext"


# SM9 signature test
def test_sm9_sign_verify():
    """SM9 signature and verification should work."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sign_msk_pem = tmpdir / "sign_msk.pem"
        sign_mpk_pem = tmpdir / "sign_mpk.pem"

        # Generate master key
        master_key = Sm9SignMasterKey()
        master_key.generate_master_key()
        master_key.export_encrypted_master_key_info_pem(str(sign_msk_pem), "password")
        master_key.export_public_master_key_pem(str(sign_mpk_pem))

        # Sign with extracted user key
        master = Sm9SignMasterKey()
        master.import_encrypted_master_key_info_pem(str(sign_msk_pem), "password")
        key = master.extract_key("Alice")
        sign = Sm9Signature(DO_SIGN)
        sign.update(b"message")
        sig = sign.sign(key)

        # Verify with public master key
        master_pub = Sm9SignMasterKey()
        master_pub.import_public_master_key_pem(str(sign_mpk_pem))
        verify = Sm9Signature(DO_VERIFY)
        verify.update(b"message")
        ret = verify.verify(sig, master_pub, "Alice")
        assert ret


# SM2 certificate test
def test_sm2_certificate_parsing():
    """SM2 certificate parsing and verification should work."""
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
        rootca_pem = tmpdir / "ROOTCA.pem"
        public_key_pem = tmpdir / "public_key.pem"

        rootca_pem.write_text(cert_txt)

        cert = Sm2Certificate()
        cert.import_pem(str(rootca_pem))

        # Test serial number
        serial = cert.get_serial_number()
        assert len(serial) > 0

        # Test validity
        validity = cert.get_validity()
        assert validity.not_before < validity.not_after

        # Test issuer and subject
        issuer = cert.get_issuer()
        assert len(issuer) > 1
        subject = cert.get_subject()
        assert len(subject) > 1

        # Test public key export/import
        public_key = cert.get_subject_public_key()
        public_key.export_public_key_info_pem(str(public_key_pem))
        public_key.import_public_key_info_pem(str(public_key_pem))

        # Test certificate verification
        ret = cert.verify_by_ca_certificate(cert, SM2_DEFAULT_ID)
        assert ret
