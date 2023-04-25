import time
import unittest
import secrets
import GmSSL


class SM2TestCase(unittest.TestCase):
    def test_sm2_encrypt_and_decrypt(self):
        for i in range(1, 256):
            keypair = GmSSL.sm2_generate_keypair()
            raw = secrets.token_bytes(i)
            encrypted = GmSSL.sm2_encrypt(keypair.public_key, raw)
            decrypted = GmSSL.sm2_decrypt(keypair.private_key, encrypted)
            self.assertEqual(raw, decrypted)

    def test_sm2_sign_and_verify_digest(self):
        keypair = GmSSL.sm2_generate_keypair()
        for i in range(1, 256):
            digest = secrets.token_bytes(GmSSL.SM3_DIGEST_SIZE)
            sign = GmSSL.sm2_sign_digest(keypair.private_key, digest)
            verified = GmSSL.sm2_verify_digest(keypair.public_key, digest, sign)
            self.assertTrue(verified)

    def test_sm2_sign_and_verify(self):
        for i in range(1, 256):
            keypair = GmSSL.sm2_generate_keypair()
            message = secrets.token_bytes(i)
            sign = GmSSL.sm2_sign(keypair.public_key, keypair.private_key, message)
            verified = GmSSL.sm2_verify(keypair.public_key, keypair.private_key, message, sign)
            self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
