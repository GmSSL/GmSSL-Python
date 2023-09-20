#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0


import unittest
from gmssl import *

class TestGmSSL(unittest.TestCase):

	def test_version(self):
		self.assertTrue(gmssl_library_version_num() > 0)
		self.assertTrue(len(GMSSL_LIBRARY_VERSION) > 0)
		self.assertTrue(len(GMSSL_PYTHON_VERSION) > 0)

	def test_rand(self):
		keylen = 20
		key = rand_bytes(keylen)
		self.assertEqual(len(key), keylen)

	def test_sm3(self):
		dgst_hex = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
		sm3 = Sm3()
		sm3.update(b'abc')
		dgst = sm3.digest()
		self.assertEqual(dgst, bytes.fromhex(dgst_hex))

	def test_sm3_hmac(self):
		key = b'1234567812345678'
		mac_hex = '0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080'
		sm3_hmac = Sm3Hmac(key)
		sm3_hmac.update(b'abc')
		mac = sm3_hmac.generate_mac()
		self.assertEqual(mac, bytes.fromhex(mac_hex))

	def test_sm3_pbkdf2(self):
		passwd = 'password'
		salt = b'12345678'
		iterator = 10000
		keylen  = 32
		keyhex = 'ac5b4a93a130252181434970fa9d8e6f1083badecafc4409aaf0097c813e9fc6'
		key = sm3_pbkdf2(passwd, salt, iterator, keylen)
		self.assertEqual(key, bytes.fromhex(keyhex))

	def test_sm4(self):
		key = b'1234567812345678'
		plaintext = b'block of message'
		ciphertext_hex = 'dd99d30fd7baf5af2930335d2554ddb7'
		sm4 = Sm4(key, DO_ENCRYPT)
		ciphertext = sm4.encrypt(plaintext)
		self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
		sm4 = Sm4(key, DO_DECRYPT)
		decrypted = sm4.encrypt(ciphertext)
		self.assertEqual(decrypted, plaintext)

	def test_sm4_cbc(self):
		key = b'1234567812345678'
		iv = b'1234567812345678'
		plaintext = b'abc'
		ciphertext_hex = '532b22f9a096e7e5b8d84a620f0f7078'
		sm4_cbc = Sm4Cbc(key, iv, DO_ENCRYPT)
		ciphertext = sm4_cbc.update(plaintext)
		ciphertext += sm4_cbc.finish()
		self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
		sm4_cbc = Sm4Cbc(key, iv, DO_DECRYPT)
		decrypted = sm4_cbc.update(ciphertext)
		decrypted += sm4_cbc.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm4_ctr(self):
		key = b'1234567812345678'
		iv = b'1234567812345678'
		plaintext = b'abc'
		ciphertext_hex = '890106'
		sm4_ctr = Sm4Ctr(key, iv)
		ciphertext = sm4_ctr.update(plaintext)
		ciphertext += sm4_ctr.finish()
		self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
		sm4_ctr = Sm4Ctr(key, iv)
		decrypted = sm4_ctr.update(ciphertext)
		decrypted += sm4_ctr.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm4_gcm(self):
		key = b'1234567812345678'
		iv = b'0123456789ab'
		aad = b'Additional Authenticated Data'
		taglen = 16
		plaintext = b'abc'
		ciphertext_hex = '7d8bd8fdc7ea3b04c15fb61863f2292c15eeaa'
		sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_ENCRYPT)
		ciphertext = sm4_gcm.update(plaintext)
		ciphertext += sm4_gcm.finish()
		self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
		sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_DECRYPT)
		decrypted = sm4_gcm.update(ciphertext)
		decrypted += sm4_gcm.finish()
		self.assertEqual(decrypted, plaintext)

	def test_zuc(self):
		key = b'1234567812345678'
		iv = b'1234567812345678'
		plaintext = b'abc'
		ciphertext_hex = '3d144b'
		zuc = Zuc(key, iv)
		ciphertext = zuc.update(plaintext)
		ciphertext += zuc.finish()
		self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
		zuc = Zuc(key, iv)
		decrypted = zuc.update(ciphertext)
		decrypted += zuc.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm2_key(self):
		dgst = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
		plaintext = b'abc'
		sm2 = Sm2Key()
		sm2.generate_key()
		sm2.export_encrypted_private_key_info_pem('sm2.pem', 'password')
		sm2.export_public_key_info_pem('sm2pub.pem')
		sm2pri = Sm2Key()
		sm2pri.import_encrypted_private_key_info_pem('sm2.pem', 'password')
		sm2pub = Sm2Key()
		sm2pub.import_public_key_info_pem("sm2pub.pem");
		sig = sm2pri.sign(dgst)
		verify_ret = sm2pub.verify(dgst, sig)
		self.assertTrue(verify_ret)
		ciphertext = sm2pub.encrypt(plaintext)
		decrypted = sm2pri.decrypt(ciphertext)
		self.assertEqual(decrypted, plaintext)

	def test_sm2_id(self):
		pem_txt = '''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE+XVF76aof3ZtBVUwXobDQwQn+Sb2
ethykPiYkXDLFdLnTrqr0b9QuA63DPdyrxJS3LZZwp9qzaMSyStai8+nrQ==
-----END PUBLIC KEY-----'''
		with open('pub.pem', 'w') as file:
			file.write(pem_txt)
			file.close()
		z_hex = '4e469c92c425960603a315491bb2181c2f25939172775e223e1759b413cfc8ba'
		sm2pub = Sm2Key()
		sm2pub.import_public_key_info_pem('pub.pem')
		z = sm2pub.compute_z(SM2_DEFAULT_ID)
		self.assertEqual(z, bytes.fromhex(z_hex))

	def test_sm2_sig(self):
		sm2 = Sm2Key()
		sm2.generate_key()
		sign = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_SIGN)
		sign.update(b'abc')
		sig = sign.sign()
		verify = Sm2Signature(sm2, SM2_DEFAULT_ID, DO_VERIFY)
		verify.update(b'abc')
		verify_ret = verify.verify(sig)
		self.assertTrue(verify_ret)

	def test_sm9_enc(self):
		master_key = Sm9EncMasterKey()
		master_key.generate_master_key()
		master_key.export_encrypted_master_key_info_pem('enc_msk.pem', 'password')
		master_key.export_public_master_key_pem('enc_mpk.pem')
		master_pub = Sm9EncMasterKey()
		master_pub.import_public_master_key_pem('enc_mpk.pem')
		ciphertext = master_pub.encrypt(b'plaintext', 'Alice')
		master = Sm9EncMasterKey()
		master.import_encrypted_master_key_info_pem('enc_msk.pem', 'password')
		key = master.extract_key('Alice')
		plaintext = key.decrypt(ciphertext)
		self.assertEqual(plaintext, b'plaintext')

	def test_sm9_sign(self):
		master_key = Sm9SignMasterKey()
		master_key.generate_master_key()
		master_key.export_encrypted_master_key_info_pem('sign_msk.pem', 'password')
		master_key.export_public_master_key_pem('sign_mpk.pem')
		master = Sm9SignMasterKey()
		master.import_encrypted_master_key_info_pem('sign_msk.pem', 'password')
		key = master.extract_key('Alice')
		sign = Sm9Signature(DO_SIGN)
		sign.update(b'message')
		sig = sign.sign(key)
		master_pub = Sm9SignMasterKey()
		master_pub.import_public_master_key_pem('sign_mpk.pem')
		verify = Sm9Signature(DO_VERIFY)
		verify.update(b'message')
		ret = verify.verify(sig, master_pub, 'Alice')
		self.assertTrue(ret)

	def test_sm2_cert(self):
		cert_txt = '''\
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
-----END CERTIFICATE-----'''
		with open('ROOTCA.pem', 'w') as file:
			file.write(cert_txt)
			file.close()

		cert = Sm2Certificate()
		cert.import_pem('ROOTCA.pem')
		serial = cert.get_serial_number()
		self.assertTrue(len(serial) > 0)
		validity = cert.get_validity()
		self.assertTrue(validity.not_before < validity.not_after)
		issuer = cert.get_issuer()
		self.assertTrue(len(issuer) > 1)
		subject = cert.get_subject()
		self.assertTrue(len(subject) > 1)
		public_key = cert.get_subject_public_key()
		public_key.export_public_key_info_pem('public_key.pem')
		public_key.import_public_key_info_pem('public_key.pem')
		ret = cert.verify_by_ca_certificate(cert, SM2_DEFAULT_ID)
		self.assertTrue(ret)


if __name__ == '__main__':
	unittest.main()

