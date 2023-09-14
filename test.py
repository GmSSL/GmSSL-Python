#!/usr/bin/env python
#
# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# pyGmSSL - the Python binding of the GmSSL library



import unittest
from gmssl import *

class TestGmSSL(unittest.TestCase):

	def test_rand(self):
		keylen = 20
		key = rand_bytes(keylen)
		self.assertEqual(len(key), keylen)
		#print("version")
		#print(GMSSL_LIBRARY_VERSION)

	def test_sm3(self):
		dgst_hex = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
		sm3 = Sm3()
		sm3.update(b'abc')
		dgst = sm3.digest()
		#print(dgst.hex())
		self.assertEqual(dgst, bytes.fromhex(dgst_hex))

	def test_sm3_hmac(self):
		key = b'1234567812345678'
		mac_hex = '0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080'
		sm3_hmac = Sm3Hmac(key)
		sm3_hmac.update(b'abc')
		mac = sm3_hmac.generateMac()
		self.assertEqual(mac, bytes.fromhex(mac_hex))

	def test_sm4(self):
		key = b'1234567812345678'
		plaintext = b'block of message'
		sm4 = Sm4(key, True)
		ciphertext = sm4.encrypt(plaintext)
		sm4 = Sm4(key, False)
		decrypted = sm4.encrypt(ciphertext)
		self.assertEqual(decrypted, plaintext)

	def test_sm4_cbc(self):
		key = b'1234567812345678'
		iv = b'0000000000000000'
		plaintext = b'abc'
		sm4_cbc = Sm4Cbc(key, iv, True)
		ciphertext = sm4_cbc.update(plaintext)
		ciphertext += sm4_cbc.finish()
		sm4_cbc = Sm4Cbc(key, iv, False)
		decrypted = sm4_cbc.update(ciphertext)
		decrypted += sm4_cbc.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm4_ctr(self):
		key = b'1234567812345678'
		iv = b'0000000000000000'
		plaintext = b'abc'
		sm4_ctr = Sm4Ctr(key, iv)
		ciphertext = sm4_ctr.update(plaintext)
		ciphertext += sm4_ctr.finish()

		sm4_ctr = Sm4Ctr(key, iv)
		decrypted = sm4_ctr.update(ciphertext)
		decrypted += sm4_ctr.finish()
		self.assertEqual(decrypted, plaintext)

	def test_zuc(self):
		key = b'1234567812345678'
		iv = b'0000000000000000'
		plaintext = b'abc'
		zuc = Zuc(key, iv)
		ciphertext = zuc.update(plaintext)
		ciphertext += zuc.finish()

		zuc = Zuc(key, iv)
		decrypted = zuc.update(ciphertext)
		decrypted += zuc.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm4_gcm(self):
		key = b'1234567812345678'
		iv = b'0000000000000000'
		aad = b'AAD data'
		taglen = 16
		plaintext = b'abc'
		sm4_gcm = Sm4Gcm(key, iv, aad, taglen, True)
		ciphertext = sm4_gcm.update(plaintext)
		ciphertext += sm4_gcm.finish()

		sm4_gcm = Sm4Gcm(key, iv, aad, taglen, False)
		decrypted = sm4_gcm.update(ciphertext)
		decrypted += sm4_gcm.finish()
		self.assertEqual(decrypted, plaintext)

	def test_sm2_key(self):
		sm3 = Sm3()
		sm3.update(b'abc')
		dgst = sm3.digest()

		sm2 = Sm2Key()
		sm2.generate_key()

		sm2.export_encrypted_private_key_info_pem('sm2.pem', 'password')

		sm2pri = Sm2Key()
		sm2pri.import_encrypted_private_key_info_pem('sm2.pem', 'password')

		sm2.export_public_key_info_pem('sm2pub.pem')

		sm2pub = Sm2Key()
		sm2pub.import_public_key_info_pem("sm2pub.pem");

		z = sm2.compute_z('1234567812345678')
		#print(z.hex())

		sig = sm2pri.sign(dgst)
		verify_ret = sm2pub.verify(dgst, sig)
		self.assertTrue(verify_ret)

		plaintext = b'abc'
		ciphertext = sm2pub.encrypt(plaintext)
		decrypted = sm2pri.decrypt(ciphertext)
		self.assertEqual(decrypted, plaintext)

	def test_sm2_sig(self):
		sm2 = Sm2Key()
		sm2.generate_key()

		sign = Sm2Signature(sm2, SM2_DEFAULT_ID, True)
		sign.update(b'abc')
		sig = sign.sign()

		verify = Sm2Signature(sm2, SM2_DEFAULT_ID, False)
		verify.update(b'abc')
		verify_ret = verify.verify(sig)
		self.assertTrue(verify_ret)


if __name__ == '__main__':
	unittest.main()



