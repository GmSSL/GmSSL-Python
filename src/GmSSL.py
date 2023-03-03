# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# pyGmSSL - the Python binding of the GmSSL library


from ctypes import *
from ctypes.util import find_library

libgmssl = find_library("gmssl")

gmssl = cdll.LoadLibrary(libgmssl)


def gmssl_version_num():
	return gmssl.gmssl_version_num()


def gmssl_version_str():
	return create_string_buffer(gmssl.gmssl_version_str()).value

def rand_bytes(size):
	buf = create_string_buffer(size)
	gmssl.rand_bytes(buf, c_size_t(size))
	return buf.raw


class InnerError(Exception):
	'''
	GmSSL libraray inner error
	'''

SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64

class SM3_CTX(Structure):

	SM3_STATE_WORDS = 8

	_fields_ = [
		("digest", c_uint32 * SM3_STATE_WORDS),
		("nblocks", c_uint64),
		("block", c_uint8 * SM3_BLOCK_SIZE),
		("num", c_size_t)
	]

	def __init__(self):
		gmssl.sm3_init(byref(self))

	def update(self, data):
		gmssl.sm3_update(byref(self), data, c_size_t(len(data)))

	def finish(self):
		dgst = create_string_buffer(SM3_DIGEST_SIZE)
		gmssl.sm3_finish(byref(self), dgst)
		return dgst.raw


SM3_HMAC_SIZE = SM3_DIGEST_SIZE

class SM3_HMAC_CTX(Structure):

	_fields_ = [
		("sm3_ctx", SM3_CTX),
		("key", c_uint8 * SM3_BLOCK_SIZE)
	]

	def __init__(self, key):
		if len(key) < 1 or len(key) > 64:
			raise ValueError('Invalid SM3 HMAC key length')
		gmssl.sm3_hmac_init(byref(self), key, c_size_t(len(key)))

	def update(self, data):
		gmssl.sm3_hmac_update(byref(self), data, c_size_t(len(data)))

	def finish(self):
		hmac = create_string_buffer(SM3_HMAC_SIZE)
		gmssl.sm3_hmac_finish(byref(self), hmac)
		return hmac.raw


SM4_KEY_SIZE = 16
SM4_BLOCK_SIZE = 16

class SM4_KEY(Structure):

	SM4_NUM_ROUNDS = 32

	_fields_ = [("rk", c_uint32 * SM4_NUM_ROUNDS)]

	def set_encrypt_key(self, key):
		if len(key) != self.KEY_SIZE:
			raise ValueError('Invalid key length')
		gmssl.sm4_set_encrypt_key(byref(self), key)

	def set_decrypt_key(self, key):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		gmssl.sm4_set_decrypt_key(byref(self), key)

	def encrypt(self, block):
		if len(block) != SM4_BLOCK_SIZE:
			raise ValueError('Invalid block size')
		outbuf = create_string_buffer(SM4_BLOCK_SIZE)
		gmssl.sm4_encrypt(byref(self), block, outbuf)
		return outbuf.raw

	def decrypt(self, block):
		return self.encrypt(block)


class SM4_CBC_CTX(Structure):

	_fields_ = [
		("sm4_key", SM4_KEY),
		("iv", c_uint8 * SM4_BLOCK_SIZE),
		("block", c_uint8 * SM4_BLOCK_SIZE),
		("block_nbytes", c_size_t)
	]

	def encrypt_init(self, key, iv):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		if len(iv) != SM4_BLOCK_SIZE:
			raise ValueError('Invalid IV size')
		if gmssl.sm4_cbc_encrypt_init(byref(self), key, iv) != 1:
			raise InnerError('libgmssl inner error')

	def encrypt_update(self, data):
		outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_cbc_encrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[0:outlen].raw

	def encrypt_finish(self):
		outbuf = create_string_buffer(SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_cbc_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw

	def decrypt_init(self, key, iv):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		if len(iv) != SM4_BLOCK_SIZE:
			raise ValueError('Invalid IV size')
		if gmssl.sm4_cbc_decrypt_init(byref(self), key, iv) != 1:
			raise InnerError('libgmssl inner error')

	def decrypt_update(self, data):
		outbuf = create_string_buffer(len(data) + 16)
		outlen = c_size_t()
		if gmssl.sm4_cbc_decrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[0:outlen].raw

	def decrypt_finish(self):
		outbuf = create_string_buffer(16)
		outlen = c_size_t()
		if gmssl.sm4_cbc_decrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
			raise InnerError('decryption failure')
		return outbuf[:outlen].raw


class SM4_CTR_CTX(Structure):

	_fields_ = [
		("sm4_key", SM4_KEY),
		("ctr", c_uint8 * SM4_BLOCK_SIZE),
		("block", c_uint8 * SM4_BLOCK_SIZE),
		("block_nbytes", c_size_t)
	]

	def encrypt_init(self, key, iv):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		if len(iv) != SM4_BLOCK_SIZE:
			raise ValueError('Invalid IV size')
		if gmssl.sm4_ctr_encrypt_init(byref(self), key, iv) != 1:
			raise InnerError('libgmssl inner error')

	def encrypt_update(self, data):
		outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_ctr_encrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[0:outlen].raw

	def encrypt_finish(self):
		outbuf = create_string_buffer(SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_ctr_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw

	def decrypt_init(self, key, iv):
		return self.encrypt_init(self, key, iv)

	def decrypt_update(self, data):
		return self.encrypt_update(self, data)

	def decrypt_finish(self):
		return self.encrypt_finish(self)


class gf128_t(Structure):
	_fields_ = [
		("hi", c_uint64),
		("lo", c_uint64)
	]


class GHASH_CTX(Structure):
	_fields_ = [
		("H", gf128_t),
		("X", gf128_t),
		("aadlen", c_size_t),
		("clen", c_size_t),
		("block", c_uint8 * 16),
		("num", c_size_t)
	]


SM4_GCM_MIN_IV_SIZE = 1
SM4_GCM_MAX_IV_SIZE = 64
SM4_GCM_DEFAULT_IV_SIZE = 12
SM4_GCM_DEFAULT_TAG_SIZE = 16
SM4_GCM_MAX_TAG_SIZE = 16

class SM4_GCM_CTX(Structure):

	_fields_ = [
		("sm4_ctr_ctx", SM4_CTR_CTX),
		("mac_ctx", GHASH_CTX),
		("Y", c_uint8 * 16),
		("taglen", c_size_t),
		("mac", c_uint8 * 16),
		("maclen", c_size_t)
	]

	def encrypt_init(self, key, iv, aad, taglen):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		if len(iv) < SM4_GCM_MIN_IV_SIZE or len(iv) > SM4_GCM_MAX_IV_SIZE:
			raise ValueError('Invalid IV size')
		if taglen < 1 or tag_len > SM4_GCM_MAX_TAG_SIZE:
			raise ValueError('Invalid Tag length')
		if gmssl.sm4_gcm_encrypt_init(byref(self), key, c_size_t(len(key)), iv, c_size_t(len(iv)), aad, c_size_t(len(aad)), c_size_t(taglen)) != 1:
			raise InnerError('libgmssl inner error')

	def encrypt_update(self, data):
		outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_gcm_encrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[0:outlen].raw

	def encrypt_finish(self):
		outbuf = create_string_buffer(SM4.BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_gcm_encrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw

	def decrypt_init(self, key, iv, aad, taglen):
		if len(key) != SM4_KEY_SIZE:
			raise ValueError('Invalid key length')
		if len(iv) < SM4_GCM_MIN_IV_SIZE or len(iv) > SM4_GCM_MAX_IV_SIZE:
			raise ValueError('Invalid IV size')
		if taglen < 1 or tag_len > SM4_GCM_MAX_TAG_SIZE:
			raise ValueError('Invalid Tag length')
		if gmssl.sm4_gcm_decrypt_init(byref(self), key, c_size_t(len(key)), iv, c_size_t(len(iv)), aad, c_size_t(len(aad)), c_size_t(taglen)) != 1:
			raise InnerError('libgmssl inner error')

	def decrypt_update(self, data):
		outbuf = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_gcm_decrypt_update(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[0:outlen].raw

	def decrypt_finish(self):
		outbuf = create_string_buffer(SM4.BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE)
		outlen = c_size_t()
		if gmssl.sm4_gcm_decrypt_finish(byref(self), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw



SM2_DEFAULT_ID = b'1234567812345678'

SM2_MAX_SIGNATURE_SIZE = 72
SM2_MIN_PLAINTEXT_SIZE = 1
SM2_MAX_PLAINTEXT_SIZE = 255
SM2_MIN_CIPHERTEXT_SIZE = 45
SM2_MAX_CIPHERTEXT_SIZE = 366


class SM2_POINT(Structure):
	_fields_ = [
		("x", c_uint8 * 32),
		("y", c_uint8 * 32)
	]


class SM2_KEY(Structure):

	_fields_ = [
		("public_key", SM2_POINT),
		("private_key", c_uint8 * 32)
	]

	def generate(self):
		if gmssl.sm2_key_generate(byref(self)) != 1:
			raise InnerError('libgmssl inner error')

	def private_key_info_encrypt_to_pem(self, passwd, file):
		return "hello"

	def sign(self, dgst):
		if len(data) != SM3.DIGEST_SIZE:
			raise ValueError('Invalid SM3 digest size')
		sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
		siglen = c_size_t()
		if gmssl.sm2_sign(byref(self), dgst, sig, byref(siglen)) != 1:
			raise InnerError('libgmssl inner error')
		return sig[:siglen].raw

	def verify(self, dgst, sig):
		if len(data) != SM3.DIGEST_SIZE:
			raise ValueError('Invalid SM3 digest size')
		ret = gmssl.sm2_verify(byref(self), dgst, sig, c_size_t(len(sig)))
		if ret < 0:
			raise InnerError('libgmssl inner error')
		if ret == 0:
			return False
		return True

	def encrypt(self, data):
		outbuf = create_string_buffer(SM2_MAX_CIPHERTEXT_SIZE)
		outlen = c_size_t()
		if gmssl.sm2_encrypt(byref(self), data, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw

	def decrypt(self, ciphertext):
		outbuf = create_string_buffer(SM2_MAX_PLAINTEXT_SIZE)
		outlen = c_size_t()
		if gmssl.sm2_decrypt(byref(self), ciphertext, c_size_t(len(data)), outbuf, byref(outlen)) != 1:
			raise InnerError('libgmssl inner error')
		return outbuf[:outlen].raw


class SM2_SIGN_CTX(Structure):

	_fields_ = [
		("sm3_ctx", SM3_CTX),
		("key", SM2_KEY)
	]

	def sign_init(self, sign_key, signer_id):
		if gmssl.sm2_sign_init(byref(self), byref(sign_key), signer_id, c_size_t(len(signer_id))) != 1:
			raise InnerError('libgmssl inner error')

	def sign_update(self, data):
		if gmssl.sm2_sign_update(byref(self), data, c_size_t(len(data))) != 1:
			raise InnerError('libgmssl inner error')

	def sign_finish(self):
		sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
		siglen = c_size_t()
		if gmssl.sm2_sign_finish(byref(self), sig, byref(siglen)) != 1:
			raise InnerError('libgmssl inner error')
		return sig[:siglen].raw

	def verify_init(self, pub_key, signer_id):
		if gmssl.sm2_verify_init(byref(self), byref(pub_key), signer_id, c_size_t(len(signer_id))) != 1:
			raise InnerError('libgmssl inner error')

	def verify_update(self, data):
		if gmssl.sm2_verify_update(byref(self), data, c_size_t(len(data))) != 1:
			raise InnerError('libgmssl inner error')

	def verify_finish(self, sig):
		ret = gmssl.sm2_verify_finish(byref(self), sig, c_size_t(len(sig)))
		if ret < 0:
			raise InnerError('libgmssl inner error')
		if ret == 0:
			return False
		return True


