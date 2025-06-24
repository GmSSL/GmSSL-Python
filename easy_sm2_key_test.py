import base64
import random
import unittest
import os

from easy_gmssl import EasySM3Digest
from .easy_sm2_key import EasySm2EncryptionKey , EasySm2Key , SM2CipherFormat , SM2CipherMode
from .gmssl import SM2_MAX_CIPHERTEXT_SIZE , SM2_MAX_PLAINTEXT_SIZE , SM2_MAX_SIGNATURE_SIZE , SM3_DIGEST_SIZE


class SM2KeyCase(unittest.TestCase):
    def setUp(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        target_dir = 'test_keys'
        self.full_target_dir = self.current_dir + '/' + target_dir + '/'
        print(self.full_target_dir)
    
    def test_new_sm2_key(self):
        test1 = EasySm2Key()
        self.assertTrue(test1.get_sm2_public_key_in_hex() != '')
        self.assertTrue(test1.get_sm2_private_key_in_hex() != '')
        self.assertTrue('X' in test1.get_point_in_hex().keys())
        self.assertTrue(test1.get_point_in_hex()[ 'X' ] != '')
        self.assertTrue('Y' in test1.get_point_in_hex().keys())
        self.assertTrue(test1.get_point_in_hex()[ 'Y' ] != '')
        
        test1_pub_key = test1.get_sm2_public_key_in_hex()
        test1_pri_key = test1.get_sm2_private_key_in_hex()
        
        # 重新生成密钥
        test1.reset_key()
        test1.new_key()
        self.assertTrue(test1.get_sm2_public_key_in_hex() != '')
        self.assertTrue(test1.get_sm2_private_key_in_hex() != '')
        self.assertTrue(test1.get_sm2_public_key_in_hex() != test1_pub_key)
        self.assertTrue(test1.get_sm2_private_key_in_hex() != test1_pri_key)
    
    def test_key_export(self):
        test = EasySm2Key()
        self.assertTrue(test.get_sm2_public_key_in_hex() != '')
        self.assertTrue(test.get_sm2_private_key_in_hex() != '')
        pub_key = test.get_sm2_public_key_in_hex()
        pri_key = test.get_sm2_private_key_in_hex()
        
        # 先导出密钥对
        test.export_to_pem_file(self.full_target_dir + 'tmp_test' , '123456')
        
        # 重新导入公钥，此时私钥数据为空
        test.load_sm2_pub_key(self.full_target_dir + 'tmp_test_sm2_public.pem')
        self.assertTrue(test.get_sm2_public_key_in_hex() == pub_key)
        self.assertTrue(test.get_sm2_private_key_in_hex() == '')
        
        # 重新导入私钥，此时公钥、私钥数据均不为空
        test.load_sm2_private_key(self.full_target_dir + 'tmp_test_sm2_private.pem' , '123456')
        self.assertTrue(test.get_sm2_public_key_in_hex() == pub_key)
        self.assertTrue(test.get_sm2_private_key_in_hex() == pri_key)
        
        test.load_sm2_pub_key(self.full_target_dir + 'kms_sm2.pem')
        self.assertFalse(test.get_sm2_public_key_in_hex() == pub_key)
    
    def test_key_import(self):
        test = EasySm2Key()
        self.assertTrue(test.get_sm2_public_key_in_hex() != '')
        self.assertTrue(test.get_sm2_private_key_in_hex() != '')
        
        try:
            test.load_sm2_pub_key(self.full_target_dir + 'invalid_pub_key.pem')
        except Exception as e:
            print(e)
            self.assertTrue(True)
        else:
            self.assertTrue(False)
        
        try:
            # 密码为空
            print('密码为空')
            test.load_sm2_private_key(self.full_target_dir + 'tmp_test_sm2_private.pem' , '')
        except Exception as e:
            print(e)
            self.assertTrue(True)
        else:
            self.assertTrue(False)
        
        try:
            # 密码错误
            print('密码错误')
            test.load_sm2_private_key(self.full_target_dir + 'tmp_test_sm2_private.pem' , '1' * 32)
        except Exception as e:
            print(e)
            self.assertTrue(True)
        else:
            self.assertTrue(False)
        
        try:
            # 密码过长
            print('密码过长')
            test.load_sm2_private_key(self.full_target_dir + 'tmp_test_sm2_private.pem' , '1' * 33)
        except Exception as e:
            print(e)
            self.assertTrue(True)
        else:
            self.assertTrue(False)
    
    def test_valid_encrypt_decrypt(self):
        test = EasySm2EncryptionKey()
        plain_valid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_PLAINTEXT_SIZE) ])
        for mode in SM2CipherMode:
            cipher = test.Encrypt(plain_data = plain_valid , cipher_mode = mode ,
                                  cipher_format = SM2CipherFormat.Base64Str)
            decrypted_plain = test.Decrypt(cipher_data = base64.b64decode(cipher) , cipher_mode = mode)
            self.assertTrue(decrypted_plain == plain_valid)
    
    def test_encrypt_too_long_plain(self):
        test = EasySm2EncryptionKey()
        plain_valid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_PLAINTEXT_SIZE + 1) ])
        try:
            test.Encrypt(plain_data = plain_valid)
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_decrypt_too_long_cipher(self):
        test = EasySm2EncryptionKey()
        cipher_invalid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_CIPHERTEXT_SIZE + 1) ])
        try:
            test.Decrypt(cipher_data = cipher_invalid)
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_invalid_cipher_mode(self):
        test = EasySm2EncryptionKey()
        plain_valid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_PLAINTEXT_SIZE) ])
        try:
            test.Encrypt(plain_data = plain_valid , cipher_mode = 'abc')
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_invalid_cipher_format(self):
        test = EasySm2EncryptionKey()
        plain_valid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_PLAINTEXT_SIZE) ])
        try:
            test.Encrypt(plain_data = plain_valid , cipher_format = 'abc')
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_has_no_private_key(self):
        test = EasySm2EncryptionKey()
        test.load_sm2_pub_key(self.full_target_dir + 'tmp_test_sm2_public.pem')
        cipher_invalid = bytes([ random.randint(1 , 255) for _ in range(0 , SM2_MAX_CIPHERTEXT_SIZE) ])
        try:
            test.Decrypt(cipher_data = cipher_invalid)
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_digest_signature(self):
        test = EasySm2Key()
        test.load_sm2_private_key(self.full_target_dir + 'tmp_test_sm2_private.pem' , '123456')
        self.assertTrue(len(test.get_sm2_public_key_in_hex()) > 0)
        self.assertTrue(len(test.get_sm2_private_key_in_hex()) > 0)
        plain = b'hello,world'
        plain_sm3 = EasySM3Digest()
        plain_sm3.UpdateData(plain)
        h , h_len , plain_len = plain_sm3.GetHash()
        self.assertTrue(len(h) == h_len)
        self.assertTrue(h_len == SM3_DIGEST_SIZE)
        self.assertTrue(plain_len == len(plain))
        signature = test.sign_digest(digest = h)
        self.assertTrue(len(signature) <= SM2_MAX_SIGNATURE_SIZE)
        verify = EasySm2Key()
        verify.load_sm2_pub_key(self.full_target_dir + 'tmp_test_sm2_public.pem')
        ret = verify.verify_digest_signature(digest = h , signature = signature)
        self.assertTrue(ret == True)
        # 错误的签名值
        ret = verify.verify_digest_signature(digest = ('1' * SM3_DIGEST_SIZE).encode() ,
                                             signature = signature)
        self.assertTrue(ret == False)


if __name__ == '__main__':
    unittest.main()
